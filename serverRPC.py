import time
import traceback
import argparse
import os
import bcrypt
import grpc
from concurrent import futures
import chat_pb2
import chat_pb2_grpc
import psycopg2
from configparser import ConfigParser
import threading
import socket
import signal
import sys

# Single-DB config
def load_single_config(replica_id=1, filename='database.ini'):
    parser = ConfigParser()
    parser.read(filename)
    section = f'postgresql{replica_id}'
    if not parser.has_section(section):
        raise Exception(f"Section {section} not found in {filename}")
    params = {}
    for param, value in parser.items(section):
        params[param] = value
    return params

def connectSingleDB(replica_id=1):
    db_config = load_single_config(replica_id)
    try:
        conn = psycopg2.connect(
            host=db_config['host'],
            port=db_config['port'],
            user=db_config['user'],
            password=db_config['password'],
            database=db_config['database']
        )
        conn.autocommit = False
        print(f"Connected to {db_config['database']} at {db_config['host']}:{db_config['port']} (replica_id={replica_id})")
        return conn
    except Exception as e:
        print(f"Error connecting to single DB for replica_id={replica_id}: {e}")
        return None

def load_server_config(filename="server.ini"):
    parser = ConfigParser()
    parser.read(filename)

    ports_sorted = []
    if parser.has_option("server", "ports_sorted"):
        raw_sorted = parser.get("server", "ports_sorted")
        for p_str in raw_sorted.split(","):
            ports_sorted.append(int(p_str.strip()))

    return ports_sorted

# Helper functions
def checkValidPassword(password):
    if len(password) < 7:
        return False
    has_upper = any(c.isupper() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_special = any(c in ['_', '@', '$', '#', '!'] for c in password)
    return has_upper and has_digit and has_special

def hashPass(password):
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed.decode('utf-8')


# ChatService with RPC-based replication + simple leader election
class ChatService(chat_pb2_grpc.ChatServicer):
    def __init__(self, db_conn, other_stubs, my_port):
        """
        :param db_conn: psycopg2 connection to THIS server's local DB
        :param other_stubs: list of stubs for the OTHER servers so we can replicate
        :param my_port: The TCP port this server is running on
        """
        super().__init__()
        self.db_conn = db_conn
        self.other_stubs = other_stubs  # list of ChatStub objects for the other servers
        self.my_port = my_port

        # Define a fixed set of known ports for the cluster:
        self.ports_sorted = load_server_config()
        # Track leader naviely initially
        self.is_leader = False

        # Start a background thread to periodically check if any smaller port is alive
        t = threading.Thread(target=self.leader_check_loop, daemon=True)
        t.start()

    # Leader Check Logic
    def leader_check_loop(self):
        while True:
            self.update_is_leader()
            time.sleep(0.5)  # check every 2 seconds

    def update_is_leader(self):
        # gGt all ports smaller than my_port
        smaller_ports = [p for p in self.ports_sorted if p < self.my_port]
        # if ANY smaller port is alive, current server is NOT the leader
        for p in smaller_ports:
            if self.is_port_alive("10.250.52.124", p):
                print(p, "is still alive")
                self.is_leader = False
                return
        # If no smaller live port found, current server becomes leader
        self.is_leader = True

    def is_port_alive(self, host, port):
        """Simple TCP check to see if the server is listening on (host, port)."""
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.5)
        try:
            s.connect((host, port))
            s.close()
            return True
        except:
            return False

    # Local DB read/write
    def local_write(self, sql, params=()):
        with self.db_conn.cursor() as cur:
            cur.execute(sql, params)
        self.db_conn.commit()

    def local_read(self, sql, params=()):
        with self.db_conn.cursor() as cur:
            cur.execute(sql, params)
            return cur.fetchall()

    # Replicate_to_others
    def replicate_to_others(self, sql, params=()):
        """
        Update all
        """
        if not self.other_stubs:
            return  # No other stubs to replicate to 

        total = len(self.other_stubs)
        for i in range(total):
            stub = self.other_stubs[i]
            print(f"[DEBUG] replicate_to_others to stub {stub}")
            try:
                resp = stub.ReplicateWrite(
                    chat_pb2.ReplicateRequest(sql=sql, params=params)
                )
                if not resp.success:
                    print(f"[DEBUG] replicate_to_others: stub {stub} returned error: {resp.message}")
            except Exception as ex:
                print(f"[DEBUG] replicate_to_others: stub {stub} call failed: {ex}")

        print("[DEBUG] replicate_to_others: all stubs successfully updated.")

    def ReplicateWrite(self, request, context):
        """
        Another server calls this to replicate a SQL statement on our local DB.
        Do local_write with the given SQL, then return success/fail
        """
        print(f"[DEBUG] Peer {context.peer()} called ReplicateWrite")
        sql = request.sql
        params = request.params
        try:
            self.local_write(sql, params)
            return chat_pb2.ReplicateResponse(success=True, message="OK")
        except Exception as e:
            traceback.print_exc()
            return chat_pb2.ReplicateResponse(success=False, message=str(e))

    def checkRealUsername(self, username):
        rows = self.local_read("SELECT COUNT(*) FROM users WHERE username=%s", (username,))
        return rows and rows[0][0] > 0

    def checkRealPassword(self, username, plain_text):
        rows = self.local_read("SELECT password FROM users WHERE username=%s", (username,))
        if not rows:
            return False
        stored_hash = rows[0][0]
        return bcrypt.checkpw(plain_text.encode('utf-8'), stored_hash.encode('utf-8'))

    # user-facing RPCs (with leader check for writes)
    def Register(self, request, context):
        print(f"[DEBUG] Client {context.peer()} called Register")

        # If not leader, reject writes
        if not self.is_leader:
            self.update_is_leader()
            return chat_pb2.Response(
                command="1",
                server_message="This server is a BACKUP; please connect to the leader for registration."
            )

        reg_username = request.username.strip()
        reg_password = request.password.strip()
        confirm_password = request.confirm_password.strip()

        if not reg_username or not reg_password or not confirm_password:
            return chat_pb2.Response(
                command="1",
                server_message="Registration canceled: All fields are required."
            )
        if self.checkRealUsername(reg_username):
            return chat_pb2.Response(
                command="1",
                server_message="Username taken. Please choose another."
            )
        if not checkValidPassword(reg_password):
            return chat_pb2.Response(
                command="1",
                server_message="Invalid password: must be >=7 chars, uppercase, digit, special char."
            )
        if reg_password != confirm_password:
            return chat_pb2.Response(
                command="1",
                server_message="Passwords do not match."
            )

        hashed = hashPass(reg_password)
        try:
            # local
            self.local_write(
                "INSERT INTO users (username, password, active) VALUES (%s, %s, 1)",
                (reg_username, hashed)
            )
            # replicate
            self.replicate_to_others(
                "INSERT INTO users (username, password, active) VALUES (%s, %s, 1)",
                (reg_username, hashed)
            )
            return chat_pb2.Response(
                command="1",
                server_message="Registration successful. You are now logged in!"
            )
        except Exception as e:
            traceback.print_exc()
            return chat_pb2.Response(
                command="1",
                server_message=f"Server error during registration: {e}"
            )

    def Login(self, request, context):
        print(f"[DEBUG] Client {context.peer()} called Login")

        if not self.is_leader:
            self.update_is_leader()
            return chat_pb2.Response(
                command="2",
                server_message="This server is a BACKUP; please connect to the leader to login."
            )

        username = request.username.strip()
        password = request.password.strip()

        if not self.checkRealUsername(username):
            return chat_pb2.Response(
                command="2",
                server_message="User not found."
            )
        if not self.checkRealPassword(username, password):
            return chat_pb2.Response(
                command="2",
                server_message="Incorrect password."
            )

        rows = self.local_read("SELECT active FROM users WHERE username=%s", (username,))
        if rows and rows[0][0] == 1:
            return chat_pb2.Response(
                command="2",
                server_message="You are already logged in. Please log out before logging in again."
            )
        try:
            self.local_write("UPDATE users SET active=1 WHERE username=%s", (username,))
            self.replicate_to_others(
                "UPDATE users SET active=1 WHERE username=%s",
                (username,)
            )
            return chat_pb2.Response(
                command="2",
                server_message=f"Welcome, {username}!"
            )
        except Exception as e:
            traceback.print_exc()
            return chat_pb2.Response(
                command="2",
                server_message="Error setting user active: " + str(e)
            )

    def SendMessage(self, request, context):
        print(f"[DEBUG] Client {context.peer()} called SendMessage")

        if not self.is_leader:
            self.update_is_leader()
            return chat_pb2.SendMessageResponse(
                success=False,
                server_message="This server is a BACKUP; please connect to the leader to send messages."
            )

        full_text = request.message.strip()
        md = dict(context.invocation_metadata())
        sender = md.get("username", "unknown")

        if not full_text.startswith("@"):
            return chat_pb2.SendMessageResponse(
                success=False,
                server_message="To send messages, use '@username message'. You can also type 'check', 'logoff', 'history', 'search', 'delete', or 'deactivate'."
            )
        parts = full_text.split(" ", 1)
        if len(parts) < 2:
            return chat_pb2.SendMessageResponse(
                success=False,
                server_message="Invalid format. Use '@username message'."
            )
        target_username = parts[0][1:]
        msg_text = parts[1]
        if not self.checkRealUsername(target_username):
            return chat_pb2.SendMessageResponse(
                success=False,
                server_message="Recipient does not exist."
            )
        try:
            self.local_write(
                "INSERT INTO messages (receiver, sender, message, isread) VALUES (%s, %s, %s, False)",
                (target_username, sender, msg_text)
            )
            self.replicate_to_others(
                "INSERT INTO messages (receiver, sender, message, isread) VALUES (%s, %s, %s, False)",
                (target_username, sender, msg_text)
            )
            return chat_pb2.SendMessageResponse(success=True, server_message="")
        except Exception as e:
            traceback.print_exc()
            return chat_pb2.SendMessageResponse(success=False, server_message="Error storing message: " + str(e))

    def Logoff(self, request, context):
        print(f"[DEBUG] Client {context.peer()} called Logoff")

        if not self.is_leader:
            self.update_is_leader()
            return chat_pb2.Response(
                command="logoff",
                server_message="This server is a BACKUP; connect to the leader to log off."
            )

        username = request.username.strip()
        if not username:
            return chat_pb2.Response(
                command="logoff",
                server_message="No username provided."
            )
        try:
            self.local_write("UPDATE users SET active=0 WHERE username=%s", (username,))
            self.replicate_to_others("UPDATE users SET active=0 WHERE username=%s", (username,))
            return chat_pb2.Response(
                command="logoff",
                server_message=f"{username} has been logged off."
            )
        except Exception as e:
            traceback.print_exc()
            return chat_pb2.Response(
                command="logoff",
                server_message="Logoff error: " + str(e)
            )

    def SearchUsers(self, request, context):
        """
        Search for other users
        """
        print(f"[DEBUG] Client {context.peer()} called SearchUsers")
        username = request.username.strip()
        try:
            rows = self.local_read("SELECT username FROM users", ())
            all_users = [r[0] for r in rows if r[0] != username]
            return chat_pb2.SearchResponse(
                success=True,
                usernames=all_users,
                server_message="User list: "
            )
        except Exception as e:
            traceback.print_exc()
            return chat_pb2.SearchResponse(
                success=False,
                usernames=[],
                server_message="Error searching users: " + str(e)
            )

    def DeleteLastMessage(self, request_iterator, context):
        """
        Deletes the last unread message for the user.
        """
        print(f"[DEBUG] Client {context.peer()} called DeleteLastMessage")

        if not self.is_leader:
            self.update_is_leader()
            yield chat_pb2.Response(
                command="delete",
                server_message="This server is a BACKUP; connect to the leader to delete messages."
            )
            return

        try:
            req_iter = iter(request_iterator)
            first_req = next(req_iter, None)
            if not first_req or not first_req.username.strip():
                yield chat_pb2.Response(
                    command="delete",
                    server_message="No username provided. Aborting."
                )
                return
            username = first_req.username.strip()

            unread_rows = self.local_read(
                "SELECT messageid, message, receiver FROM messages "
                "WHERE sender=%s AND isread=False ORDER BY messageid DESC LIMIT 1",
                (username,)
            )
            if not unread_rows:
                yield chat_pb2.Response(
                    command="delete",
                    server_message="No unread messages to delete."
                )
                return
            msgid, msgtxt, recv = unread_rows[0]
            yield chat_pb2.Response(
                command="delete",
                server_message=f"Last unread message: '{msgtxt}' -> {recv}. Delete it? (yes/no)"
            )

            second_req = next(req_iter, None)
            if not second_req or not second_req.confirmation.strip():
                yield chat_pb2.Response(
                    command="delete",
                    server_message="No confirmation provided. Delete canceled."
                )
                return
            if second_req.confirmation.strip().lower() == "yes":
                try:
                    self.local_write("DELETE FROM messages WHERE messageid=%s", (msgid,))
                    msg_ids = [str(msgid)]
                    self.replicate_to_others("DELETE FROM messages WHERE messageid=%s", msg_ids)
                    yield chat_pb2.Response(
                        command="delete",
                        server_message="Message deleted."
                    )
                except Exception as e:
                    yield chat_pb2.Response(
                        command="delete",
                        server_message="Error deleting message: " + str(e)
                    )
            else:
                yield chat_pb2.Response(
                    command="delete",
                    server_message="Delete canceled."
                )
        except Exception as e:
            traceback.print_exc()
            yield chat_pb2.Response(
                command="delete",
                server_message="Error: " + str(e)
            )

    def DeactivateAccount(self, request_iterator, context):
        """
        Deactivates the user's account and deletes their messages.
        """
        print(f"[DEBUG] Client {context.peer()} called DeactivateAccount")

        # If not leader, reject writes
        if not self.is_leader:
            self.update_is_leader()
            yield chat_pb2.Response(
                command="deactivate",
                server_message="This server is a BACKUP; connect to the leader to deactivate your account."
            )
            return

        try:
            req_iter = iter(request_iterator)
            first_req = next(req_iter, None)
            if not first_req or not first_req.username.strip():
                yield chat_pb2.Response(
                    command="deactivate",
                    server_message="No username provided."
                )
                return
            username = first_req.username.strip()

            yield chat_pb2.Response(
                command="deactivate",
                server_message="Are you sure you want to deactivate your account? (yes/no)"
            )
            second_req = next(req_iter, None)
            if not second_req or not second_req.confirmation.strip():
                yield chat_pb2.Response(
                    command="deactivate",
                    server_message="No confirmation. Canceled."
                )
                return
            if second_req.confirmation.strip().lower() == "yes":
                try:
                    self.local_write("DELETE FROM messages WHERE sender=%s", (username,))
                    self.local_write("DELETE FROM messages WHERE receiver=%s", (username,))
                    self.local_write("DELETE FROM users WHERE username=%s", (username,))

                    self.replicate_to_others("DELETE FROM messages WHERE sender=%s", (username,))
                    self.local_write("DELETE FROM messages WHERE receiver=%s", (username,))
                    self.replicate_to_others("DELETE FROM users WHERE username=%s", (username,))

                    yield chat_pb2.Response(
                        command="deactivate",
                        server_message="Your account and sent messages are removed."
                    )
                except Exception as e:
                    yield chat_pb2.Response(
                        command="deactivate",
                        server_message="Error removing account: " + str(e)
                    )
            else:
                yield chat_pb2.Response(
                    command="deactivate",
                    server_message="Deactivation canceled."
                )
        except Exception as e:
            traceback.print_exc()
            yield chat_pb2.Response(
                command="deactivate",
                server_message="Error: " + str(e)
            )

    def History(self, request_iterator, context):
        """
        Displays chat history between two users
        """
        print(f"[DEBUG] Client {context.peer()} called History")
        try:
            req_iter = iter(request_iterator)
            yield chat_pb2.Response(
                command="history",
                server_message="Enter the username of the user whose chat history you'd like to view:"
            )
            confirmation = ""
            while not confirmation:
                req = next(req_iter)
                confirmation = req.confirmation.strip().lower()
            username = req.username.strip()
            if confirmation:
                sql = (
                    "SELECT messageid, sender, message, datetime "
                    "FROM messages "
                    "WHERE (sender=%s AND receiver=%s) OR (sender=%s AND receiver=%s) "
                    "ORDER BY datetime"
                )
                params = (username, confirmation, confirmation, username)
                msgs = self.local_read(sql, params)
                chat_history = "\n".join([
                    f"{row[3].strftime('%Y-%m-%d %H:%M:%S')} {row[1]}: {row[2]}"
                    for row in msgs
                ])
                yield chat_pb2.Response(
                    command="history",
                    server_message=chat_history if chat_history else "No message history available."
                )
            else:
                yield chat_pb2.Response(
                    command="history",
                    server_message="History view canceled."
                )
        except Exception as e:
            traceback.print_exc()
            yield chat_pb2.Response(
                command="history",
                server_message="Error: " + str(e)
            )

    def CheckMessages(self, request_iterator, context):
        """
        Checks for incoming messages
        """
        print(f"[DEBUG] Client {context.peer()} called CheckMessages")
        try:
            req_iter = iter(request_iterator)
            first_req = next(req_iter, None)
            if first_req is None or not first_req.username.strip():
                yield chat_pb2.CheckMessagesResponse(
                    command="checkmessages",
                    server_message="No username provided. Aborting."
                )
                return
            username = first_req.username.strip()

            unread_rows = self.local_read(
                "SELECT COUNT(*) FROM messages WHERE receiver=%s AND isread=False",
                (username,)
            )
            unread_count = unread_rows[0][0]
            if unread_count == 0:
                yield chat_pb2.CheckMessagesResponse(
                    command="checkmessages",
                    server_message = (
                     " ------------------------------------------\n"
                     "| You have 0 unread messages.             |\n"
                     "| Type @username msg to send new messages |\n"
                     " ------------------------------------------"
                 ))
                return
            yield chat_pb2.CheckMessagesResponse(
                command="checkmessages",
                server_message = (
                         " ----------------------------------------- \n"
                         f"| You have {unread_count} unread messages.              |\n"
                         "| Type '1' to read them, or '2' to skip    |\n"
                         "| and send new messages.                   |\n"
                         "  ----------------------------------------- "
                 )
            )

            req = next(req_iter, None)
            if req is None:
                yield chat_pb2.CheckMessagesResponse(
                    command="checkmessages",
                    server_message="No choice provided. Aborting."
                )
                return
            choice = req.choice.strip()
            print("choice  is", choice)
            if choice == "2":
                yield chat_pb2.CheckMessagesResponse(
                    command="checkmessages",
                    server_message="Skipping reading messages."
                )
                context.cancel()
                return 
            elif choice not in ["1", "2"]:
                yield chat_pb2.CheckMessagesResponse(
                    command="checkmessages",
                    server_message="Invalid choice. Aborting."
                )
                context.cancel()
                return 
            sender_counts = self.local_read(
                "SELECT sender, COUNT(*) FROM messages WHERE receiver=%s AND isread=False GROUP BY sender",
                (username,)
            )
            if not sender_counts:
                yield chat_pb2.CheckMessagesResponse(
                    command="checkmessages",
                    server_message="No unread messages found."
                )
                return
            senders_str = ", ".join([f"{r[0]}({r[1]})" for r in sender_counts])
            yield chat_pb2.CheckMessagesResponse(
                command="checkmessages",
                server_message=f"Unread from: {senders_str}\nWhich sender do you want to read?"
            )

            req_sender = next(req_iter, None)
            if not req_sender or not req_sender.sender.strip():
                yield chat_pb2.CheckMessagesResponse(
                    command="checkmessages",
                    server_message="No sender provided. Aborting."
                )
                return
            chosen_sender = req_sender.sender.strip()

            msgs_rows = self.local_read(
                "SELECT messageid, sender, message, datetime "
                "FROM messages WHERE receiver=%s AND sender=%s AND isread=False ORDER BY messageid",
                (username, chosen_sender)
            )
            if not msgs_rows:
                yield chat_pb2.CheckMessagesResponse(
                    command="checkmessages",
                    server_message=f"No unread messages from {chosen_sender}."
                )
                return

            batch_size = 5
            index = 0
            while index < len(msgs_rows):
                batch = msgs_rows[index : index + batch_size]
                for row in batch:
                    msg_id, msg_sender, msg_body, msg_dt = row
                    dt_str = msg_dt.strftime("%Y-%m-%d %H:%M:%S")
                    yield chat_pb2.CheckMessagesResponse(
                        command="checkmessages",
                        server_message=f"{dt_str} {msg_sender}: {msg_body}"
                    )
                # Mark them read
                msg_ids = [r[0] for r in batch]
                placeholders = ", ".join(["%s"] * len(msg_ids))
                sql_update = f"UPDATE messages SET isread=True WHERE messageid IN ({placeholders})"
                try:
                    self.local_write(sql_update, msg_ids)
                    self.replicate_to_others(sql_update, [str(m) for m in msg_ids])
                except Exception as e:
                    yield chat_pb2.CheckMessagesResponse(
                        command="checkmessages",
                        server_message="Error marking batch read: " + str(e)
                    )
                yield chat_pb2.CheckMessagesResponse(
                    command="checkmessages",
                    server_message="(Batch of messages marked as read.)"
                )
                index += batch_size
                if index < len(msgs_rows):
                    yield chat_pb2.CheckMessagesResponse(
                        command="checkmessages",
                        server_message="Type anything to see the next batch..."
                    )
                    _ = next(req_iter, None)

            yield chat_pb2.CheckMessagesResponse(
                command="checkmessages",
                server_message="All messages from this sender have been read."
            )
        except Exception as e:
            traceback.print_exc()
            yield chat_pb2.CheckMessagesResponse(
                command="checkmessages",
                server_message="Error in CheckMessages: " + str(e)
            )

    def ReceiveMessages(self, request, context):
        """
        Checks for incoming messages
        """
        print(f"[DEBUG] Client {context.peer()} called ReceiveMessages")

        username = request.username.strip()
        while context.is_active():
            rows = self.local_read(
                "SELECT messageid, sender, message, datetime "
                "FROM messages WHERE receiver=%s AND isread=False ORDER BY datetime",
                (username,)
            )
            if rows:
                for row in rows:
                    msgid, sender, msg_body, msg_dt = row
                    ts = msg_dt.strftime("%Y-%m-%d %H:%M:%S")
                    yield chat_pb2.ReceiveResponse(
                        sender=sender,
                        message=msg_body,
                        timestamp=ts
                    )
                # mark them read
                msg_ids = [r[0] for r in rows]
                placeholders = ", ".join(["%s"] * len(msg_ids))
                sql_update = f"UPDATE messages SET isread=True WHERE messageid IN ({placeholders})"
                try:
                    self.local_write(sql_update, msg_ids)
                    self.replicate_to_others(sql_update, [str(m) for m in msg_ids])
                except Exception as e:
                    print("Error marking messages read:", e)
            time.sleep(1)

def build_other_stubs(this_hostport):
    addresses = [
        "10.250.52.124:65432",
        "10.250.52.124:65433",
        "10.250.52.124:65434",
    ]
    other_addresses = [addr for addr in addresses if addr != this_hostport]
    stubs = []
    for addr in other_addresses:
        channel = grpc.insecure_channel(addr)
        stub = chat_pb2_grpc.ChatStub(channel)
        stubs.append(stub)
    return stubs

def serve():
    parser = argparse.ArgumentParser(description="RPC-based replication + naive leader election + single local DB.")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=65432,
                        help="Port to run the gRPC server on (e.g. 65432/65433/65434).")
    parser.add_argument("--replica_id", type=int, default=1, help="Which DB config to load (1..3).")
    args = parser.parse_args()

    local_conn = connectSingleDB(args.replica_id)
    if not local_conn:
        print("Could not connect to local DB. Exiting.")
        return

    this_hostport = f"{args.host}:{args.port}"
    other_stubs = build_other_stubs(this_hostport)

    server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))
    chat_service = ChatService(local_conn, other_stubs, my_port=args.port)
    chat_pb2_grpc.add_ChatServicer_to_server(chat_service, server)

    address = f"{args.host}:{args.port}"
    server.add_insecure_port(address)
    server.start()
    print(f"Server started on {address} (replica {args.replica_id}), with naive leader election.")

    def handle_signal(*_):
        print("Shutting down gRPC server gracefully...")
        server.stop(0)  
        sys.exit(0)

    signal.signal(signal.SIGINT, handle_signal)  # Catch Ctrl-C
    signal.signal(signal.SIGTERM, handle_signal) # Catch other kill signals

    server.wait_for_termination()

if __name__ == "__main__":
    serve()