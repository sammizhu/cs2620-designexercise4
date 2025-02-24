import threading
import pymysql
import pymysql.cursors
import bcrypt
import traceback
import argparse
import os

from concurrent import futures
import logging

import grpc
import chat_pb2
import chat_pb2_grpc

# Parse command-line arguments
parser = argparse.ArgumentParser(description="Start the chat server.")
parser.add_argument("--host", default=os.getenv("CHAT_SERVER_HOST", "0.0.0.0"), help="Server hostname or IP")
parser.add_argument("--port", type=int, default=int(os.getenv("CHAT_SERVER_PORT", 65432)), help="Port number")
args = parser.parse_args()

# Use argument or environment variable
HOST = args.host
PORT = args.port
# HOST = '127.0.0.1'
# PORT = 65432

clients = {}

def connectsql():
    return pymysql.connect(
        host=HOST,
        user='root',
        password='',
        database='db262',
        cursorclass=pymysql.cursors.DictCursor
    )

def checkRealUsername(username):
    with connectsql() as db:
        with db.cursor() as cur:
            cur.execute("SELECT COUNT(*) AS cnt FROM users WHERE username=%s", (username,))
            row = cur.fetchone()
            return (row['cnt'] > 0)

def checkValidPassword(password):
    if len(password) < 7:
        return False
    has_upper = any(c.isupper() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_special = any(c in ['_', '@', '$', '#', '!'] for c in password)
    return (has_upper and has_digit and has_special)

def hashPass(password):
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed.decode('utf-8')

def checkRealPassword(username, plain_text):
    with connectsql() as db:
        with db.cursor() as cur:
            cur.execute("SELECT password FROM users WHERE username=%s", (username,))
            row = cur.fetchone()
            if not row:
                return False
            stored_hash = row['password']
    return bcrypt.checkpw(plain_text.encode('utf-8'), stored_hash.encode('utf-8'))

class ChatService(chat_pb2_grpc.ChatServicer):
    def Register(self, request_iterator, context):
        reg_username = None
        reg_password = None

        # 1) Prompt repeatedly for username until it is a valid username
        for request in request_iterator:
            # If user just hit Enter or disconnected, cancel registration
            if not request.username:
                return chat_pb2.Response(command="1", server_message="Registration canceled.\n")
            
            # If username is taken, let user know and stay in loop
            if checkRealUsername(request.username):
                return chat_pb2.Response(command="1", server_message="Username taken. Please choose another.\n")
            
            reg_username = request.username
            # Exit loop after valid username
            break

        # 2) Prompt repeatedly for password until valid
        for request in request_iterator:
            if not request.password:
                return chat_pb2.Response(command="1", server_message="Registration canceled.\n")
            
            if not checkValidPassword(request.password):
                return chat_pb2.Response(command="1", server_message="Invalid password. Please try again.\n")
            reg_password = request.password
            # Exit loop after valid password
            break

        # 3) Ask for confirmation of the password
        for request in request_iterator:
            if reg_password != request.password:
                return chat_pb2.Response(command="1", server_message="Passwords do not match. Please try again.\n")
            
            # Hash and store
            hashed = hashPass(reg_password)
            try:
                with connectsql() as db:
                    with db.cursor() as cur:
                        cur.execute("INSERT INTO users (username, password, active) VALUES (%s, %s, 1)",
                                    (reg_username, hashed))
                        db.commit()
                return chat_pb2.Response(command="1", server_message="Registration successful. You are now logged in!\n")
            except Exception:
                traceback.print_exc()
                return chat_pb2.Response(command="1", server_message="Server error. Registration canceled.\n")

    def Login(self, request_iterator, context):
        login_username = None
        login_password = None

        # Request username for login
        for request in request_iterator:
            if not request.username:
                return chat_pb2.Response(command="2", server_message="Login canceled.\n")

            if not checkRealUsername(request.username):
                return chat_pb2.Response(command="2", server_message="User not found. Please try again.\n")
            
            login_username = request.username
            break

        # Request password for login
        for request in request_iterator:
            if not request.password:
                return chat_pb2.Response(command="2", server_message="Login canceled.\n")

            if not checkRealPassword(login_username, request.password):
                return chat_pb2.Response(command="2", server_message=f"Welcome, {login_username}!\n", username=login_username)

            login_password = request.password
            break

        # Mark active=1
        with connectsql() as db:
            with db.cursor() as cur:
                cur.execute("UPDATE users SET active=1 WHERE username=%s",
                            (login_username,))
                db.commit()
        return chat_pb2.Response(command="2", server_message="Incorrect password. Try again.\n")
    
    # Checks if 'username' has unread messages.
    # If so, we ask them whether they'd like to read or send new messages.
    # If they choose read => ask from which sender, then fetch those messages, mark them read.
    # If they choose send => they can just type '@username message'.
    def CheckMessagesServerSide(self, request_iterator, context):
        username = None
        choice = None
        sender = None

        # Request from clients
        for request in request_iterator:
            username = request.username
            choice = request.choice
            sender = request.sender

            if not username:
                yield chat_pb2.CheckMessagesResponse(server_message="Invalid username.")

        with connectsql() as db:
            with db.cursor() as cur:
                # Count how many unread messages
                cur.execute("SELECT COUNT(*) AS cnt FROM messages WHERE receiver=%s AND isread=0", (username,))
                row = cur.fetchone()
                unread_count = row['cnt']

                if unread_count == 0:
                    yield chat_pb2.CheckMessagesReponse(command="checkmessage", server_message="You have 0 unread messages.\n ")
                    return
                
                # If we have unread
                yield chat_pb2.CheckMessagesResponse(command="checkmessage", server_message=f" ------------------------------------------\n| You have {unread_count} unread messages.              |\n| Type '1' to read them, or '2' to skip    |\n| and send new messages.                   |\n ------------------------------------------\n """,
                                                    unread_count=unread_count)
                
                if choice == "1":
                    # Check which sender(s)
                    cur.execute("SELECT sender, COUNT(*) AS num FROM messages WHERE receiver=%s AND isread=0 GROUP BY sender", (username,))
                    rows = cur.fetchall()
                    if not rows:
                        yield chat_pb2.CheckMessagesResponse(command="checkmessage", server_message="No unread messages found (maybe they were just read?).\n")
                        return
                    
                    # Show which senders
                    senders_info = "\n".join([f"{row['sender']} ({row['num']} messages)" for row in rows])
                    
                    yield chat_pb2.CheckMessagesResponse(command="checkmessage", server_message=f"You have unread messages from: {senders_info}")
                    
                    yield chat_pb2.CheckMessagesResponse(command="checkmessage", server_message="Which sender do you want to read from?", sender="choose_sender")

                    if sender:
                        # Fetch unread messages from the database
                        cur.execute(
                            "SELECT messageid, sender, message, datetime FROM messages "
                            "WHERE receiver=%s AND sender=%s AND isread=0 ORDER BY messageid",
                            (username, sender)
                        )
                        unread_msgs = cur.fetchall()

                        if not unread_msgs:
                            yield chat_pb2.CheckMessagesResponse(command="checkmessage", server_message="No unread messages from that user.\n")
                            return
                        
                        # Batch size: if more than 5 messages, use batches of 5; otherwise, show all
                        batch_size = 5 if len(unread_msgs) > 5 else len(unread_msgs)

                        yield chat_pb2.CheckMessagesResponse(command="checkmessage", server_message=f"--- Unread messages from {sender} ---\n")

                        for i in range(0, len(unread_msgs), batch_size):
                            batch = unread_msgs[i:i+batch_size]

                            for m in batch:
                                ts = m['datetime'].strftime("%Y-%m-%d %H:%M:%S")
                                yield chat_pb2.CheckMessagesResponse(command="checkmessage",
                                                                     server_message=f"{ts} {m['sender']}: {m['message']}\n",
                                                                     sender=m['sender'],
                                                                     message_body=m['message'])
                                
                            # Mark the current batch as read in the database
                            batch_ids = [m['messageid'] for m in batch]
                            if len(batch_ids) == 1:
                                cur.execute("UPDATE messages SET isread=1 WHERE messageid=%s", (batch_ids[0],))
                            else:
                                placeholders = ','.join(['%s'] * len(batch_ids))
                                query = f"UPDATE messages SET isread=1 WHERE messageid IN ({placeholders})"
                                cur.execute(query, batch_ids)
                            db.commit()

                            yield chat_pb2.ChecMessagesResponse(command="checkmessage", server_message="The current batch of messages has been marked as read.\n")

                            # If there are more messages, wait for the user input before showing the next batch.
                            if i + batch_size < len(unread_msgs):
                                yield chat_pb2.ChecMessagesResponse(command="checkmessage", server_message="Type anything to see the next batch of messages...\n")
                    
                    elif choice == "2":
                        # Skips reading, user can continue
                        return
                    
                    else:
                        yield chat_pb2.ChecMessagesResponse(command="checkmessage", server_message="Invalid choice. Returning to main.\n")

def handle_client(conn, addr):
    user_id = addr[1]
    clients[user_id] = conn
    print(f"New connection from {addr}")

    logged_in = False
    username = None

    try:
        while True:
            data_jsonstr = conn.recv(1024).decode('utf-8')
            data = json.loads(data_jsonstr)["command"] ### FIX ###
            if not data:
                # client disconnected
                print(f"Client {addr} disconnected.")
                break

            # If not logged in => only handle register or login
            if not logged_in:
                if data == "1":
                    new_user = handle_registration(conn, user_id)
                    if new_user:
                        username = new_user
                        logged_in = True
                        # Check unread (should be none if newly registered, but included for consistency)
                        check_messages_server_side(conn, username)
                        json_handleclient_registercommands = {"command": "handleclient",
                                                              "server_message": "To send messages, use '@username message'. You can also type 'check', 'logoff',' search', 'delete', or 'deactivate'.\n "}
                        conn.sendall(json.dumps(json_handleclient_registercommands).encode('utf-8'))
                elif data == "2":
                    logged_user = handle_login(conn, user_id)
                    if logged_user:
                        username = logged_user
                        logged_in = True
                        # Check unread for returning user
                        check_messages_server_side(conn, username)
                        json_handleclient_logincommands = {"command": "handleclient",
                                                           "server_message": "To send messages, use '@username message'. You can also type 'check', 'logoff',' search', 'delete', or 'deactivate'.\n "}
                        conn.sendall(json.dumps(json_handleclient_logincommands).encode('utf-8'))

            # If logged in => handle DM sending, check, or logoff
            else:
                if data.lower() == "logoff":
                    # Mark user inactive
                    with connectsql() as db:
                        with db.cursor() as cur:
                            cur.execute("UPDATE users SET active=0 WHERE username=%s", (username,))
                        db.commit()
                    json_handleclient_logoff = {"command": "logoff",
                                                "server_message": "Logged off.\n"}
                    conn.sendall(json.dumps(json_handleclient_logoff).encode('utf-8'))
                    break

                elif data.lower() == "check":
                    check_messages_server_side(conn, username)

                elif data.startswith("@"):
                    # Parse DM
                    parts = data.split(" ", 1)
                    if len(parts) < 2:
                        json_handleclient_invalidsend = {"command": "sendmessage",
                                                         "server_message": "Invalid format. Use '@username message'.\n"}
                        conn.sendall(json.dumps(json_handleclient_invalidsend).encode('utf-8'))
                        continue
                    target_username, message = parts[0][1:], parts[1]
                    try:
                        with connectsql() as db:
                            with db.cursor() as cur:
                                cur.execute("INSERT INTO messages (receiver, sender, message, isread) VALUES (%s, %s, %s, 0)", (target_username, username, message))
                                db.commit()

                                # If target online, send message; otherwise just keep it stored in messages table
                                cur.execute("SELECT socket_id, active FROM users WHERE username=%s", (target_username,))
                                row = cur.fetchone()
                                if row and row['socket_id'] and row['socket_id'].isdigit() and row['active']:
                                    tsid = int(row['socket_id'])
                                    if tsid in clients:
                                        cur.execute("SELECT messageid FROM messages WHERE message=%s", (message))
                                        msg_id = cur.fetchall()
                                        msg_ids = tuple([m['messageid'] for m in msg_id])
                                        query = "UPDATE messages SET isread=1 WHERE messageid=%s"
                                        cur.execute(query, (msg_ids[0],))
                                        db.commit()
                                        json_handleclient_messagesend = {"command": "sendmessage",
                                                                         "messagetext": f"{username}: {message}\n",
                                                                         "username": username,
                                                                         "message": message}
                                        clients[tsid].sendall(json.dumps(json_handleclient_messagesend).encode('utf-8'))
                    except Exception:
                        traceback.print_exc()
                        json_handleclient_errorsend = {"command": "sendmessage",
                                                       "server_message": "Error storing/sending message.\n"}
                        conn.sendall(json.dumps(json_handleclient_errorsend).encode('utf-8'))

                elif data.lower() == "search":
                    # List all users in the users table
                    try:
                        with connectsql() as db:
                            with db.cursor() as cur:
                                cur.execute("SELECT username FROM users")
                                rows = cur.fetchall()
                        if len(rows) > 0:
                            all_usernames = ", ".join([row['username'] for row in rows if row['username'] != username])
                            json_handleclient_userlist = {"command": "search",
                                                          "server_message": f"\nAll users:\n{all_usernames}\n ",
                                                          "all_usernames": all_usernames}
                            conn.sendall(json.dumps(json_handleclient_userlist).encode('utf-8'))
                        else:
                            json_handleclient_no_users = {"command": "search",
                                                          "server_message": "No users found.\n"}
                            conn.sendall(json.dumps(json_handleclient_no_users).encode('utf-8'))
                    except Exception as e:
                        traceback.print_exc()
                        json_handleclient_errorsearch = {"command": "search",
                                                         "server_message": "Error while searching for users.\n"}
                        conn.sendall(json.dumps(json_handleclient_errorsearch).encode('utf-8'))

                elif data.lower() == "delete":
                    # Check if user has sent any unread messages
                    try:
                        with connectsql() as db:
                            with db.cursor() as cur:
                                cur.execute("SELECT messageid FROM messages WHERE sender=%s AND isread=0 ORDER BY messageid DESC LIMIT 1""", (username,))
                                row = cur.fetchone()
                                if row:
                                    last_msg_id = row['messageid']
                                    # Confirm with the user that they want to delete the last message they sent
                                    json_handleclient_delete = {"command": "delete",
                                                                "server_message": "Are you sure you want to delete the last message you sent? Type 'yes' or 'no':\n "}
                                    conn.sendall(json.dumps(json_handleclient_delete).encode('utf-8'))

                                    confirm_resp_jsonstr = conn.recv(1024).decode('utf-8')
                                    confirm_resp = json.loads(confirm_resp_jsonstr)["data"].lower() ### FIX ###

                                    if confirm_resp == 'yes':
                                        cur.execute("DELETE FROM messages WHERE messageid=%s", (last_msg_id,))
                                        db.commit()
                                        json_handleclient_deleteconfirm = {"command": "delete",
                                                                           "server_message": "Your last message has been deleted.\n"}
                                        conn.sendall(json.dumps(json_handleclient_deleteconfirm).encode('utf-8'))
                                    else:
                                        json_handleclient_deletecancel = {"command": "delete",
                                                                          "server_message": "Delete canceled.\n"}
                                        conn.sendall(json.dumps(json_handleclient_deletecancel).encode('utf-8'))
                                else:
                                    json_handleclient_no_delete = {"command": "delete",
                                                                  "server_message": "You have not sent any messages able to be deleted. Note that you cannot delete messages already read.\n"}
                                    conn.sendall(json.dumps(json_handleclient_no_delete).encode('utf-8'))
                    except Exception as e:
                        traceback.print_exc()
                        json_handleclient_deleteerror = {"command": "delete",
                                                         "server_message": "Error deleting your last message. Please try again.\n"}
                        conn.sendall(json.dumps(json_handleclient_deleteerror).encode('utf-8'))

                elif data.lower() == "deactivate":
                    # Confirm with the user that this will deactivate (delete) their account
                    json_handleclient_deactivateconfirm = {"command": "deactivate",
                                                           "server_message": "Are you sure you want to deactivate your account?\n This will remove your account and all messages you've sent.\n Type 'yes' to confirm or 'no' to cancel.\n "}
                    conn.sendall(json.dumps(json_handleclient_deactivateconfirm).encode('utf-8'))

                    confirm_resp_jsonstr = conn.recv(1024).decode('utf-8')
                    confirm_resp = json.loads(confirm_resp_jsonstr)["data"].lower() ### FIX ###

                    if confirm_resp == 'yes':
                        try:
                            with connectsql() as db:
                                with db.cursor() as cur:
                                    # Delete all messages sent by this user
                                    cur.execute("DELETE FROM messages WHERE sender=%s", (username,))
                                    # Delete the user record
                                    cur.execute("DELETE FROM users WHERE username=%s", (username,))
                                    db.commit()
                            json_handleclient_deactivatedone = {"command": "deactivate",
                                                                "server_message": "Your account and all your sent messages have been removed. Goodbye.\n"}
                            conn.sendall(json.dumps(json_handleclient_deactivatedone).encode('utf-8'))
                        except Exception as e:
                            traceback.print_exc()
                            json_handleclient_deactivateerror = {"command": "deactivate",
                                                                 "server_message": "Error deactivating your account.\n"}
                            conn.sendall(json.dumps(json_handleclient_deactivateerror).encode('utf-8'))
                        finally:
                            # Force a break so we exit the loop and close connection
                            break
                    else:
                        json_handleclient_deactivatecancel = {"command": "deactivate",
                                                              "server_message": "Account deactivation canceled.\n"}
                        conn.sendall(json.dumps(json_handleclient_deactivatecancel).encode('utf-8'))

                else:
                    # Unrecognized command
                    json_handleclient_unrecognized = {"command": "handleclient",
                                                      "server_message": "Error: Messages must start with '@username' or use 'check', 'logoff',' search', 'delete', or 'deactivate'.\n "}
                    conn.sendall(json.dumps(json_handleclient_unrecognized).encode('utf-8'))

    except Exception as e:
        print("Exception in handle_client:", e)
        traceback.print_exc()
    finally:
        # If user was logged in, mark them inactive
        if username:
            with connectsql() as db:
                with db.cursor() as cur:
                    cur.execute("UPDATE users SET active=0 WHERE username=%s", (username,))
                db.commit()

        if user_id in clients:
            del clients[user_id]
        conn.close()
        print(f"Connection with {addr} closed.")

def start_server():
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))

    chat_pb2_grpc.add_ChatServicer_to_server(ChatService(), server)
    server.add_insecure_port("[::]:50051")
    server.start()
    print("Server started, listening on port 50051")
    server.wait_for_termination()

if __name__ == "__main__":
    start_server()