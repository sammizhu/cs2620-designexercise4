import time
import traceback
import argparse
import os
import pymysql
import pymysql.cursors
import bcrypt
import grpc
from concurrent import futures
import chat_pb2
import chat_pb2_grpc
import time


# Command-line arguments
parser = argparse.ArgumentParser(description="Start the chat server (gRPC).")
parser.add_argument("--host", default=os.getenv("CHAT_SERVER_HOST", "0.0.0.0"), help="Server hostname or IP")
parser.add_argument("--port", type=int, default=int(os.getenv("CHAT_SERVER_PORT", 65432)), help="Port number")
args = parser.parse_args()
HOST = args.host
PORT = args.port

# Database connection function
def connectsql():
    return pymysql.connect(
        host=HOST,
        user='root',
        password='',
        database='db262',
        cursorclass=pymysql.cursors.DictCursor
    )

# Helper functions
def checkRealUsername(username):
    with connectsql() as db:
        with db.cursor() as cur:
            cur.execute("SELECT COUNT(*) AS cnt FROM users WHERE username=%s", (username,))
            row = cur.fetchone()
            return row['cnt'] > 0

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
    def Register(self, request, context):
        reg_username = request.username.strip()
        reg_password = request.password.strip()
        confirm_password = request.confirm_password.strip()

        if not reg_username or not reg_password or not confirm_password:
            return chat_pb2.Response(
                command="1",
                server_message="Registration canceled: All fields are required."
            )
        if checkRealUsername(reg_username):
            return chat_pb2.Response(
                command="1",
                server_message="Username taken. Please choose another."
            )
        if not checkValidPassword(reg_password):
            return chat_pb2.Response(
                command="1",
                server_message="Invalid password: Must be >=7 chars, include uppercase, digit, and special char."
            )
        if reg_password != confirm_password:
            return chat_pb2.Response(
                command="1",
                server_message="Passwords do not match."
            )
        hashed = hashPass(reg_password)
        try:
            with connectsql() as db:
                with db.cursor() as cur:
                    cur.execute("INSERT INTO users (username, password, active) VALUES (%s, %s, 1)",
                                (reg_username, hashed))
                db.commit()
            return chat_pb2.Response(
                command="1",
                server_message="Registration successful. You are now logged in!"
            )
        except Exception:
            traceback.print_exc()
            return chat_pb2.Response(
                command="1",
                server_message="Server error during registration."
            )

    def Login(self, request, context):
        username = request.username.strip()
        password = request.password.strip()

        if not checkRealUsername(username):
            return chat_pb2.Response(
                command="2",
                server_message="User not found."
            )
        if not checkRealPassword(username, password):
            return chat_pb2.Response(
                command="2",
                server_message="Incorrect password."
            )

        with connectsql() as db:
            with db.cursor() as cur:
                cur.execute("SELECT active FROM users WHERE username=%s", (username,))
                activeStatus = cur.fetchone()
                if activeStatus['active'] == 1:
                    return chat_pb2.Response(
                        command="2",
                        server_message="You are already logged in. Please log out before logging in again."
                    )
                else:
                    cur.execute("UPDATE users SET active=1 WHERE username=%s", (username,))
                    db.commit()
        return chat_pb2.Response(
            command="2",
            server_message=f"Welcome, {username}!"
        )

    def SendMessage(self, request, context):
        full_text = request.message.strip()
        md = dict(context.invocation_metadata())
        sender = md.get("username", "unknown")
        if not full_text.startswith("@"):
            return chat_pb2.SendMessageResponse(
                success=False,
                server_message="To send messages, use '@username message'. You can also type 'check', 'logoff',' search', 'delete', or 'deactivate'."
            )
        parts = full_text.split(" ", 1)
        if len(parts) < 2:
            return chat_pb2.SendMessageResponse(
                success=False,
                server_message="Invalid format. Use '@username message'."
            )
        target_username = parts[0][1:]
        message = parts[1]
        if not checkRealUsername(target_username):
            return chat_pb2.SendMessageResponse(
                success=False,
                server_message="Recipient does not exist."
            )
        try:
            with connectsql() as db:
                with db.cursor() as cur:
                    cur.execute(
                        "INSERT INTO messages (receiver, sender, message, isread) VALUES (%s, %s, %s, 0)",
                        (target_username, sender, message)
                    )
                    db.commit()
            return chat_pb2.SendMessageResponse(
                success=True,
                server_message=""
            )
        except Exception:
            traceback.print_exc()
            return chat_pb2.SendMessageResponse(
                success=False,
                server_message="Error storing message."
            )

    def CheckMessages(self, request_iterator, context):
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
            with connectsql() as db:
                with db.cursor() as cur:
                    cur.execute("SELECT COUNT(*) AS cnt FROM messages WHERE receiver=%s AND isread=0", (username,))
                    row = cur.fetchone()
                    unread_count = row['cnt']
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
            else:
                yield chat_pb2.CheckMessagesResponse(
                    command="checkmessages",
                    server_message = (
                        " ----------------------------------------- \n"
                        f"| You have {unread_count} unread messages.              |\n"
                        "| Type '1' to read them, or '2' to skip    |\n"
                        "| and send new messages.                   |\n"
                        "  ----------------------------------------- "
                ))
            req = next(req_iter, None)
            if req is None:
                yield chat_pb2.CheckMessagesResponse(
                    command="checkmessages",
                    server_message="No choice provided. Aborting."
                )
                return
            choice = req.choice.strip()
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
            with connectsql() as db:
                with db.cursor() as cur:
                    cur.execute("SELECT sender, COUNT(*) as num FROM messages WHERE receiver=%s AND isread=0 GROUP BY sender", (username,))
                    senders_info = cur.fetchall()
            if not senders_info:
                yield chat_pb2.CheckMessagesResponse(
                    command="checkmessages",
                    server_message="No unread messages found."
                )
                return
            senders_str = ", ".join([f"{r['sender']}({r['num']})" for r in senders_info])
            yield chat_pb2.CheckMessagesResponse(
                command="checkmessages",
                server_message=f"You have unread messages from:\n{senders_str}\nWhich sender do you want to read from?"
            )
            req = next(req_iter, None)
            if req is None or not req.sender.strip():
                yield chat_pb2.CheckMessagesResponse(
                    command="checkmessages",
                    server_message="No sender provided. Aborting."
                )
                return
            chosen_sender = req.sender.strip()
            with connectsql() as db:
                with db.cursor() as cur:
                    cur.execute("SELECT messageid, sender, message, datetime FROM messages WHERE receiver=%s AND sender=%s AND isread=0 ORDER BY messageid", (username, chosen_sender))
                    msgs = cur.fetchall()
            if not msgs:
                yield chat_pb2.CheckMessagesResponse(
                    command="checkmessages",
                    server_message=f"No unread messages from {chosen_sender}."
                )
                return
            batch_size = 5
            i = 0
            while i < len(msgs):
                batch = msgs[i:i+batch_size]
                for m in batch:
                    ts = m['datetime'].strftime("%Y-%m-%d %H:%M:%S")
                    yield chat_pb2.CheckMessagesResponse(
                        command="checkmessages",
                        server_message=f"{ts} {m['sender']}: {m['message']}",
                        sender=m['sender'],
                        message_body=m['message']
                    )
                batch_ids = [m['messageid'] for m in batch]
                with connectsql() as db:
                    with db.cursor() as cur:
                        if len(batch_ids) == 1:
                            cur.execute("UPDATE messages SET isread=1 WHERE messageid=%s", (batch_ids[0],))
                        else:
                            placeholders = ','.join(['%s'] * len(batch_ids))
                            cur.execute(f"UPDATE messages SET isread=1 WHERE messageid IN ({placeholders})", batch_ids)
                    db.commit()
                yield chat_pb2.CheckMessagesResponse(
                    command="checkmessages",
                    server_message="(The current batch of messages has been marked as read.)"
                )
                i += batch_size
                if i < len(msgs):
                    yield chat_pb2.CheckMessagesResponse(
                        command="checkmessages",
                        server_message="Type anything to see the next batch of messages..."
                    )
                    try:
                        _ = next(req_iter)
                    except StopIteration:
                        break
            yield chat_pb2.CheckMessagesResponse(
                command="checkmessages",
                server_message="All messages from this sender have been read."
            )
        except Exception as e:
            traceback.print_exc()
            yield chat_pb2.CheckMessagesResponse(
                command="checkmessages",
                server_message="Error: " + str(e)
            )
    
    def History(self, request_iterator, context):
        # given a userID, can see all of the chat history with that specific user
        try:
            yield chat_pb2.Response(
                command="history",
                server_message="Enter userID of the user whose chat history you'd like to view:"
            )
            req_iter = iter(request_iterator)
            confirmation = ""
            while not confirmation:
                req = next(req_iter)
                confirmation = req.confirmation.strip().lower()
            username = req.username.strip()
            if confirmation:
                with connectsql() as db:
                    with db.cursor() as cur:
                        cur.execute("SELECT * FROM messages WHERE sender=%s AND receiver=%s", (username, confirmation))
                        msgs_sent = cur.fetchall()
                        cur.execute("SELECT * FROM messages WHERE sender=%s AND receiver=%s", (confirmation, username))
                        msgs_recieved = cur.fetchall()
                msgs = msgs_sent + list(msgs_recieved)  
                msgs_sorted = sorted(msgs, key=lambda x: x['datetime']) 
                chat_history = "\n".join([f"{m['datetime']} {m['sender']}: {m['message']}" for m in msgs_sorted])
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



    def Logoff(self, request, context):
        username = request.username.strip()
        if not username:
            return chat_pb2.Response(
                command="logoff",
                server_message="No username provided."
            )
        try:
            with connectsql() as db:
                with db.cursor() as cur:
                    cur.execute("UPDATE users SET active=0 WHERE username=%s", (username,))
                db.commit()
            return chat_pb2.Response(
                command="logoff",
                server_message=f"{username} has been logged off."
            )
        except Exception:
            traceback.print_exc()
            return chat_pb2.Response(
                command="logoff",
                server_message="Logoff error."
            )

    def SearchUsers(self, request, context):
        username = request.username.strip()
        try:
            with connectsql() as db:
                with db.cursor() as cur:
                    cur.execute("SELECT username FROM users")
                    rows = cur.fetchall()
            all_users = [r['username'] for r in rows if r['username'] != username]
            return chat_pb2.SearchResponse(
                success=True,
                usernames=all_users,
                server_message="User list retrieved."
            )
        except Exception:
            traceback.print_exc()
            return chat_pb2.SearchResponse(
                success=False,
                usernames=[],
                server_message="Error searching users."
            )

    def DeleteLastMessage(self, request_iterator, context):
        """
        Two-step bidirectional conversation for deleting the last unread message:
        1. The client sends a DeleteRequest (confirmation empty) to trigger the prompt.
        2. The server looks up the last unread message and yields a prompt showing its details.
        3. The client sends a second DeleteRequest with a confirmation.
            If 'yes', the message is deleted; otherwise, deletion is canceled.
        """
        try:
            req_iter = iter(request_iterator)
            # First request: username (confirmation may be empty)
            first_req = next(req_iter, None)
            if first_req is None or not first_req.username.strip():
                yield chat_pb2.Response(
                    command="delete",
                    server_message="No username provided. Aborting."
                )
                return
            username = first_req.username.strip()
            # Look up the last unread message for this user.
            with connectsql() as db:
                with db.cursor() as cur:
                    cur.execute(
                        "SELECT messageid, message, receiver FROM messages WHERE sender=%s AND isread=0 ORDER BY messageid DESC LIMIT 1",
                        (username,)
                    )
                    row = cur.fetchone()
            if not row:
                yield chat_pb2.Response(
                    command="delete",
                    server_message="No unread messages to delete."
                )
                return
            # Yield a prompt showing the message details.
            yield chat_pb2.Response(
                command="delete",
                server_message=f"Your last unread message is: '{row['message']}' sent to {row['receiver']}. Do you want to delete it? (yes/no)"
            )
            # Wait for the second request with the confirmation.
            second_req = next(req_iter, None)
            if second_req is None or not second_req.confirmation.strip():
                yield chat_pb2.Response(
                    command="delete",
                    server_message="No confirmation provided. Delete canceled."
                )
                return
            confirmation = second_req.confirmation.strip().lower()
            if confirmation == "yes":
                with connectsql() as db:
                    with db.cursor() as cur:
                        cur.execute("DELETE FROM messages WHERE messageid=%s", (row['messageid'],))
                    db.commit()
                yield chat_pb2.Response(
                    command="delete",
                    server_message="Your last unread message was deleted."
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
        try:
            yield chat_pb2.Response(
                command="deactivate",
                server_message="Are you sure you want to deactivate your account? (yes/no)"
            )
            req_iter = iter(request_iterator)
            confirmation = ""
            while not confirmation:
                req = next(req_iter)
                confirmation = req.confirmation.strip().lower()
            username = req.username.strip()
            if confirmation == 'yes':
                with connectsql() as db:
                    with db.cursor() as cur:
                        cur.execute("DELETE FROM messages WHERE sender=%s", (username,))
                        cur.execute("DELETE FROM users WHERE username=%s", (username,))
                    db.commit()
                yield chat_pb2.Response(
                    command="deactivate",
                    server_message="Your account and sent messages are removed."
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
    
    def ReceiveMessages(self, request, context):
        """Continuously poll the database for unread messages and stream them to the client."""
        username = request.username.strip()
        while context.is_active():
            with connectsql() as db:
                with db.cursor() as cur:
                    cur.execute("SELECT messageid, sender, message, datetime FROM messages WHERE receiver=%s AND isread=0 ORDER BY datetime", (username,))
                    msgs = cur.fetchall()
            if msgs:
                for m in msgs:
                    ts = m['datetime'].strftime("%Y-%m-%d %H:%M:%S")
                    yield chat_pb2.ReceiveResponse(
                        sender=m['sender'],
                        message=m['message'],
                        timestamp=ts
                    )
                # Mark these messages as read:
                batch_ids = [m['messageid'] for m in msgs]
                with connectsql() as db:
                    with db.cursor() as cur:
                        placeholders = ','.join(['%s'] * len(batch_ids))
                        cur.execute(f"UPDATE messages SET isread=1 WHERE messageid IN ({placeholders})", batch_ids)
                    db.commit()
            time.sleep(1)  

def serve():
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))
    chat_pb2_grpc.add_ChatServicer_to_server(ChatService(), server)
    address = f"{HOST}:{PORT}"
    server.add_insecure_port(address)
    server.start()
    print(f"Server started on {address}")
    server.wait_for_termination()

if __name__ == "__main__":
    serve()