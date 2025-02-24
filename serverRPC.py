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

parser = argparse.ArgumentParser(description="Start the chat server.")
parser.add_argument("--host", default=os.getenv("CHAT_SERVER_HOST", "0.0.0.0"), help="Server hostname or IP")
parser.add_argument("--port", type=int, default=int(os.getenv("CHAT_SERVER_PORT", 65432)), help="Port number")
args = parser.parse_args()

HOST = args.host
PORT = args.port

def connectsql():
    return pymysql.connect(
        host=HOST,       # or "localhost"
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
        """Register a new user with (username, password, confirm_password)."""
        reg_username = request.username.strip()
        reg_password = request.password.strip()
        confirm_password = request.confirm_password.strip()

        if not reg_username or not reg_password or not confirm_password:
            return chat_pb2.Response(
                command="register",
                server_message="Please fill in all fields."
            )

        if checkRealUsername(reg_username):
            return chat_pb2.Response(
                command="register",
                server_message="Username is already taken."
            )

        if not checkValidPassword(reg_password):
            return chat_pb2.Response(
                command="register",
                server_message="Password must be >= 7 chars, have uppercase, digit, special char."
            )

        if reg_password != confirm_password:
            return chat_pb2.Response(
                command="register",
                server_message="Passwords do not match."
            )

        # Insert into DB
        try:
            hashed = hashPass(reg_password)
            with connectsql() as db:
                with db.cursor() as cur:
                    cur.execute("""
                        INSERT INTO users (username, password, active)
                        VALUES (%s, %s, 1)
                    """, (reg_username, hashed))
                    db.commit()
            return chat_pb2.Response(
                command="register",
                server_message="Registration successful! You are now logged in."
            )
        except Exception:
            traceback.print_exc()
            return chat_pb2.Response(
                command="register",
                server_message="Server error. Could not register."
            )

    def Login(self, request, context):
        """Login with (username, password)."""
        username = request.username.strip()
        password = request.password.strip()

        if not checkRealUsername(username):
            return chat_pb2.Response(
                command="login",
                server_message="User not found."
            )

        if not checkRealPassword(username, password):
            return chat_pb2.Response(
                command="login",
                server_message="Incorrect password."
            )

        # Mark active=1
        with connectsql() as db:
            with db.cursor() as cur:
                cur.execute("UPDATE users SET active=1 WHERE username=%s", (username,))
                db.commit()

        return chat_pb2.Response(
            command="login",
            server_message=f"Welcome, {username}!"
        )

    def SendMessage(self, request, context):
        """Sends a message to the DB. Doesn't do real-time push in this example."""
        sender = request.sender.strip()
        recipient = request.recipient.strip()
        message_body = request.message_body.strip()

        if not checkRealUsername(recipient):
            return chat_pb2.SendMessageResponse(
                success=False,
                server_message="Recipient does not exist."
            )

        # Insert message
        try:
            with connectsql() as db:
                with db.cursor() as cur:
                    cur.execute("""
                        INSERT INTO messages (receiver, sender, message, isread)
                        VALUES (%s, %s, %s, 0)
                    """, (recipient, sender, message_body))
                    db.commit()
        except Exception:
            traceback.print_exc()
            return chat_pb2.SendMessageResponse(
                success=False,
                server_message="Error storing message."
            )

        return chat_pb2.SendMessageResponse(
            success=True,
            server_message="Message sent successfully."
        )

    def CheckMessages(self, request, context):
        """
        Server-streaming:
        - We show how many unread messages
        - If choice == "2", skip
        - If choice == "1", check which senders, then which sender user wants
        - This example is simplified but demonstrates streaming multiple responses
        """
        username = request.username.strip()
        choice = request.choice.strip()
        chosen_sender = request.sender.strip() if request.sender else ""

        if not username:
            yield chat_pb2.CheckMessagesResponse(
                command="checkmessages",
                server_message="Invalid username."
            )
            return

        with connectsql() as db:
            with db.cursor() as cur:
                # Count unread
                cur.execute("""
                    SELECT COUNT(*) AS cnt
                    FROM messages
                    WHERE receiver=%s AND isread=0
                """, (username,))
                row = cur.fetchone()
                unread_count = row['cnt']

                if unread_count == 0:
                    yield chat_pb2.CheckMessagesResponse(
                        command="checkmessages",
                        server_message="You have 0 unread messages."
                    )
                    return

                # We have some unread
                yield chat_pb2.CheckMessagesResponse(
                    command="checkmessages",
                    server_message=f"You have {unread_count} unread messages."
                )

                # If the user chooses "2" => skip reading
                if choice == "2":
                    yield chat_pb2.CheckMessagesResponse(
                        command="checkmessages",
                        server_message="Skipping reading messages."
                    )
                    return

                # Otherwise list senders
                cur.execute("""
                    SELECT sender, COUNT(*) as num
                    FROM messages
                    WHERE receiver=%s AND isread=0
                    GROUP BY sender
                """, (username,))
                senders_info = cur.fetchall()
                if not senders_info:
                    yield chat_pb2.CheckMessagesResponse(
                        command="checkmessages",
                        server_message="No unread messages found (maybe updated?)."
                    )
                    return

                senders_str = "\n".join([f"{r['sender']} ({r['num']} msg)" for r in senders_info])
                yield chat_pb2.CheckMessagesResponse(
                    command="checkmessages",
                    server_message=f"Unread from:\n{senders_str}"
                )

                # If user specified a sender to read from:
                if chosen_sender:
                    cur.execute("""
                        SELECT messageid, sender, message, datetime
                        FROM messages
                        WHERE receiver=%s AND sender=%s AND isread=0
                        ORDER BY messageid
                    """, (username, chosen_sender))
                    msgs = cur.fetchall()
                    if not msgs:
                        yield chat_pb2.CheckMessagesResponse(
                            command="checkmessages",
                            server_message=f"No unread messages from {chosen_sender}."
                        )
                        return

                    # Stream them in batches of 5
                    batch_size = 5
                    for i in range(0, len(msgs), batch_size):
                        batch = msgs[i:i+batch_size]
                        for m in batch:
                            ts = m['datetime'].strftime("%Y-%m-%d %H:%M:%S")
                            yield chat_pb2.CheckMessagesResponse(
                                command="checkmessages",
                                server_message=f"{ts} {m['sender']}: {m['message']}",
                                sender=m['sender'],
                                message_body=m['message']
                            )

                        # Mark as read
                        batch_ids = [m['messageid'] for m in batch]
                        placeholders = ','.join(['%s'] * len(batch_ids))
                        cur.execute(f"""
                            UPDATE messages
                            SET isread=1
                            WHERE messageid IN ({placeholders})
                        """, batch_ids)
                        db.commit()

                        yield chat_pb2.CheckMessagesResponse(
                            command="checkmessages",
                            server_message="(This batch marked as read.)"
                        )

                        # If more left, you could prompt the client to continue
                    return

                # If no chosen_sender, yield prompt
                yield chat_pb2.CheckMessagesResponse(
                    command="checkmessages",
                    server_message="Please specify which sender to read from."
                )

    def Logoff(self, request, context):
        """Mark user as inactive."""
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
        """Return a list of all users (excluding self if desired)."""
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

    def DeleteLastMessage(self, request, context):
        """Delete last unread message from this user if confirmation == 'yes'."""
        username = request.username.strip()
        confirmation = request.confirmation.strip().lower()
        if confirmation != 'yes':
            return chat_pb2.Response(
                command="delete",
                server_message="Delete canceled (no confirmation)."
            )
        try:
            with connectsql() as db:
                with db.cursor() as cur:
                    cur.execute("""
                        SELECT messageid
                        FROM messages
                        WHERE sender=%s AND isread=0
                        ORDER BY messageid DESC
                        LIMIT 1
                    """, (username,))
                    row = cur.fetchone()
                    if not row:
                        return chat_pb2.Response(
                            command="delete",
                            server_message="No unread messages to delete."
                        )
                    last_id = row['messageid']
                    cur.execute("DELETE FROM messages WHERE messageid=%s", (last_id,))
                    db.commit()
            return chat_pb2.Response(
                command="delete",
                server_message="Your last unread message was deleted."
            )
        except Exception:
            traceback.print_exc()
            return chat_pb2.Response(
                command="delete",
                server_message="Error deleting message."
            )

    def DeactivateAccount(self, request, context):
        """Permanently remove user & messages if confirmation == 'yes'."""
        username = request.username.strip()
        confirmation = request.confirmation.strip().lower()
        if confirmation != 'yes':
            return chat_pb2.Response(
                command="deactivate",
                server_message="Deactivation canceled."
            )
        try:
            with connectsql() as db:
                with db.cursor() as cur:
                    # Remove all sent messages
                    cur.execute("DELETE FROM messages WHERE sender=%s", (username,))
                    # Remove user
                    cur.execute("DELETE FROM users WHERE username=%s", (username,))
                    db.commit()
            return chat_pb2.Response(
                command="deactivate",
                server_message="Your account and sent messages are removed."
            )
        except Exception:
            traceback.print_exc()
            return chat_pb2.Response(
                command="deactivate",
                server_message="Error deactivating account."
            )

def start_server():
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))
    chat_pb2_grpc.add_ChatServicer_to_server(ChatService(), server)
    address = f"{HOST}:{PORT}"
    server.add_insecure_port(address)

    server.start()
    print(f"Server started, listening on {address}")
    server.wait_for_termination()

if __name__ == "__main__":
    start_server()