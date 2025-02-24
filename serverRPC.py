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

                            yield chat_pb2.CheckMessagesResponse(command="checkmessage", server_message="The current batch of messages has been marked as read.\n")

                            # If there are more messages, wait for the user input before showing the next batch.
                            if i + batch_size < len(unread_msgs):
                                yield chat_pb2.CheckMessagesResponse(command="checkmessage", server_message="Type anything to see the next batch of messages...\n")
                    
                    elif choice == "2":
                        # Skips reading, user can continue
                        return
                    
                    else:
                        yield chat_pb2.CheckMessagesResponse(command="checkmessage", server_message="Invalid choice. Returning to main.\n")

    def SendMessage(self, request, context):
        """Send a message from one user to another."""          
        sender = request.sender
        recipient = request.recipient
        message_body = request.message_body

        try:
            with connectsql() as db:
                with db.cursor() as cur:
                    cur.execute("SELECT socket_id, active FROM users WHERE username=%s", (recipient,))
                    row = cur.fetchone()
                    if row:
                        # Insert into DB
                        cur.execute("""INSERT INTO messages (receiver, sender, message, isread)
                                    VALUES (%s, %s, %s, 0)""",
                                    (recipient, sender, message_body))
                        db.commit()
                        if row['active'] and row['socket_id'] and row['socket_id'].isdigit():
                            tsid = int(row['socket_id'])
                            if tsid in clients:
                                cur.execute("SELECT messageid FROM messages WHERE message=%s", (message))
                                msg_id = cur.fetchall()
                                msg_ids = tuple([m['messageid'] for m in msg_id])
                                query = "UPDATE messages SET isread=1 WHERE messageid=%s"
                                cur.execute(query, (msg_ids[0],))
                                db.commit()
                                msg_data = {
                                'sender': sender,
                                'message_body': message_body,
                                'timestamp': time.strftime("%Y-%m-%d %H:%M:%S")
                            }
                            user_message_queues[recipient].put(msg_data)
                    else:
                        return chat_pb2.SendMessageResponse(
                        success=False,
                        server_message="Username does not exist."
                    )

        except Exception as e:
            traceback.print_exc()
            return chat_pb2.SendMessageResponse(
                success=False,
                server_message="Error storing/sending message."
            )

        # If we reach here, the message was sent successfully but not sure if this is actually neccessary 
        # Logic here is a bit confusing because I'm not sure if this will automatically send if the user is active 
        return chat_pb2.SendMessageResponse(
            success=True,
            server_message="Message sent successfully."
        )
    
    def CheckMessages(self, request, context):
        """
        Server-streaming: yield unread messages (in batches) or 
        show how many unread exist.
        """
        username = request.username
        choice = request.choice
        chosen_sender = request.sender

        if not username:
            # Just yield one response and end
            yield chat_pb2.CheckMessagesResponse(
                command="checkmessages",
                server_message="Invalid username."
            )
            return

        # Count unread
        with connectsql() as db:
            with db.cursor() as cur:
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

                # Unread messages
                yield chat_pb2.CheckMessagesResponse(
                    command="checkmessages",
                    server_message=f"You have {unread_count} unread messages total."
                )

                # Handling client choice
                if choice == "2":
                    # user chose to skip reading
                    yield chat_pb2.CheckMessagesResponse(
                        command="checkmessages",
                        server_message="Skipping reading messages."
                    )
                    return

                # Read from a particular sender
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
                        server_message="No unread messages found (possibly updated)."
                    )
                    return

                # Show all senders & counts
                info_str = "\n".join(
                    [f"{r['sender']} ({r['num']} messages)" for r in senders_info]
                )
                yield chat_pb2.CheckMessagesResponse(
                    command="checkmessages",
                    server_message=f"Unread messages from:\n{info_str}\n"
                )

                # If the client has specified a sender to read from (request.sender)
                if chosen_sender:
                    # fetch those messages
                    cur.execute("""
                        SELECT messageid, sender, message, datetime
                        FROM messages
                        WHERE receiver=%s AND sender=%s AND isread=0
                        ORDER BY messageid
                    """, (username, chosen_sender))
                    unread_msgs = cur.fetchall()
                    if not unread_msgs:
                        yield chat_pb2.CheckMessagesResponse(
                            command="checkmessages",
                            server_message=f"No unread messages from {chosen_sender}."
                        )
                        return

                    # Batch for display: if more than 5, show in batches of 5
                    batch_size = 5
                    for i in range(0, len(unread_msgs), batch_size):
                        batch = unread_msgs[i:i+batch_size]
                        for msg in batch:
                            timestamp_str = msg['datetime'].strftime("%Y-%m-%d %H:%M:%S")
                            yield chat_pb2.CheckMessagesResponse(
                                command="checkmessages",
                                server_message=f"{timestamp_str} {msg['sender']}: {msg['message']}",
                                sender=msg['sender'],
                                message_body=msg['message']
                            )

                        # Mark as read
                        batch_ids = [m['messageid'] for m in batch]
                        q_marks = ','.join(['%s'] * len(batch_ids))
                        update_sql = f"UPDATE messages SET isread=1 WHERE messageid IN ({q_marks})"
                        cur.execute(update_sql, batch_ids)
                        db.commit()

                        yield chat_pb2.CheckMessagesResponse(
                            command="checkmessages",
                            server_message="(This batch marked as read.)"
                        )

                        # If more messages remain, use a prompt to continue
                        if i + batch_size < len(unread_msgs):
                            yield chat_pb2.CheckMessagesResponse(
                            command="checkmessages",
                            server_message="Type anything to see the next batch of messages..."
                        )

                    return

                # Error handling 
                yield chat_pb2.CheckMessagesResponse(
                    command="checkmessages",
                    server_message="Please specify a sender to read from, or choose to skip."
                )

    def Logoff(self, request, context):
        """Mark the user as inactive (active=0)."""
        username = request.username
        if not username:
            return chat_pb2.Response(
                command="logoff",
                server_message="No username provided."
            )

        with connectsql() as db:
            with db.cursor() as cur:
                cur.execute("UPDATE users SET active=0 WHERE username=%s", (username,))
                db.commit()

        return chat_pb2.Response(
            command="logoff",
            server_message=f"{username} has been logged off."
        )

    def Logoff(self, request, context):
        """Mark the user as inactive (active=0)."""
        username = request.username
        if not username:
            return chat_pb2.Response(
                command="logoff",
                server_message="No username provided."
            )

        with connectsql() as db:
            with db.cursor() as cur:
                cur.execute("UPDATE users SET active=0 WHERE username=%s", (username,))
                db.commit()

        return chat_pb2.Response(
            command="logoff",
            server_message=f"{username} has been logged off."
        )

    def DeleteLastMessage(self, request, context):
        """
        Delete the last *unread* message that this user has sent, 
        if 'confirmation' == 'yes'.
        """
        username = request.username
        confirmation = request.confirmation.lower() if request.confirmation else "no"

        if confirmation != 'yes':
            return chat_pb2.Response(
                command="delete",
                server_message="Delete canceled (no confirmation)."
            )

        try:
            with connectsql() as db:
                with db.cursor() as cur:
                    # Check the last unread message (sender=the user, isread=0)
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
                            server_message="You have not sent any messages able to be deleted. Note that you cannot delete messages already read."
                        )
                    last_msg_id = row['messageid']
                    # Delete it
                    cur.execute("DELETE FROM messages WHERE messageid=%s", (last_msg_id,))
                    db.commit()
            return chat_pb2.Response(
                command="delete",
                server_message="Your last unread message was deleted."
            )

        except Exception:
            traceback.print_exc()
            return chat_pb2.Response(
                command="delete",
                server_message="Error deleting your last message."
            )
            
    def DeactivateAccount(self, request, context):
        """
        Permanently delete a user’s account and all messages they've sent
        if 'confirmation' == 'yes'.
        """
        username = request.username
        confirmation = request.confirmation.lower() if request.confirmation else "no"

        if confirmation != 'yes':
            return chat_pb2.Response(
                command="deactivate",
                server_message="Account deactivation canceled (no confirmation)."
            )

        try:
            with connectsql() as db:
                with db.cursor() as cur:
                    # Delete all messages sent by this user
                    cur.execute("DELETE FROM messages WHERE sender=%s", (username,))
                    # Delete user record
                    cur.execute("DELETE FROM users WHERE username=%s", (username,))
                    db.commit()
            return chat_pb2.Response(
                command="deactivate",
                server_message="Your account and all sent messages have been removed."
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
    server.add_insecure_port("[::]:50051")
    server.start()
    print("Server started, listening on port 50051")
    server.wait_for_termination()

if __name__ == "__main__":
    start_server()