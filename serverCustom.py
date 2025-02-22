import socket
import threading
import pymysql
import pymysql.cursors
import bcrypt
import argparse
import os

# Parse command-line arguments
parser = argparse.ArgumentParser(description="Start the chat server.")
parser.add_argument("--host", default=os.getenv("CHAT_SERVER_HOST", "0.0.0.0"), help="Server hostname or IP")
parser.add_argument("--port", type=int, default=int(os.getenv("CHAT_SERVER_PORT", 65432)), help="Port number")
args = parser.parse_args()

HOST = args.host  # Use argument or environment variable
PORT = args.port  # Use argument or environment variable

clients = {}  


def connectsql():
    """Establishes and returns a connection to the MySQL database."""
    return pymysql.connect(
        host=HOST,
        user='root',
        password='', 
        database='db262',
        cursorclass=pymysql.cursors.DictCursor
    )

def checkRealUsername(username):
    """Checks if the given username exists in the database.
        
        Returns:
            bool: True if the username exists, False otherwise.
    """
    with connectsql() as db:
        with db.cursor() as cur:
            cur.execute("SELECT COUNT(*) AS cnt FROM users WHERE username=%s", (username,))
            row = cur.fetchone()
            if row is None:
                return False
            return (row['cnt'] > 0)

def checkValidPassword(password):
    """Validates if the given password meets security requirements.

    Requirements:
    - At least 7 characters long
    - Contains at least one uppercase letter
    - Contains at least one digit
    - Contains at least one special character (_ @ $ # !)

    Returns:
        bool: True if the password is valid, False otherwise.
    """
    if len(password) < 7:
        return False
    has_upper = any(c.isupper() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_special = any(c in ['_', '@', '$', '#', '!'] for c in password)
    return (has_upper and has_digit and has_special)

def hashPass(password):
    """Hashes a password using bcrypt with a generated salt.

    Returns:
        str: The hashed password as a string.
    """
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed.decode('utf-8')

def checkRealPassword(username, plain_text):
    """Verifies if the provided password matches the stored hashed password for a given username.

    Returns:
        bool: True if the password matches, False otherwise.
    """
    with connectsql() as db:
        with db.cursor() as cur:
            cur.execute("SELECT password FROM users WHERE username=%s", (username,))
            row = cur.fetchone()
            if not row:
                return False
            stored_hash = row['password']
    return bcrypt.checkpw(plain_text.encode('utf-8'), stored_hash.encode('utf-8'))

def handle_registration(conn, user_id):
    """Handles user registration process.
    
    Steps:
    1. Prompt for a unique username.
    2. Prompt for a valid password and confirmation.
    3. Hash and store the password in the database.
    4. Mark the user as active and store the socket ID.
    
    Returns:
        str or None: The registered username if successful, None if registration fails.
    """
    # 1) Prompt repeatedly for username until it's not taken
    while True:
        conn.sendall("Enter a username (alphanumeric): ".encode())
        reg_username = conn.recv(1024).decode().strip()

        if not reg_username:
            # If user just hit Enter or disconnected
            conn.sendall("Registration canceled.\n".encode())
            return None
        
        # If username is taken, let them know and loop again
        if checkRealUsername(reg_username):
            conn.sendall("Username taken. Please choose another.\n".encode())
            continue
        else:
            # Good username
            break
    
    # 2) Prompt repeatedly for password until valid
    while True:
        conn.sendall("Enter a password (>=7 chars, including uppercase, digit, special): ".encode())
        reg_password = conn.recv(1024).decode().strip()

        if not reg_password:
            conn.sendall("Registration canceled.\n".encode())
            return None

        if not checkValidPassword(reg_password):
            conn.sendall("Invalid password. Please try again.\n".encode())
            continue

        # Now ask for confirmation of the password
        conn.sendall("Confirm your password: ".encode())
        confirm_password = conn.recv(1024).decode().strip()

        if reg_password != confirm_password:
            conn.sendall("Passwords do not match. Please try again.\n".encode())
            continue
        else:
            break

    # 3) Hash & store
    hashed = hashPass(reg_password)
    try:
        with connectsql() as db:
            with db.cursor() as cur:
                cur.execute("INSERT INTO users (username, password, active) VALUES (%s, %s, 1)",
                            (reg_username, hashed))
                cur.execute("UPDATE users SET socket_id=%s WHERE username=%s",
                            (str(user_id), reg_username))
            db.commit()
        conn.sendall("Registration successful. You are now logged in!\n".encode())
        return reg_username
    except Exception:
        conn.sendall("Server error. Registration canceled.\n".encode())
        return None

def handle_login(conn, user_id):
    """Handles user login process.
    
    Steps:
    1. Prompt for an existing username.
    2. Verify the provided password.
    3. Mark the user as active and store the socket ID.
    
    Returns:
        str or None: The logged-in username if successful, None if login fails.
    """
    # Prompt repeatedly for username until found
    conn.sendall("Enter your username: ".encode())
    while True:
        login_username = conn.recv(1024).decode().strip()

        if not login_username:
            conn.sendall("Login canceled.\n".encode())
            return None
        
        if not checkRealUsername(login_username):
            conn.sendall("User not found. Please try again.\n".encode())
        else:
            break

    # Prompt repeatedly for password until correct
    while True:
        conn.sendall("Enter your password: ".encode())
        login_password = conn.recv(1024).decode().strip()

        if not login_password:
            conn.sendall("Login canceled.\n".encode())
            return None

        if not checkRealPassword(login_username, login_password):
            conn.sendall("Incorrect password. Try again.\n".encode())
        else:
            break

    # Mark active=1
    with connectsql() as db:
        with db.cursor() as cur:
            cur.execute("UPDATE users SET active=1, socket_id=%s WHERE username=%s",
                        (str(user_id), login_username))
        db.commit()
    conn.sendall(f"Welcome, {login_username}!\n".encode())
    return login_username

def check_messages_server_side(conn, username):
    """Checks for unread messages for a given user.
    
    If unread messages exist:
    - Prompts the user to read or skip.
    - If reading, allows selecting a sender to view messages.
    - Marks messages as read in the database.
    
    Args:
        conn (socket): The client connection.
        username (str): The username of the recipient.
    """
    with connectsql() as db:
        with db.cursor() as cur:
            # Count how many unread messages
            cur.execute("SELECT COUNT(*) AS cnt FROM messages WHERE receiver=%s AND isread=0", (username,))
            row = cur.fetchone()
            unread_count = row['cnt']

            if unread_count == 0:
                conn.sendall("You have 0 unread messages.\n ".encode())
                return

            # If we have unread
            conn.sendall(f" ------------------------------------------\n| You have {unread_count} unread messages.              |\n| Type '1' to read them, or '2' to skip    |\n| and send new messages.                   |\n ------------------------------------------\n """.encode())

            choice = conn.recv(1024).decode().strip()

            if choice == "1":
                # Check which sender(s)
                cur.execute("SELECT sender, COUNT(*) AS num FROM messages WHERE receiver=%s AND isread=0 GROUP BY sender", (username,))
                rows = cur.fetchall()
                if not rows:
                    conn.sendall("No unread messages found (maybe they were just read?).\n".encode())
                    return
                # Show which senders
                senders_info = "\n".join([f"{row['sender']} ({row['num']} messages)" for row in rows])
                conn.sendall(f"You have unread messages from:\n{senders_info}\n".encode())
                conn.sendall("Which sender do you want to read from?\n ".encode())
                
                chosen_sender = conn.recv(1024).decode().strip()
                if not chosen_sender:
                    conn.sendall("Canceled reading messages.\n".encode())
                    return
                
                # Fetch unread messages from the database
                cur.execute(
                    "SELECT messageid, sender, message, datetime FROM messages "
                    "WHERE receiver=%s AND sender=%s AND isread=0 ORDER BY messageid",
                    (username, chosen_sender)
                )
                unread_msgs = cur.fetchall()

                if not unread_msgs:
                    conn.sendall("No unread messages from that user.\n".encode())
                    return

                # Batch size: if more than 5 messages, use batches of 5; otherwise, show all
                batch_size = 5 if len(unread_msgs) > 5 else len(unread_msgs)

                conn.sendall(f"--- Unread messages from {chosen_sender} ---\n".encode())

                for i in range(0, len(unread_msgs), batch_size):
                    batch = unread_msgs[i:i+batch_size]
                    
                    for m in batch:
                        ts = m['datetime'].strftime("%Y-%m-%d %H:%M:%S")
                        conn.sendall(f"{ts} {m['sender']}: {m['message']}\n".encode())
                    
                    # Mark the current batch as read in the database
                    batch_ids = [m['messageid'] for m in batch]
                    if len(batch_ids) == 1:
                        cur.execute("UPDATE messages SET isread=1 WHERE messageid=%s", (batch_ids[0],))
                    else:
                        placeholders = ','.join(['%s'] * len(batch_ids))
                        query = f"UPDATE messages SET isread=1 WHERE messageid IN ({placeholders})"
                        cur.execute(query, batch_ids)
                    
                    db.commit()
                    conn.sendall("The current batch of messages has been marked as read.\n".encode())

                    # If there are more messages, wait for the user input before showing the next batch.
                    if i + batch_size < len(unread_msgs):
                        conn.sendall("Type anything to see the next batch of messages...\n".encode())
                        _ = conn.recv(1024)  # Wait for user input
            elif choice == "2":
                # Skips reading, user can continue
                return 
            else:
                conn.sendall("Invalid choice. Returning to main.\n".encode())

def handle_client(conn, addr):
    """Handles a new client connection and processes their requests.
    
    Steps:
    - Prompt for login or registration.
    - If logged in, handle message sending, checking, and user commands.
    - Manage user logoff, search, delete message, and deactivate account requests.
    
    Args:
        conn (socket): The client connection.
        addr (tuple): The client's address.
    """
    user_id = addr[1]
    clients[user_id] = conn
    print(f"New connection from {addr}")
    
    logged_in = False
    username = None

    try:
        while True:
            data = conn.recv(1024).decode().strip()
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
                        # check unread (should be none if newly registered, but let's be consistent)
                        check_messages_server_side(conn, username)
                        conn.sendall("To send messages, use '@username message'. You can also type 'check', 'logoff',' search', 'delete', or 'deactivate'.\n ".encode())
                elif data == "2":
                    logged_user = handle_login(conn, user_id)
                    if logged_user:
                        username = logged_user
                        logged_in = True
                        # check unread for returning user
                        check_messages_server_side(conn, username)
                        conn.sendall("To send messages, use '@username message'. You can also type 'check', 'logoff',' search', 'delete', or 'deactivate'.\n ".encode())
            
            # If logged in => handle DM sending, check, or logoff
            else:
                if data.lower() == "logoff":
                    # Mark user inactive
                    with connectsql() as db:
                        with db.cursor() as cur:
                            cur.execute("UPDATE users SET active=0 WHERE username=%s", (username,))
                        db.commit()
                    conn.sendall("Logged off.\n".encode())
                    break

                elif data.lower() == "check":
                    check_messages_server_side(conn, username)
                
                elif data.startswith("@"):
                    # parse DM
                    parts = data.split(" ", 1)
                    if len(parts) < 2:
                        conn.sendall("Invalid format. Use '@username message'.\n".encode())
                        continue
                    target_username, message = parts[0][1:], parts[1]
                    try:
                        with connectsql() as db:
                            with db.cursor() as cur:
                                # If target online, send message --> otherwise just keep it stored in messages table above
                                cur.execute("SELECT socket_id, active FROM users WHERE username=%s", (target_username,))
                                row = cur.fetchone()
                                if row:
                                    cur.execute("INSERT INTO messages (receiver, sender, message, isread) VALUES (%s, %s, %s, 0)", (target_username, username, message))
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
                                            clients[tsid].sendall(f"{username}: {message}\n".encode())
                                else:
                                    conn.sendall("Username does not exist.\n".encode())

                    except Exception:
                        conn.sendall("Error storing/sending message.\n".encode())
                
                elif data.lower() == "search":
                    # List all users in the users table
                    try:
                        with connectsql() as db:
                            with db.cursor() as cur:
                                cur.execute("SELECT username FROM users")
                                rows = cur.fetchall()
                        if len(rows) > 1:
                            all_usernames = ", ".join([row['username'] for row in rows if row['username'] != username])
                            conn.sendall(f"\nAll users:\n{all_usernames}\n ".encode())
                        else:
                            conn.sendall("No users found.\n".encode())
                    except Exception as e:
                        conn.sendall("Error while searching for users.\n".encode())
                
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
                                    conn.sendall("Are you sure you want to delete the last message you sent? Type 'yes' or 'no':\n ".encode())
                                    confirm_resp = conn.recv(1024).decode().strip().lower()
                                    if confirm_resp == 'yes':
                                        cur.execute("DELETE FROM messages WHERE messageid=%s", (last_msg_id,))
                                        db.commit()
                                        conn.sendall("Your last message has been deleted.\n".encode())
                                    else:
                                        conn.sendall("Delete canceled.\n".encode())
                                else:
                                    conn.sendall("You have not sent any messages able to be deleted. Note that you cannot delete messages already read.\n".encode())
                    except Exception as e:
                        conn.sendall("Error deleting your last message. Please try again.\n".encode())

                elif data.lower() == "deactivate":
                    # Confirm with the user that this will deactivate (delete) their account
                    conn.sendall(
                        "Are you sure you want to deactivate your account?\n"
                        "This will remove your account and all messages you've sent.\n"
                        "Type 'yes' to confirm or 'no' to cancel.\n ".encode()
                    )
                    confirm_resp = conn.recv(1024).decode().strip().lower()
                    if confirm_resp == 'yes':
                        try:
                            with connectsql() as db:
                                with db.cursor() as cur:
                                    # Delete all messages sent by this user
                                    cur.execute("DELETE FROM messages WHERE sender=%s", (username,))
                                    # Delete the user record
                                    cur.execute("DELETE FROM users WHERE username=%s", (username,))
                                    db.commit()
                            conn.sendall("Your account and all your sent messages have been removed. Goodbye.\n".encode())
                        except Exception as e:
                            conn.sendall("Error deactivating your account.\n".encode())
                        finally:
                            # Force a break so we exit the loop and close connection
                            break
                    else:
                        conn.sendall("Account deactivation canceled.\n".encode())
                
                else:
                    # unrecognized command
                    conn.sendall("Error: Messages must start with '@username' or use 'check', 'logoff',' search', 'delete', or 'deactivate'.\n ".encode())

    except Exception as e:
        print("Exception in handle_client:", e)
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
    """Starts the chat server and listens for incoming client connections.

    - Binds the server to the specified host and port.
    - Accepts new client connections.
    - Spawns a new thread to handle each client.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind((HOST, PORT))
        server_socket.listen()
        print(f"Server listening on {HOST}:{PORT}...")

        while True:
            conn, addr = server_socket.accept()
            t = threading.Thread(target=handle_client, args=(conn, addr), daemon=True)
            t.start()

if __name__ == "__main__":
    start_server()