import tkinter as tk
from tkinter import scrolledtext, messagebox
import threading
import socket
import queue
import argparse
import os

# Parse command-line arguments
parser = argparse.ArgumentParser(description="Start the chat client.")
parser.add_argument("--host", default=os.getenv("CHAT_SERVER_HOST", "127.0.0.1"), help="Server hostname or IP")
parser.add_argument("--port", type=int, default=int(os.getenv("CHAT_SERVER_PORT", 65432)), help="Port number")
args = parser.parse_args()

HOST = args.host  # Use argument or environment variable
PORT = args.port  # Use argument or environment variable

class ChatClient:
    """UI interface configuration with various functionalities."""
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Chat Client")
        self.socket = None  
        self.receive_queue = queue.Queue()
        self.running = False  # Chat message receiving thread

        # Different pages as Frames
        self.welcome_frame = tk.Frame(self.root)
        self.login_frame = tk.Frame(self.root)
        self.register_frame = tk.Frame(self.root)
        self.chat_frame = tk.Frame(self.root)

        self.build_welcome_frame()
        self.build_login_frame()
        self.build_register_frame()
        self.build_chat_frame()

        self.show_welcome_page()
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)
        self.root.mainloop()

    # WELCOME PAGE
    def build_welcome_frame(self):
        """Constructs the welcome screen with login and register buttons."""
        label = tk.Label(self.welcome_frame, text="Welcome to EST!\nPlease choose an option:", font=("Helvetica", 16))
        label.pack(pady=10)
        login_btn = tk.Button(self.welcome_frame, text="Login", width=15, command=self.show_login_page)
        login_btn.pack(pady=5)
        register_btn = tk.Button(self.welcome_frame, text="Register", width=15, command=self.show_register_page)
        register_btn.pack(pady=5)

    def show_welcome_page(self):
        """Displays the welcome screen and hides other frames."""
        self.login_frame.pack_forget()
        self.register_frame.pack_forget()
        self.chat_frame.pack_forget()
        self.welcome_frame.pack(fill="both", expand=True)

    # LOGIN PAGE
    def build_login_frame(self):
        """Constructs the login screen with input fields for username and password."""
        label = tk.Label(self.login_frame, text="Login", font=("Helvetica", 16))
        label.pack(pady=10)

        self.login_username_var = tk.StringVar()
        self.login_password_var = tk.StringVar()

        tk.Label(self.login_frame, text="Username:").pack(pady=5)
        tk.Entry(self.login_frame, textvariable=self.login_username_var).pack(pady=5)
        tk.Label(self.login_frame, text="Password:").pack(pady=5)
        tk.Entry(self.login_frame, textvariable=self.login_password_var, show="*").pack(pady=5)

        tk.Button(self.login_frame, text="Submit", width=10, command=self.handle_login).pack(pady=5)

        self.login_error_label = tk.Label(self.login_frame, text="", fg="red")
        self.login_error_label.pack(pady=5)

    def show_login_page(self):
        """Displays the login screen and hides other frames."""
        self.welcome_frame.pack_forget()
        self.register_frame.pack_forget()
        self.login_error_label.config(text="")
        self.login_frame.pack(fill="both", expand=True)

    def handle_login(self):
        """Handles user login by collecting input and initiating a login request in a separate thread."""
        username = self.login_username_var.get().strip()
        password = self.login_password_var.get().strip()
        if not username or not password:
            self.login_error_label.config(text="Please enter both username and password.")
            return
        self.login_error_label.config(text="")  
        # Start a separate thread for the login conversation
        threading.Thread(target=self.login_thread, args=(username, password), daemon=True).start()

    def login_thread(self, username, password):
        """Handles the actual login process by communicating with the server.
        If login is successful, switches to the chat screen.
        If login fails, displays an error message.
        """
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.connect((HOST, PORT))
            # Send "2" to choose registration
            self.socket.sendall("2".encode())
            _ = self.socket.recv(1024).decode()
            self.socket.sendall(username.encode())
            _ = self.socket.recv(1024).decode()
            self.socket.sendall(password.encode())
            result = self.socket.recv(1024).decode()
            if "Welcome" in result:
                # Successful login; switch to chat page
                self.root.after(0, self.show_chat_page)
                self.receive_queue.put(result)
            else:
                # Login failed; show the error message
                self.root.after(0, lambda: self.login_error_label.config(text=result))
                self.socket.close()
                self.socket = None
        except Exception as e:
            err = "Login error: " + str(e)
            self.root.after(0, lambda: self.login_error_label.config(text=err))
            if self.socket:
                self.socket.close()
                self.socket = None

    # REGISTER PAGE
    def build_register_frame(self):
        """Constructs the registration screen with input fields for username, password, and confirmation."""
        label = tk.Label(self.register_frame, text="Register", font=("Helvetica", 16))
        label.pack(pady=10)

        self.reg_username_var = tk.StringVar()
        self.reg_password_var = tk.StringVar()
        self.reg_confirm_var = tk.StringVar()

        tk.Label(self.register_frame, text="Username:").pack(pady=5)
        tk.Entry(self.register_frame, textvariable=self.reg_username_var).pack(pady=5)
        tk.Label(self.register_frame, text="Password:").pack(pady=5)
        tk.Entry(self.register_frame, textvariable=self.reg_password_var, show="*").pack(pady=5)
        tk.Label(self.register_frame, text="Confirm Password:").pack(pady=5)
        tk.Entry(self.register_frame, textvariable=self.reg_confirm_var, show="*").pack(pady=5)

        tk.Button(self.register_frame, text="Submit", width=10, command=self.handle_register).pack(pady=5)

        self.register_error_label = tk.Label(self.register_frame, text="", fg="red")
        self.register_error_label.pack(pady=5)

    def show_register_page(self):
        """Displays the registration screen and hides other frames."""
        self.welcome_frame.pack_forget()
        self.login_frame.pack_forget()
        self.register_error_label.config(text="")
        self.register_frame.pack(fill="both", expand=True)

    def handle_register(self):
        """Handles user registration by collecting input and initiating a registration request in a separate thread."""
        username = self.reg_username_var.get().strip()
        password = self.reg_password_var.get().strip()
        confirm = self.reg_confirm_var.get().strip()
        if not username or not password or not confirm:
            self.register_error_label.config(text="Please fill in all fields.")
            return
        if password != confirm:
            self.register_error_label.config(text="Passwords do not match.")
            return
        self.register_error_label.config(text="")  
        # Start a separate thread for the registration conversation
        threading.Thread(target=self.register_thread, args=(username, password, confirm), daemon=True).start()

    def register_thread(self, username, password, confirm):
        """Handles the actual registration process by communicating with the server.
        If registration is successful, switches to the chat screen.
        If registration fails, displays an error message.
        """
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.connect((HOST, PORT))
            # Send "1" to choose registration
            self.socket.sendall("1".encode())
            _ = self.socket.recv(1024).decode()
            self.socket.sendall(username.encode())
            _ = self.socket.recv(1024).decode()
            self.socket.sendall(password.encode())
            _ = self.socket.recv(1024).decode()
            self.socket.sendall(confirm.encode())
            result = self.socket.recv(1024).decode()
            if "successful" in result:
                self.root.after(0, self.show_chat_page)
                self.receive_queue.put(result)
            else:
                self.root.after(0, lambda: self.register_error_label.config(text=result))
                self.socket.close()
                self.socket = None
        except Exception as e:
            err = "Registration error: " + str(e)
            self.root.after(0, lambda: self.register_error_label.config(text=err))
            if self.socket:
                self.socket.close()
                self.socket = None

    # CHAT PAGE
    def build_chat_frame(self):
        """Constructs the chat screen with a scrolling text area for messages and an input field."""
        self.chat_display = scrolledtext.ScrolledText(self.chat_frame, state='disabled', wrap='word', width=80, height=24)
        self.chat_display.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)
        self.chat_display.tag_configure("right", justify="right")

        self.input_frame = tk.Frame(self.chat_frame)
        self.input_frame.pack(fill=tk.X, padx=10, pady=(0, 10))
        self.message_entry = tk.Entry(self.input_frame, width=70)
        self.message_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        self.message_entry.bind("<Return>", self.send_message)
        self.send_button = tk.Button(self.input_frame, text="Send", command=self.send_message)
        self.send_button.pack(side=tk.LEFT, padx=(5, 0))

    def show_chat_page(self):
        """Displays the chat screen and starts receiving messages from the server."""
        self.welcome_frame.pack_forget()
        self.login_frame.pack_forget()
        self.register_frame.pack_forget()
        self.chat_frame.pack(fill="both", expand=True)
        self.start_receiving()

    def send_message(self, event=None):
        """Sends a message to the server and displays it in the chat window.
        If the message is 'logoff', the client disconnects and returns to the welcome screen.
        """
        message = self.message_entry.get().strip()
        if message:
            self.append_message(message, sent_by_me=True)
            try:
                self.socket.sendall(message.encode())
                if message.lower() == "logoff":
                    # When "logoff" is typed, stop receiving, close the connection,
                    # and go back to the welcome page
                    self.running = False
                    self.socket.close()
                    self.socket = None
                    self.chat_frame.pack_forget()
                    self.show_welcome_page()
                    return
            except Exception as e:
                self.append_message("Error sending message: " + str(e), sent_by_me=True)
            self.message_entry.delete(0, tk.END)

    def append_message(self, message, sent_by_me=False):
        """Appends a message to the chat display.
        If `sent_by_me` is True, the message is aligned to the right.
        """
        self.chat_display.configure(state='normal')
        if sent_by_me:
            self.chat_display.insert(tk.END, message + "\n", "right")
        else:
            self.chat_display.insert(tk.END, message + "\n")
        self.chat_display.configure(state='disabled')
        self.chat_display.yview(tk.END)

    def start_receiving(self):
        """Starts a separate thread to continuously receive messages from the server."""
        self.running = True
        threading.Thread(target=self.receive_messages, daemon=True).start()
        self.root.after(100, self.poll_receive_queue)

    def receive_messages(self):
        """Receives messages from the server in a loop and adds them to the message queue.
        If the connection is closed or an error occurs, stops receiving.
        """
        while self.running:
            try:
                data = self.socket.recv(1024)
                if not data:
                    self.receive_queue.put("Server closed connection.")
                    break
                self.receive_queue.put(data.decode())
            except Exception as e:
                self.receive_queue.put("Receive error: " + str(e))
                break
        self.running = False

    def poll_receive_queue(self):
        """Checks the receive queue for new messages and updates the chat display.
        If the connection is lost, shows a 'Disconnected' message.
        """
        try:
            while True:
                msg = self.receive_queue.get_nowait()
                self.append_message(msg, sent_by_me=False)
        except queue.Empty:
            pass
        if self.running:
            self.root.after(100, self.poll_receive_queue)
        else:
            self.append_message("Disconnected.", sent_by_me=False)

    def on_close(self):
        """Handles closing the application.
        Sends a 'logoff' message to the server (if connected) before exiting.
        """
        try:
            if self.socket:
                self.socket.sendall("logoff".encode())
                self.socket.close()
        except Exception:
            pass
        self.root.destroy()

if __name__ == "__main__":
    ChatClient()