import tkinter as tk
from tkinter import scrolledtext
import threading
import queue
import argparse
import os

from __future__ import print_function

import logging

import grpc
import chat_pb2
import chat_pb2_grpc

# Parse command-line arguments
parser = argparse.ArgumentParser(description="Start the chat client.")
parser.add_argument("--host", default=os.getenv("CHAT_SERVER_HOST", "127.0.0.1"), help="Server hostname or IP")
parser.add_argument("--port", type=int, default=int(os.getenv("CHAT_SERVER_PORT", 65432)), help="Port number")
args = parser.parse_args()

# Use argument or environment variable
HOST = args.host
PORT = args.port
# HOST = '127.0.0.1'
# PORT = 65432

class ChatClient:
    def __init__(self, stub):
        self.root = tk.Tk()
        self.root.title("Chat Client")
        # self.socket = None # Will hold our socket after login/registration
        self.receive_queue = queue.Queue()
        self.running = False # For the chat message receiving thread

        # Keep track of the last prompt we received from server
        self.last_prompt = ""

        with grpc.insecure_channel("localhost:50051") as channel:
            self.stub = chat_pb2_grpc.ChatStub(channel)

        # Create UI pages
        self.welcome_frame = tk.Frame(self.root)
        self.login_frame = tk.Frame(self.root)
        self.register_frame = tk.Frame(self.root)
        self.chat_frame = tk.Frame(self.root)

        self.build_welcome_frame()
        self.build_login_frame()
        self.build_register_frame()
        self.build_chat_frame()

        # Start with the welcome page
        self.show_welcome_page()
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)
        self.root.mainloop()

    # =========================
    #   WELCOME PAGE
    # =========================
    def build_welcome_frame(self):
        label = tk.Label(self.welcome_frame, text="Welcome to EST!\nPlease choose an option:", font=("Helvetica", 16))
        label.pack(pady=10)
        login_btn = tk.Button(self.welcome_frame, text="Login", width=15, command=self.show_login_page)
        login_btn.pack(pady=5)
        register_btn = tk.Button(self.welcome_frame, text="Register", width=15, command=self.show_register_page)
        register_btn.pack(pady=5)

    def show_welcome_page(self):
        self.login_frame.pack_forget()
        self.register_frame.pack_forget()
        self.chat_frame.pack_forget()
        self.welcome_frame.pack(fill="both", expand=True)

    # =========================
    #   LOGIN PAGE
    # =========================
    def build_login_frame(self):
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
        self.welcome_frame.pack_forget()
        self.register_frame.pack_forget()
        self.login_error_label.config(text="")
        self.login_frame.pack(fill="both", expand=True)

    def handle_login(self):
        username = self.login_username_var.get().strip()
        password = self.login_password_var.get().strip()
        if not username or not password:
            self.login_error_label.config(text="Please enter both username and password.")
            return
        self.login_error_label.config(text="") # Clear any previous error
        # Separate thread for the login conversation
        threading.Thread(target=self.login_thread, args=(username, password), daemon=True).start()

    def login_thread(self, username, password):
        try:
            # Tell server "2" => login
            _ = self.stub.SendMessage(chat_pb2.GeneralMessage(command="2"))
            # Wait for "enter username" prompt

            _ = self.stub.SendUsername(chat_pb2.Username(command="2", username=username))
            # Wait for password prompt

            login_password_response = self.stub.SendPassword(chat_pb2.Password(command="2", password=password))
            # Final response
            response = login_password_response.server_message

            if "Welcome" in response:
                self.root.after(0, self.show_chat_page)
                self.receive_queue.put(response)
            else:
                self.root.after(0, lambda: self.login_error_label.config(text=response))

        except Exception as e:
            err = "Login error: " + str(e)
            self.root.after(0, lambda: self.login_error_label.config(text=err))

    # =========================
    #   REGISTER PAGE
    # =========================
    def build_register_frame(self):
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
        self.welcome_frame.pack_forget()
        self.login_frame.pack_forget()
        self.register_error_label.config(text="")
        self.register_frame.pack(fill="both", expand=True)

    def handle_register(self):
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
        threading.Thread(target=self.register_thread, args=(username, password, confirm), daemon=True).start()

    def register_thread(self, username, password, confirm):
        try:
            # Tell server "1" => register
            _ = self.stub.SendMessage(chat_pb2.GeneralMessage(command="1"))
            # Wait for "Enter a username" prompt

            _ = self.stub.SendUsername(chat_pb2.Username(command="1", username=username))
            # Wait for password prompt

            _ = self.stub.SendPassword(chat_pb2.Password(command="1", password=password))
            # Wait for confirm prompt

            register_confirm_response = self.stub.SendPassword(chat_pb2.Password(command="1", password=confirm))
            # Final response
            response = register_confirm_response.server_message
            
            if "successful" in response:
                self.root.after(0, self.show_chat_page)
                self.receive_queue.put(response)
            else:
                self.root.after(0, lambda: self.register_error_label.config(text=response))

        except Exception as e:
            err = "Registration error: " + str(e)
            self.root.after(0, lambda: self.register_error_label.config(text=err))

    # =========================
    #   CHAT PAGE
    # =========================
    def build_chat_frame(self):
        self.chat_display = scrolledtext.ScrolledText(
            self.chat_frame, state='disabled', wrap='word', width=80, height=24
        )
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
        self.welcome_frame.pack_forget()
        self.login_frame.pack_forget()
        self.register_frame.pack_forget()
        self.chat_frame.pack(fill="both", expand=True)
        self.start_receiving()

    def send_message(self, event=None):
        message = self.message_entry.get().strip()
        if not message:
            return

        # Handle local "logoff"
        if message.lower() == "logoff":
            message_body = chat_pb2.GeneralMessage(command="logoff")
            self.append_message(message, sent_by_me=True)
            try:
                _ = self.stub.SendMessage(message_body)
            except:
                pass
            self.running = False
            self.chat_frame.pack_forget()
            self.show_welcome_page()
            return

        # Decide which message to send based on the last prompt from server
        if self.last_prompt and "Type '1' to read them, or '2' to skip" in self.last_prompt:
            message_body = chat_pb2.Choice(choice=message)
        elif self.last_prompt and "Which sender do you want to read from?" in self.last_prompt:
            message_body = chat_pb2.Sender(sender=message)
        elif self.last_prompt and (
             "Are you sure you want to delete" in self.last_prompt
             or "Are you sure you want to deactivate" in self.last_prompt
        ):
            message_body = chat_pb2.Sender(data=message)
        else:
            # Normal usage: "command"
            message_body = chat_pb2.GeneralMessage(command=message)

        # Display on our UI
        self.append_message(message, sent_by_me=True)

        # Send to server
        try:
            _ = self.stub.SendMessage(message_body)
        except Exception as e:
            self.append_message("Error sending message: " + str(e), sent_by_me=True)

        self.message_entry.delete(0, tk.END)

    def append_message(self, message, sent_by_me=False):
        self.chat_display.configure(state='normal')
        if sent_by_me:
            self.chat_display.insert(tk.END, message + "\n", "right")
        else:
            self.chat_display.insert(tk.END, message + "\n")
        self.chat_display.configure(state='disabled')
        self.chat_display.yview(tk.END)

    def start_receiving(self):
        self.running = True
        threading.Thread(target=self.receive_messages, daemon=True).start()
        self.root.after(100, self.poll_receive_queue)

    def receive_messages(self):
        while self.running:
            try:
                data = self.stub.SendMessage(chat_pb2.GeneralMessage())
                data_response = data.server_message
                if not data:
                    self.receive_queue.put("Server closed connection.")
                    break
                self.receive_queue.put(data_response)
            except Exception as e:
                self.receive_queue.put("Receive error: " + str(e))
                break
        self.running = False

    def poll_receive_queue(self):
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
        try:
            # Attempt a clean logoff
            _ = self.stub.SendMessage(chat_pb2.GeneralMessage(command="logoff"))
        except:
            pass
        self.root.destroy()

# def run():
#     with grpc.insecure_channel("localhost:50051") as channel:
#         ChatClient()

if __name__ == "__main__":
    logging.basicConfig()
    ChatClient()