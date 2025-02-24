import tkinter as tk
from tkinter import scrolledtext
import threading
import queue
import argparse
import os
import time
import logging

import grpc

import chat_pb2
import chat_pb2_grpc

parser = argparse.ArgumentParser(description="Start the chat client.")
parser.add_argument("--host", default=os.getenv("CHAT_SERVER_HOST", "127.0.0.1"), help="Server hostname or IP")
parser.add_argument("--port", type=int, default=int(os.getenv("CHAT_SERVER_PORT", 65432)), help="Port number")
args = parser.parse_args()

HOST = args.host
PORT = args.port

class ChatClient:
    def __init__(self):
        # Connect to server
        channel_addr = f"{HOST}:{PORT}" 
        self.channel = grpc.insecure_channel(channel_addr)
        self.stub = chat_pb2_grpc.ChatStub(self.channel)

        self.root = tk.Tk()
        self.root.title("Chat Client")
        self.receive_queue = queue.Queue()

        self.username = None  # track who is logged in
        self.check_messages_thread = None
        self.check_running = False

        # Build UI frames
        self.build_frames()

        # Show welcome
        self.show_welcome_frame()
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)
        self.root.mainloop()

    def build_frames(self):
        # 1) WELCOME
        self.welcome_frame = tk.Frame(self.root)
        tk.Label(self.welcome_frame, text="Welcome to the Chat!", font=("Helvetica", 16)).pack(pady=10)
        tk.Button(self.welcome_frame, text="Login", command=self.show_login_frame).pack(pady=5)
        tk.Button(self.welcome_frame, text="Register", command=self.show_register_frame).pack(pady=5)

        # 2) LOGIN
        self.login_frame = tk.Frame(self.root)
        tk.Label(self.login_frame, text="Login", font=("Helvetica", 16)).pack(pady=10)
        tk.Label(self.login_frame, text="Username:").pack()
        self.login_user_var = tk.StringVar()
        tk.Entry(self.login_frame, textvariable=self.login_user_var).pack(pady=5)
        tk.Label(self.login_frame, text="Password:").pack()
        self.login_pass_var = tk.StringVar()
        tk.Entry(self.login_frame, textvariable=self.login_pass_var, show="*").pack(pady=5)
        tk.Button(self.login_frame, text="Submit", command=self.do_login).pack(pady=5)
        self.login_error = tk.Label(self.login_frame, fg="red")
        self.login_error.pack(pady=5)

        # 3) REGISTER
        self.register_frame = tk.Frame(self.root)
        tk.Label(self.register_frame, text="Register", font=("Helvetica", 16)).pack(pady=10)
        tk.Label(self.register_frame, text="Username:").pack()
        self.reg_user_var = tk.StringVar()
        tk.Entry(self.register_frame, textvariable=self.reg_user_var).pack(pady=5)
        tk.Label(self.register_frame, text="Password:").pack()
        self.reg_pass_var = tk.StringVar()
        tk.Entry(self.register_frame, textvariable=self.reg_pass_var, show="*").pack(pady=5)
        tk.Label(self.register_frame, text="Confirm Password:").pack()
        self.reg_confirm_var = tk.StringVar()
        tk.Entry(self.register_frame, textvariable=self.reg_confirm_var, show="*").pack(pady=5)
        tk.Button(self.register_frame, text="Submit", command=self.do_register).pack(pady=5)
        self.reg_error = tk.Label(self.register_frame, fg="red")
        self.reg_error.pack(pady=5)

        # 4) CHAT
        self.chat_frame = tk.Frame(self.root)
        self.chat_display = scrolledtext.ScrolledText(self.chat_frame, state='disabled', width=80, height=20)
        self.chat_display.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)

        self.input_frame = tk.Frame(self.chat_frame)
        self.input_frame.pack(fill=tk.X, padx=10, pady=(0, 10))
        self.msg_var = tk.StringVar()
        tk.Entry(self.input_frame, textvariable=self.msg_var, width=60).pack(side=tk.LEFT, fill=tk.X, expand=True)
        tk.Button(self.input_frame, text="Send", command=self.send_message).pack(side=tk.LEFT, padx=5)

        # Buttons for checking messages, logoff, etc.
        self.buttons_frame = tk.Frame(self.chat_frame)
        self.buttons_frame.pack(fill=tk.X)
        tk.Button(self.buttons_frame, text="Check Messages", command=self.check_messages).pack(side=tk.LEFT, padx=5)
        tk.Button(self.buttons_frame, text="Logoff", command=self.do_logoff).pack(side=tk.LEFT, padx=5)
        tk.Button(self.buttons_frame, text="Delete Last", command=self.delete_last_message).pack(side=tk.LEFT, padx=5)
        tk.Button(self.buttons_frame, text="Deactivate", command=self.deactivate_account).pack(side=tk.LEFT, padx=5)

    def show_welcome_frame(self):
        self.login_frame.pack_forget()
        self.register_frame.pack_forget()
        self.chat_frame.pack_forget()
        self.welcome_frame.pack(fill="both", expand=True)

    def show_login_frame(self):
        self.welcome_frame.pack_forget()
        self.register_frame.pack_forget()
        self.login_error.config(text="")
        self.login_user_var.set("")
        self.login_pass_var.set("")
        self.login_frame.pack(fill="both", expand=True)

    def show_register_frame(self):
        self.welcome_frame.pack_forget()
        self.login_frame.pack_forget()
        self.reg_error.config(text="")
        self.reg_user_var.set("")
        self.reg_pass_var.set("")
        self.reg_confirm_var.set("")
        self.register_frame.pack(fill="both", expand=True)

    def show_chat_frame(self):
        self.welcome_frame.pack_forget()
        self.login_frame.pack_forget()
        self.register_frame.pack_forget()
        self.chat_frame.pack(fill="both", expand=True)

    # ---------------------------
    #        LOGIN
    # ---------------------------
    def do_login(self):
        u = self.login_user_var.get().strip()
        p = self.login_pass_var.get().strip()
        if not u or not p:
            self.login_error.config(text="Enter username and password.")
            return

        # Send gRPC
        req = chat_pb2.LoginRequest(username=u, password=p)
        resp = self.stub.Login(req)
        if "Welcome" in resp.server_message:
            self.username = u
            self.login_error.config(text="")
            self.show_chat_frame()
            self.append_message(resp.server_message)
        else:
            self.login_error.config(text=resp.server_message)

    # ---------------------------
    #       REGISTER
    # ---------------------------
    def do_register(self):
        u = self.reg_user_var.get().strip()
        p = self.reg_pass_var.get().strip()
        c = self.reg_confirm_var.get().strip()
        if not u or not p or not c:
            self.reg_error.config(text="All fields required.")
            return

        req = chat_pb2.RegisterRequest(username=u, password=p, confirm_password=c)
        resp = self.stub.Register(req)
        if "successful" in resp.server_message:
            self.username = u
            self.reg_error.config(text="")
            self.show_chat_frame()
            self.append_message(resp.server_message)
        else:
            self.reg_error.config(text=resp.server_message)

    # ---------------------------
    #       CHAT ACTIONS
    # ---------------------------
    def append_message(self, text, sent_by_me=False):
        self.chat_display.config(state='normal')
        self.chat_display.insert(tk.END, text + "\n")
        self.chat_display.config(state='disabled')
        self.chat_display.yview(tk.END)

    def send_message(self):
        """Sends whatever is in the msg_var as a DM. 
           For a real chat, you'd parse an '@recipient' or something."""
        msg = self.msg_var.get().strip()
        if not msg or not self.username:
            return
        self.msg_var.set("")
        # For simplicity, let's assume user typed: @bob Hi Bob
        if msg.startswith("@"):
            parts = msg.split(" ", 1)
            if len(parts) < 2:
                self.append_message("Invalid format. Use '@user <message>'.")
                return
            recipient = parts[0][1:]  # skip '@'
            body = parts[1]
            req = chat_pb2.SendMessageRequest(
                sender=self.username,
                recipient=recipient,
                message_body=body
            )
            resp = self.stub.SendMessage(req)
            self.append_message(f"[You -> {recipient}]: {body}", sent_by_me=True)
            if not resp.success:
                self.append_message(resp.server_message)
        else:
            self.append_message("To send a DM, use '@username message'.")

    def check_messages(self):
        if not self.username:
            return

        # For example, we might do "choice=1" to read, or "2" to skip
        # or pass "sender=..." if we want to read from a specific user.
        req = chat_pb2.CheckMessagesRequest(
            username=self.username,
            choice="1"  # means "I want to read messages"
        )
        # Server streaming => read responses in a thread
        def stream_thread():
            try:
                for msg_res in self.stub.CheckMessages(req):
                    self.receive_queue.put(msg_res.server_message)
            except Exception as e:
                self.receive_queue.put(f"CheckMessages error: {e}")

        self.check_running = True
        t = threading.Thread(target=stream_thread, daemon=True)
        t.start()
        self.poll_check_queue()

    def poll_check_queue(self):
        """Poll the queue for new server messages during check_messages streaming."""
        while not self.receive_queue.empty():
            msg = self.receive_queue.get()
            self.append_message(msg)
        if self.check_running:
            self.root.after(200, self.poll_check_queue)

    def do_logoff(self):
        if not self.username:
            return
        req = chat_pb2.LogoffRequest(username=self.username)
        resp = self.stub.Logoff(req)
        self.append_message(resp.server_message)
        self.username = None
        self.check_running = False
        self.show_welcome_frame()

    def delete_last_message(self):
        if not self.username:
            return
        # For simplicity, always confirm 'yes'
        req = chat_pb2.DeleteRequest(username=self.username, confirmation="yes")
        resp = self.stub.DeleteLastMessage(req)
        self.append_message(resp.server_message)

    def deactivate_account(self):
        if not self.username:
            return
        req = chat_pb2.DeactivateRequest(username=self.username, confirmation="yes")
        resp = self.stub.DeactivateAccount(req)
        self.append_message(resp.server_message)
        self.username = None
        self.check_running = False
        self.show_welcome_frame()

    def on_close(self):
        if self.username:
            try:
                _ = self.stub.Logoff(chat_pb2.LogoffRequest(username=self.username))
            except:
                pass
        self.root.destroy()

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    ChatClient()