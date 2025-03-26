#!/usr/bin/env python3
import tkinter as tk
from tkinter import scrolledtext
import threading
import queue
import os
import grpc
import chat_pb2
import chat_pb2_grpc
import sys
from grpc import RpcError, StatusCode
import configparser

def load_client_config(filename="client.ini"):
    parser = configparser.ConfigParser()
    parser.read(filename)
    if not parser.has_section("client"):
        raise Exception(f"[client] section not found in {filename}")

    raw_servers = parser.get("client", "servers", fallback="")
    if not raw_servers.strip():
        raise Exception(f"No servers found in {filename} under [client] servers=")

    # parse each "host:port" pair
    server_candidates = []
    for item in raw_servers.split(","):
        item = item.strip()
        host, port_str = item.split(":")
        server_candidates.append((host.strip(), int(port_str.strip())))
    return server_candidates

class ChatClient:
    def __init__(self, config_file="client.ini"):
        self.root = tk.Tk()
        self.root.title("Chat Client (gRPC)")

        self.username = None
        self.stub = None
        self.channel = None
        self.active_bidi = None
        self.bidi_queue = None

        self.server_candidates = load_client_config(config_file) # List of candidate servers for failover
        self.current_server_index = 0  # which server we are currently using

        # Build the frames/pages
        self.welcome_frame = tk.Frame(self.root)
        self.login_frame = tk.Frame(self.root)
        self.register_frame = tk.Frame(self.root)
        self.chat_frame = tk.Frame(self.root)

        self.build_welcome_frame()
        self.build_login_frame()
        self.build_register_frame()
        self.build_chat_frame()
        self.show_welcome_page()

        # Cleanly close on window exit
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)
        self.root.mainloop()

    # Utility: connect to a server by index
    def connect_to_server(self, index):
        """Set self.stub to whichever server is at self.server_candidates[index]."""
        srv_host, srv_port = self.server_candidates[index]
        print(f"[DEBUG] Attempting connection to {srv_host}:{srv_port} ...")
        self.channel = grpc.insecure_channel(f"{srv_host}:{srv_port}")
        self.stub = chat_pb2_grpc.ChatStub(self.channel)

    # Utility: wrapper for all gRPC calls to handle failover
    def grpc_call(self, method_name, *args, **kwargs):
        """
        Attempt a gRPC call on the current stub. We pass the gRPC method name (string)
        and then do getattr(self.stub, method_name). If it fails with UNAVAILABLE,
        or a similar error, move to the next server in a round-robin fashion.
        """
        # default short timeout if not given
        if method_name not in ("ReceiveMessages", "CheckMessages"):
            if 'timeout' not in kwargs:
                kwargs['timeout'] = 3.0 

        try:
            stub_method = getattr(self.stub, method_name)
            return stub_method(*args, **kwargs)
        except RpcError as e:
            if e.code() in (StatusCode.UNAVAILABLE, StatusCode.DEADLINE_EXCEEDED, StatusCode.INTERNAL):
                print(f"[DEBUG] Server {self.server_candidates[self.current_server_index]} might be down. Failing over.")
                return self.failover_and_retry(method_name, *args, **kwargs)
            else:
                print("[DEBUG] grpc_call caught RpcError:", e)
                raise
        except Exception as ex:
            print("[DEBUG] grpc_call caught generic exception:", ex)
            return self.failover_and_retry(method_name, *args, **kwargs)

    def failover_and_retry(self, method_name, *args, **kwargs):
        """
        Keep trying the 'next' server in a round-robin fashion until one call succeeds
        or we've tried all servers. If all fail, raise an exception.
        Also reorder the server list so the working server becomes index 0 after success.
        """
        total = len(self.server_candidates)
        original_index = self.current_server_index

        # We'll try 'total-1' times, because we already tried the initial server
        for attempt in range(total - 1):
            self.current_server_index = (self.current_server_index + 1) % total

            # If we've looped around to the original index, we've tried them all
            if self.current_server_index == original_index:
                break

            srv_host, srv_port = self.server_candidates[self.current_server_index]
            print(f"[DEBUG] Failover attempt {attempt+1}: trying {srv_host}:{srv_port}...")
            self.connect_to_server(self.current_server_index)

            new_rpc_func = getattr(self.stub, method_name)
            try:
                # Attempt the same RPC call on the new server
                result = new_rpc_func(*args, **kwargs)
                # If success, reorder so this working server becomes index 0
                working_server = self.server_candidates.pop(self.current_server_index)
                self.server_candidates.insert(0, working_server)
                self.current_server_index = 0
                return result
            except Exception as e:
                print(f"[DEBUG] Server {srv_host}:{srv_port} also failed with: {e}")

        raise Exception("All servers are unavailable after full failover attempt.")

    # Build UI frames
    def build_welcome_frame(self):
        label = tk.Label(self.welcome_frame, text="Welcome to EST!\nPlease choose an option:", font=("Helvetica", 16))
        label.pack(pady=10)
        login_btn = tk.Button(self.welcome_frame, text="Login", width=15, command=self.show_login_page)
        login_btn.pack(pady=5)
        register_btn = tk.Button(self.welcome_frame, text="Register", width=15, command=self.show_register_page)
        register_btn.pack(pady=5)

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

    def build_chat_frame(self):
        self.chat_display = scrolledtext.ScrolledText(self.chat_frame, state='disabled', wrap='word', width=80, height=24)
        self.chat_display.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)
        self.chat_display.tag_configure("right", justify="right")

        self.input_frame = tk.Frame(self.chat_frame)
        self.input_frame.pack(fill=tk.X, padx=10, pady=(0,10))
        self.message_entry = tk.Entry(self.input_frame, width=70)
        self.message_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        self.message_entry.bind("<Return>", self.send_message)
        self.send_button = tk.Button(self.input_frame, text="Send", command=self.send_message)
        self.send_button.pack(side=tk.LEFT, padx=(5,0))

    # Navigation
    def show_welcome_page(self):
        self.login_frame.pack_forget()
        self.register_frame.pack_forget()
        self.chat_frame.pack_forget()
        self.welcome_frame.pack(fill="both", expand=True)

    def show_login_page(self):
        self.welcome_frame.pack_forget()
        self.register_frame.pack_forget()
        self.login_error_label.config(text="")
        self.login_frame.pack(fill="both", expand=True)

    def show_register_page(self):
        self.welcome_frame.pack_forget()
        self.login_frame.pack_forget()
        self.register_error_label.config(text="")
        self.register_frame.pack(fill="both", expand=True)

    def show_chat_page(self):
        self.welcome_frame.pack_forget()
        self.login_frame.pack_forget()
        self.register_frame.pack_forget()
        self.chat_frame.pack(fill="both", expand=True)

    # Login/Registration
    def handle_login(self):
        username = self.login_username_var.get().strip()
        password = self.login_password_var.get().strip()
        if not username or not password:
            self.login_error_label.config(text="Please enter both username and password.")
            return

        threading.Thread(target=self.login_thread, args=(username, password), daemon=True).start()

    def login_thread(self, username, password):
        # Start by connecting to server_candidates[0]
        self.current_server_index = 0
        self.connect_to_server(self.current_server_index)

        error_msg = ""
        try:
            # pass the method name "Login" instead of self.stub.Login
            response = self.grpc_call(
                "Login",
                chat_pb2.LoginRequest(username=username, password=password)
            )
            if "Welcome" in response.server_message:
                self.username = username
                self.root.after(0, self.show_chat_page)
                self.append_message("Welcome, " + username + "!", sent_by_me=False)
                # Start background threads
                threading.Thread(target=self.process_messages_flow, daemon=True).start()
                return
            else:
                # server responded but it's not success
                error_msg = "Login error: " + response.server_message
        except Exception as e:
            error_msg = str(e)

        self.root.after(0, lambda: self.login_error_label.config(text=error_msg))

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

        threading.Thread(target=self.register_thread, args=(username, password, confirm), daemon=True).start()

    def register_thread(self, username, password, confirm):
        self.current_server_index = 0
        self.connect_to_server(self.current_server_index)

        error_msg = ""
        try:
            # pass "Register" as the method name
            response = self.grpc_call(
                "Register",
                chat_pb2.RegisterRequest(username=username, password=password, confirm_password=confirm)
            )
            if "successful" in response.server_message.lower():
                self.username = username
                self.root.after(0, self.show_chat_page)
                self.append_message("Welcome, " + username + "!", sent_by_me=False)
                threading.Thread(target=self.process_messages_flow, daemon=True).start()
                return
            else:
                error_msg = response.server_message
        except Exception as e:
            error_msg = str(e)

        self.root.after(0, lambda: self.register_error_label.config(text=error_msg))

    # Message flows
    def process_messages_flow(self):
        # Check old messages, then start receiving new ones
        self.check_messages_stream()
        self.receive_messages_stream()

    def check_messages_stream(self):
        self.active_bidi = "check"
        self.bidi_queue = queue.Queue()

        def request_generator():
            yield chat_pb2.CheckMessagesRequest(username=self.username)
            while True:
                user_input = self.bidi_queue.get()
                if user_input in ("1", "2"):
                    yield chat_pb2.CheckMessagesRequest(username=self.username, choice=user_input)
                else:
                    yield chat_pb2.CheckMessagesRequest(username=self.username, sender=user_input)

        try:
            responses = self.grpc_call(
                "CheckMessages",
                request_generator(),
                metadata=(('username', self.username),)
            )
            for resp in responses:
                self.append_message(resp.server_message, sent_by_me=False)
                if resp.server_message in ["Skipping reading messages.", "Invalid choice. Aborting."]:
                    break
        except RpcError as err:
            if err.code() == StatusCode.CANCELLED:
                pass
            else:
                print("Error in check_messages_stream:", err)
        except Exception as e:
            print("Error in check_messages_stream:", e)
        finally:
            self.active_bidi = None

    def receive_messages_stream(self):
        """We auto re-initiate if the server goes down mid-stream,
           so the user doesn't have to type commands again."""
        try:
            responses = self.grpc_call(
                "ReceiveMessages",
                chat_pb2.ReceiveRequest(username=self.username)
            )
            for resp in responses:
                display = f"[{resp.timestamp}] {resp.sender}: {resp.message}"
                self.append_message(display, sent_by_me=False)
        except Exception as e:
            print("Error in receive_messages_stream:", e)
            # Re-initiate in new thread
            threading.Thread(target=self.receive_messages_stream, daemon=True).start()

    def history_messages_stream(self):
        self.active_bidi = "history"
        self.bidi_queue = queue.Queue()

        def request_gen():
            yield chat_pb2.HistoryRequest(username=self.username, confirmation="")
            while True:
                confirmation = self.bidi_queue.get().strip()
                yield chat_pb2.HistoryRequest(username=self.username, confirmation=confirmation.lower())

        try:
            responses = self.grpc_call(
                "History",
                request_gen(),
                metadata=(('username', self.username),)
            )
            for resp in responses:
                self.append_message(resp.server_message, sent_by_me=False)
        except Exception as e:
            print("Error in history_messages_stream:", e)
        finally:
            self.active_bidi = None

    def delete_last_message_stream(self):
        self.active_bidi = "delete"
        self.bidi_queue = queue.Queue()

        def request_gen():
            yield chat_pb2.DeleteRequest(username=self.username, confirmation="")
            while True:
                confirmation = self.bidi_queue.get().strip()
                yield chat_pb2.DeleteRequest(username=self.username, confirmation=confirmation.lower())

        try:
            responses = self.grpc_call(
                "DeleteLastMessage",
                request_gen(),
                metadata=(('username', self.username),)
            )
            for resp in responses:
                self.append_message(resp.server_message, sent_by_me=False)
        except Exception as e:
            print("Error in delete_last_message_stream:", e)
        finally:
            self.active_bidi = None

    def deactivate_account_stream(self):
        self.active_bidi = "deactivate"
        self.bidi_queue = queue.Queue()

        def request_gen():
            yield chat_pb2.DeactivateRequest(username=self.username, confirmation="")
            while True:
                confirmation = self.bidi_queue.get().strip()
                yield chat_pb2.DeactivateRequest(username=self.username, confirmation=confirmation.lower())

        try:
            responses = self.grpc_call(
                "DeactivateAccount",
                request_gen(),
                metadata=(('username', self.username),)
            )
            for resp in responses:
                self.append_message(resp.server_message, sent_by_me=False)
                if "removed" in resp.server_message:
                    self.close_connection()
        except Exception as e:
            print("Error in deactivate_account_stream:", e)
        finally:
            self.active_bidi = None

    # Sending messages from GUI
    def send_message(self, event=None):
        message = self.message_entry.get().strip()
        if not message:
            return
        self.message_entry.delete(0, tk.END)

        # If in a streaming 2-step conversation
        if self.active_bidi:
            self.bidi_queue.put(message)
            self.append_message(message, sent_by_me=True)
            return

        # Display user's typed message
        self.append_message(message, sent_by_me=True)

        cmd_lower = message.lower()
        if cmd_lower == "check":
            threading.Thread(target=self.check_messages_stream, daemon=True).start()
            return
        if cmd_lower == "delete":
            threading.Thread(target=self.delete_last_message_stream, daemon=True).start()
            return
        if cmd_lower == "deactivate":
            threading.Thread(target=self.deactivate_account_stream, daemon=True).start()
            return
        if cmd_lower == "search":
            def do_search():
                try:
                    response = self.grpc_call(
                        "SearchUsers",
                        chat_pb2.SearchRequest(username=self.username),
                        metadata=(('username', self.username),)
                    )
                    self.append_message(response.server_message, sent_by_me=False)
                    if response.success and response.usernames:
                        self.append_message("Users: " + ", ".join(response.usernames), sent_by_me=False)
                except Exception as e:
                    print("Error searching users:", e)
            threading.Thread(target=do_search, daemon=True).start()
            return
        if cmd_lower == "history":
            threading.Thread(target=self.history_messages_stream, daemon=True).start()
            return
        if cmd_lower == "logoff":
            def do_logoff():
                try:
                    response = self.grpc_call(
                        "Logoff",
                        chat_pb2.LogoffRequest(username=self.username),
                        metadata=(('username', self.username),)
                    )
                    self.append_message(response.server_message, sent_by_me=False)
                    self.close_connection()
                except Exception as e:
                    print("Error on logoff:", e)
            threading.Thread(target=do_logoff, daemon=True).start()
            return
        if message.startswith("@"):
            def do_send_direct():
                try:
                    response = self.grpc_call(
                        "SendMessage",
                        chat_pb2.GeneralMessage(command="sendmessage", message=message),
                        metadata=(('username', self.username),)
                    )
                    self.append_message(response.server_message, sent_by_me=False)
                except Exception as e:
                    print("Error sending direct message:", e)
            threading.Thread(target=do_send_direct, daemon=True).start()
            return

        # Default: treat as a normal message
        def do_send():
            try:
                response = self.grpc_call(
                    "SendMessage",
                    chat_pb2.GeneralMessage(command="sendmessage", message=message),
                    metadata=(('username', self.username),)
                )
                self.append_message(response.server_message, sent_by_me=False)
            except Exception as e:
                print("Error sending message:", e)
        threading.Thread(target=do_send, daemon=True).start()

    def append_message(self, message, sent_by_me=False):
        self.chat_display.configure(state='normal')
        if sent_by_me:
            self.chat_display.insert(tk.END, message + "\n", "right")
        else:
            self.chat_display.insert(tk.END, message + "\n")
        self.chat_display.configure(state='disabled')
        self.chat_display.yview(tk.END)

    def close_connection(self):
        if self.channel:
            self.channel.close()
        self.channel = None
        self.stub = None
        self.username = None
        self.chat_frame.pack_forget()
        self.show_welcome_page()

    def on_close(self):
        try:
            if self.stub and self.username:
                self.grpc_call(
                    "Logoff",
                    chat_pb2.LogoffRequest(username=self.username)
                )
        except:
            pass
        self.close_connection()
        self.root.destroy()
        

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Chat Client with server config in a file.")
    parser.add_argument("--config", default="client.ini", help="Path to client config (INI) file.")
    args = parser.parse_args()

    ChatClient(config_file=args.config)