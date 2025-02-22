"""
Usage:
  coverage run --source=clientJson testClientJSON.py
  coverage report -m
"""

import unittest
from unittest.mock import patch, MagicMock
import tkinter as tk
from tkinter import scrolledtext
import threading
import socket
import queue
import time
import json

# Import from your JSON client implementation (adjust if needed).
import clientJson as client


class TestableChatClient(client.ChatClient):
    """
    A subclass of the JSON ChatClient that avoids mainloop in __init__
    so we can run tests without blocking. We override just enough to 
    prevent self.root.mainloop() from being called.
    """
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Test Chat Client (JSON) - Integration")
        self.socket = None
        self.receive_queue = queue.Queue()
        self.running = False

        self.last_prompt = ""

        # Build frames, but do NOT call mainloop().
        self.welcome_frame = tk.Frame(self.root)
        self.login_frame = tk.Frame(self.root)
        self.register_frame = tk.Frame(self.root)
        self.chat_frame = tk.Frame(self.root)

        self.build_welcome_frame()
        self.build_login_frame()
        self.build_register_frame()
        self.build_chat_frame()

    def destroy(self):
        try:
            self.root.destroy()
        except tk.TclError:
            pass


class FakeSocketClient:
    """
    A simple fake socket that returns a predefined list of responses.
    We also track how many bytes the client attempts to send in total_sent.
    """
    def __init__(self, responses):
        self.responses = list(responses)
        self.sent_messages = []
        self.total_sent = 0
        self.closed = False

    def connect(self, address):
        pass

    def sendall(self, data):
        self.total_sent += len(data)
        self.sent_messages.append(data)

    def recv(self, bufsize):
        if self.responses:
            return self.responses.pop(0).encode('utf-8')
        return "".encode('utf-8')

    def close(self):
        self.closed = True


class TestClientJSONUnit(unittest.TestCase):
    """
    Unit tests for JSON client focusing on individual methods and small behaviors.
    """
    def setUp(self):
        self.client = TestableChatClient()

    def tearDown(self):
        self.client.destroy()

    def test_build_welcome_frame(self):
        """Check welcome frame has child widgets."""
        children = self.client.welcome_frame.winfo_children()
        self.assertGreater(len(children), 0)

    def test_show_welcome_page(self):
        """Ensure show_welcome_page hides other frames and shows welcome."""
        self.client.welcome_frame.pack = MagicMock()
        self.client.login_frame.pack_forget = MagicMock()
        self.client.register_frame.pack_forget = MagicMock()
        self.client.chat_frame.pack_forget = MagicMock()

        self.client.show_welcome_page()
        self.client.welcome_frame.pack.assert_called_once()
        self.client.login_frame.pack_forget.assert_called_once()
        self.client.register_frame.pack_forget.assert_called_once()
        self.client.chat_frame.pack_forget.assert_called_once()

    def test_append_message(self):
        """append_message should place text in chat_display."""
        self.client.chat_display.configure(state='normal')
        self.client.chat_display.delete("1.0", tk.END)
        self.client.append_message("Test JSON message", sent_by_me=True)
        content = self.client.chat_display.get("1.0", tk.END)
        self.assertIn("Test JSON message", content)

    def test_send_message(self):
        """Check that send_message encodes JSON data and calls sendall."""
        fake_socket = FakeSocketClient([])
        self.client.socket = fake_socket
        self.client.message_entry.insert(0, "some_command")

        self.client.send_message()
        self.assertTrue(fake_socket.sent_messages, "Should have sent at least one message.")
        sent_data = fake_socket.sent_messages[0].decode('utf-8')
        self.assertIn('"command": "some_command"', sent_data)

    def test_on_close(self):
        """Ensure on_close sends a JSON logoff command if socket is open."""
        fake_socket = FakeSocketClient([])
        self.client.socket = fake_socket

        self.client.on_close()
        self.assertTrue(fake_socket.closed)
        self.assertTrue(fake_socket.sent_messages, "Expected a logoff JSON message to be sent.")
        logoff_data = fake_socket.sent_messages[0].decode('utf-8')
        self.assertIn('"command": "logoff"', logoff_data)


class TestClientJSONRegression(unittest.TestCase):
    """
    Regression tests to ensure the JSON client doesn't crash on edge cases.
    """
    def setUp(self):
        self.client = TestableChatClient()

    def tearDown(self):
        self.client.destroy()

    def test_empty_username_login(self):
        """Check that an empty username doesn't crash login_thread."""
        self.client.login_username_var.set("")
        self.client.login_password_var.set("Password123!")
        try:
            self.client.login_thread("", "Password123!")
        except Exception as e:
            self.fail(f"Client crashed on empty username: {e}")

    def test_mismatched_register_passwords(self):
        """If password != confirm, the client shows error (just like custom version)."""
        self.client.reg_username_var.set("newUser")
        self.client.reg_password_var.set("Abc123!")
        self.client.reg_confirm_var.set("Mismatch1!")

        self.client.register_thread("newUser", "Abc123!", "Mismatch1!")
        self.client.root.update()

        error_text = self.client.register_error_label.cget("text")
        self.assertNotEqual(error_text, "")

    def test_unexpected_server_message(self):
        """Ensure unexpected JSON or garbage doesn't crash the client."""
        responses = ["not_valid_json"]
        fake_socket = FakeSocketClient(responses)
        self.client.socket = fake_socket
        self.client.running = True

        try:
            data = fake_socket.recv(1024).decode('utf-8')
            self.client.receive_queue.put(data)
            self.client.poll_receive_queue()
        except Exception as e:
            self.fail(f"Client crashed on unexpected server message: {e}")


class TestClientJSONIntegration(unittest.TestCase):
    """
    Integration tests that simulate real flows (login, register, etc.) 
    with a fake JSON server socket. We'll measure total bytes the client 
    tries to send, similar to testClientCustom integration tests.
    """

    def setUp(self):
        self.client = TestableChatClient()
        self.fake_socket = None

    def tearDown(self):
        if self.fake_socket:
            print(f"\nFakeSocket bytes sent: {self.fake_socket.total_sent}")
        self.client.destroy()

    #
    # 1) Login success test
    #
    @patch('socket.socket')
    def test_login_thread_success(self, mock_socket_class):
        """
        Simulate a successful login:
          1) JSON server first prompts for username
          2) Then prompts for password
          3) Final server response has "Welcome"
          => The client should pack the chat_frame (show_chat_page).
        """
        # Responses the server sends at each step:
        #  - "Enter your username"
        #  - "Enter your password"
        #  - "Welcome, testuser!"
        responses = [
            json.dumps({"server_message": "Enter your username:"}),
            json.dumps({"server_message": "Enter your password:"}),
            json.dumps({"server_message": "Welcome, testuser!"})
        ]
        self.fake_socket = FakeSocketClient(responses)
        mock_socket_class.return_value = self.fake_socket

        # Fill in the GUI entry fields
        self.client.login_username_var.set("testuser")
        self.client.login_password_var.set("Abc123!")

        # Start login
        self.client.login_thread("testuser", "Abc123!")

        # Wait a bit so the background thread can do its work
        time.sleep(0.2)
        self.client.root.update()

        # Check if chat frame is packed => success
        try:
            info = self.client.chat_frame.pack_info()
        except tk.TclError:
            info = None

        self.assertIsNotNone(info, "Chat frame not packed => login might have failed.")

    #
    # 2) Register success test
    #
    @patch('socket.socket')
    def test_register_thread_success(self, mock_socket_class):
        """
        Simulate a successful registration flow:
         - final server_message: "Registration successful..."
         => The client calls show_chat_page => chat_frame gets packed
        """
        responses = [
            json.dumps({"server_message": "Enter a username:"}),
            json.dumps({"server_message": "Enter a password:"}),
            json.dumps({"server_message": "Confirm your password:"}),
            json.dumps({"server_message": "Registration successful. You are now logged in!"})
        ]
        self.fake_socket = FakeSocketClient(responses)
        mock_socket_class.return_value = self.fake_socket

        self.client.reg_username_var.set("myjsonuser")
        self.client.reg_password_var.set("Abc123!")
        self.client.reg_confirm_var.set("Abc123!")

        self.client.register_thread("myjsonuser", "Abc123!", "Abc123!")
        time.sleep(0.2)
        self.client.root.update()

        try:
            info = self.client.chat_frame.pack_info()
        except tk.TclError:
            info = None

        self.assertIsNotNone(info, "Chat frame not packed => registration might have failed.")

    #
    # 3) Receive messages
    #
    def test_receive_messages_thread(self):
        """
        We push multiple JSON messages into the FakeSocket, the client 
        should parse & display them in chat_display.
        """
        responses = [
            json.dumps({"server_message": "Hello from JSON server #1"}),
            json.dumps({"server_message": "Hello from JSON server #2"})
        ]
        self.fake_socket = FakeSocketClient(responses)
        self.client.socket = self.fake_socket
        self.client.running = True

        def fake_receiver():
            while self.client.running:
                data = self.fake_socket.recv(1024).decode('utf-8')
                if not data:
                    break
                self.client.receive_queue.put(data)

        recv_thread = threading.Thread(target=fake_receiver, daemon=True)
        recv_thread.start()
        time.sleep(0.1)

        self.client.poll_receive_queue()
        self.client.running = False
        recv_thread.join()

        chat_text = self.client.chat_display.get("1.0", tk.END)
        self.assertIn("Hello from JSON server #1", chat_text)
        self.assertIn("Hello from JSON server #2", chat_text)



if __name__ == '__main__':
    unittest.main()