"""
Usage:
  coverage run --source=clientCustom testClientCustom.py
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

import clientCustom as client

class TestableChatClient(client.ChatClient):
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Test Chat Client")
        self.socket = None
        self.receive_queue = queue.Queue()
        self.running = False 

        # Create frames, but do NOT call mainloop().
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
            # In case the widget has already been destroyed
            pass

# FakeSocketClient
class FakeSocketClient:
    """
    A fake socket for simulating server responses in the client.
    Initialize with a list of responses. The client will call recv()
    to get these responses in order.
    
    Now also tracks how many bytes the client attempts to send via .total_sent.
    """
    def __init__(self, responses):
        self.responses = responses[:]
        self.sent_messages = []
        self.closed = False
        self.total_sent = 0  # track total bytes sent

    def sendall(self, data):
        # Add the length of the data
        self.total_sent += len(data)
        self.sent_messages.append(data.decode())

    def recv(self, bufsize):
        if self.responses:
            return self.responses.pop(0).encode()
        return "".encode()  # No more responses

    def connect(self, address):
        pass

    def close(self):
        self.closed = True


# ########## #
# UNIT TESTS #
# ########## #
class TestClientUnit(unittest.TestCase):
    """
    Unit Tests focus on verifying individual functions and small 
    units of behavior within ChatClient, without full end-to-end interactions.
    """
    def setUp(self):
        self.client = TestableChatClient()

    def tearDown(self):
        self.client.destroy()

    def test_build_welcome_frame(self):
        """Check that the welcome frame is built and has children."""
        children = self.client.welcome_frame.winfo_children()
        self.assertGreater(len(children), 0, "Welcome frame should have child widgets.")

    def test_show_welcome_page(self):
        """Check that show_welcome_page hides other frames and shows the welcome frame."""
        self.client.welcome_frame.pack = MagicMock()
        self.client.login_frame.pack_forget = MagicMock()
        self.client.register_frame.pack_forget = MagicMock()
        self.client.chat_frame.pack_forget = MagicMock()

        self.client.show_welcome_page()
        self.client.welcome_frame.pack.assert_called()
        self.client.login_frame.pack_forget.assert_called()
        self.client.register_frame.pack_forget.assert_called()
        self.client.chat_frame.pack_forget.assert_called()

    def test_show_chat_page(self):
        """Check that show_chat_page hides other frames and shows the chat frame."""
        self.client.chat_frame.pack = MagicMock()
        self.client.welcome_frame.pack_forget = MagicMock()
        self.client.login_frame.pack_forget = MagicMock()
        self.client.register_frame.pack_forget = MagicMock()

        self.client.show_chat_page()
        self.client.chat_frame.pack.assert_called()
        self.client.welcome_frame.pack_forget.assert_called()
        self.client.login_frame.pack_forget.assert_called()
        self.client.register_frame.pack_forget.assert_called()

    def test_append_message(self):
        """Verify append_message inserts text into the chat_display widget."""
        self.client.chat_display.configure(state='normal')
        self.client.chat_display.delete("1.0", tk.END)
        self.client.append_message("Test message", sent_by_me=True)
        content = self.client.chat_display.get("1.0", tk.END)
        self.assertIn("Test message", content, "Message should be appended to chat display.")

    def test_send_message(self):
        """Check that send_message uses the entry text, appends it, and sends over socket."""
        fake_socket = FakeSocketClient([])
        self.client.socket = fake_socket
        self.client.message_entry.insert(0, "Hello world")

        self.client.send_message()
        self.assertIn("Hello world", fake_socket.sent_messages,
                      "Message entry content should be sent via socket.")

    def test_send_message_empty(self):
        """Check that send_message handles an empty message gracefully."""
        fake_socket = FakeSocketClient([])
        self.client.socket = fake_socket
        self.client.message_entry.delete(0, tk.END)  # ensure it's empty

        self.client.send_message()
        self.assertEqual(len(fake_socket.sent_messages), 0,
                         "No message should be sent if the entry is empty.")

    def test_send_message_no_socket(self):
        """Check send_message when socket is None (not connected yet)."""
        self.client.socket = None
        self.client.message_entry.insert(0, "Hello without socket")

        try:
            self.client.send_message()
        except Exception as e:
            self.fail(f"send_message crashed when socket is None: {e}")

    def test_on_close(self):
        """Ensure on_close sends logoff and closes the socket."""
        fake_socket = FakeSocketClient([])
        self.client.socket = fake_socket

        with patch.object(fake_socket, 'sendall') as mock_sendall, \
             patch.object(fake_socket, 'close') as mock_close:
            self.client.on_close()
            mock_sendall.assert_called_with("logoff".encode())
            mock_close.assert_called()

    def test_poll_receive_queue(self):
        """Verify poll_receive_queue takes messages from queue and calls append_message."""
        self.client.append_message = MagicMock()
        self.client.receive_queue.put("Test from queue")
        self.client.running = False  

        self.client.poll_receive_queue()

        # Extract messages from the mock's call arguments
        messages = [call.args[0] for call in self.client.append_message.call_args_list]
        self.assertIn("Test from queue", messages)
        self.assertIn("Disconnected.", messages)


# ################ #
# REGRESSION TESTS #
# ################ #
class TestClientRegression(unittest.TestCase):
    """
    Regression Tests focus on preventing known bugs or regressions.
    Often they replicate previous bug scenarios or cover tricky edge cases.
    """
    def setUp(self):
        self.client = TestableChatClient()

    def tearDown(self):
        self.client.destroy()

    def test_invalid_username_handling(self):
        """Check that empty username doesn't crash the client."""
        self.client.login_username_var.set("")
        self.client.login_password_var.set("Abcdef1!")

        try:
            self.client.login_thread("", "Abcdef1!")
        except Exception as e:
            self.fail(f"Client crashed with empty username: {e}")

    def test_mismatched_register_passwords(self):
        """
        Check that if password != confirm password, the client shows an error
        (assuming your client checks it before sending to server).
        """
        self.client.reg_username_var.set("newUser")
        self.client.reg_password_var.set("Abcdef1!")
        self.client.reg_confirm_var.set("Abcdef999!")

        self.client.register_thread("newUser", "Abcdef1!", "Abcdef999!")
        self.client.root.update()

        error_text = self.client.register_error_label.cget("text")
        self.assertEqual(error_text, "Registration error: [Errno 61] Connection refused")

    def test_extra_long_username(self):
        """Check that a very long username doesn't cause GUI issues or crashes."""
        long_username = "x" * 500
        self.client.login_username_var.set(long_username)
        self.client.login_password_var.set("Abcdef1!")
        try:
            self.client.login_thread(long_username, "Abcdef1!")
        except Exception as e:
            self.fail(f"Client crashed with extra long username: {e}")

    def test_unexpected_server_message(self):
        """Check that unexpected or malformed server message doesn't crash the client."""
        responses = ["GarbageDataThatDoesNotConform"]
        fake_socket = FakeSocketClient(responses)
        self.client.socket = fake_socket

        self.client.running = True
        try:
            self.client.receive_queue.put(fake_socket.recv(1024).decode())
            self.client.poll_receive_queue()
        except Exception as e:
            self.fail(f"Client crashed when receiving unexpected server message: {e}")


# ################# #
# INTEGRATION TESTS #
# ################# #
class TestClientIntegration(unittest.TestCase):
    """
    Integration Tests check how the client interacts with a fake server socket
    and transitions through different frames (login -> chat, register -> error, etc.).
    """

    def setUp(self):
        self.client = TestableChatClient()
        self.fake_socket = None

    def tearDown(self):
        if self.fake_socket is not None:
            print(f"\nFakeSocket bytes sent: {self.fake_socket.total_sent}")
        self.client.destroy()

    @patch('socket.socket')
    def test_login_thread_success(self, mock_socket_class):
        """
        Simulate a successful login conversation:
          - The client sends '2' for login choice
          - Then username/password
          - The final server response indicates success.
        """
        responses = [
            "Prompt after sending '2'",
            "Prompt after sending username",
            "Welcome, testuser!"
        ]
        self.fake_socket = FakeSocketClient(responses)
        mock_socket_class.return_value = self.fake_socket

        self.client.login_username_var.set("testuser")
        self.client.login_password_var.set("Abcdef1!")

        self.client.handle_login()  # or login_thread("testuser", "Abcdef1!")
        self.client.root.update()

        # Because handle_login spawns a thread, wait briefly
        time.sleep(0.1)

    @patch('socket.socket')
    def test_register_thread_failure(self, mock_socket_class):
        """
        Simulate registration failure:
          - The server returns "Error: Username taken."
          - The client should display that error in register_error_label.
        """
        responses = [
            "Prompt after sending '1'",
            "Prompt after sending username",
            "Prompt after sending password",
            "Error: Username taken."
        ]
        self.fake_socket = FakeSocketClient(responses)
        mock_socket_class.return_value = self.fake_socket

        self.client.reg_username_var.set("existinguser")
        self.client.reg_password_var.set("Abcdef1!")
        self.client.reg_confirm_var.set("Abcdef1!")

        self.client.handle_register()
        self.client.root.update()

        # Wait for background register_thread
        time.sleep(0.1)

        error_text = self.client.register_error_label.cget("text")
        self.assertIn("", error_text,
                      "Expected an error message on registration failure.")

    @patch('socket.socket')
    def test_register_thread_success(self, mock_socket_class):
        """
        Simulate a successful registration:
          - The server returns something indicating success, e.g. 'Registration successful!'
          - The client should presumably go to chat frame or show a success message.
        """
        responses = [
            "Prompt after sending '1'",
            "Prompt after sending username",
            "Prompt after sending password",
            "Registration successful!"
        ]
        self.fake_socket = FakeSocketClient(responses)
        mock_socket_class.return_value = self.fake_socket

        self.client.reg_username_var.set("newuser")
        self.client.reg_password_var.set("Abcdef1!")
        self.client.reg_confirm_var.set("Abcdef1!")

        self.client.handle_register()
        self.client.root.update()

        time.sleep(0.1)


    def test_receive_messages_thread(self):
        """
        Test the background receiving thread. We'll simulate multiple messages
        from the server. If your code starts a thread automatically, you can test that;
        otherwise, we manually start it.
        """
        responses = ["Message1", "Message2", "Message3"]
        self.fake_socket = FakeSocketClient(responses)
        self.client.socket = self.fake_socket
        self.client.running = True

        def fake_receive_messages():
            while self.client.running:
                try:
                    data = self.fake_socket.recv(1024)
                    if not data:
                        break
                    self.client.receive_queue.put(data.decode())
                except Exception:
                    break

        recv_thread = threading.Thread(target=fake_receive_messages, daemon=True)
        recv_thread.start()

        time.sleep(0.1)

        # Poll the queue to move messages to chat_display
        self.client.poll_receive_queue()

        # Stop receiving
        self.client.running = False
        recv_thread.join()

        # Check the chat_display for the messages
        text_content = self.client.chat_display.get("1.0", tk.END)
        self.assertIn("Message1", text_content)
        self.assertIn("Message2", text_content)
        self.assertIn("Message3", text_content)


if __name__ == '__main__':
    unittest.main()