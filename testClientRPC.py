"""
  coverage run --source=clientRPC testClientRPC.py
  coverage report -m
"""

import unittest
from unittest.mock import patch, MagicMock
import tkinter as tk
from tkinter import scrolledtext
import threading
import queue
import time
import sys
import socket
import json
import random
import string

import chat_pb2
import chat_pb2_grpc
import clientRPC as client  

class TestableChatClient(client.ChatClient):
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Chat Client (gRPC) - Testable")
        self.username = None
        self.stub = None
        self.channel = None
        self.active_bidi = None
        self.bidi_queue = None

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

    def destroy(self):
        try:
            self.root.destroy()
        except tk.TclError:
            pass

# FakeChannel and FakeStub for Integration Testing
class FakeChannel:
    def __init__(self):
        self.close = MagicMock()

class FakeStub:
    def __init__(self, payload_record):
        self.payload_record = payload_record  # dictionary to record sizes

    def Login(self, request, metadata=None):
        req_size = len(request.SerializeToString())
        self.payload_record.setdefault("login", {"request": 0, "response": 0})
        self.payload_record["login"]["request"] = req_size
        response = chat_pb2.Response(command="2", server_message="Welcome, " + request.username + "!")
        resp_size = len(response.SerializeToString())
        self.payload_record["login"]["response"] = resp_size
        return response

    def Register(self, request, metadata=None):
        req_size = len(request.SerializeToString())
        self.payload_record.setdefault("register", {"request": 0, "response": 0})
        self.payload_record["register"]["request"] = req_size
        response = chat_pb2.Response(command="1", server_message="Registration successful. You are now logged in!")
        resp_size = len(response.SerializeToString())
        self.payload_record["register"]["response"] = resp_size
        return response

    def SearchUsers(self, request, metadata=None):
        req_size = len(request.SerializeToString())
        self.payload_record.setdefault("search", {"request": 0, "response": 0})
        self.payload_record["search"]["request"] = req_size
        response = chat_pb2.SearchResponse(success=True, usernames=["userA", "userB"], server_message="User list retrieved.")
        resp_size = len(response.SerializeToString())
        self.payload_record["search"]["response"] = resp_size
        return response

    def SendMessage(self, request, metadata=None):
        req_size = len(request.SerializeToString())
        self.payload_record.setdefault("send_message", {"request": 0, "response": 0})
        self.payload_record["send_message"]["request"] = req_size
        response = chat_pb2.SendMessageResponse(success=True, server_message="")
        resp_size = len(response.SerializeToString())
        self.payload_record["send_message"]["response"] = resp_size
        return response

    def Logoff(self, request, metadata=None):
        req_size = len(request.SerializeToString())
        self.payload_record.setdefault("logoff", {"request": 0, "response": 0})
        self.payload_record["logoff"]["request"] = req_size
        response = chat_pb2.Response(command="logoff", server_message=f"{request.username} has been logged off.")
        resp_size = len(response.SerializeToString())
        self.payload_record["logoff"]["response"] = resp_size
        return response

    def CheckMessages(self, request_iterator, metadata=None):
        response = chat_pb2.CheckMessagesResponse(command="checkmessages", server_message="0 unread messages.")
        return iter([response])

    def DeleteLastMessage(self, request_iterator, metadata=None):
        for _ in request_iterator:
            pass
        response = chat_pb2.Response(command="delete", server_message="Your last unread message was deleted.")
        return iter([response])

    def DeactivateAccount(self, request_iterator, metadata=None):
        for _ in request_iterator:
            pass
        response = chat_pb2.Response(command="deactivate", server_message="Your account and sent messages are removed.")
        return iter([response])

    def ReceiveMessages(self, request):
        req_size = len(request.SerializeToString())
        self.payload_record.setdefault("receive", {"request": 0, "response": 0})
        self.payload_record["receive"]["request"] = req_size
        response = chat_pb2.ReceiveResponse(sender="server", message="Hello from server", timestamp="2025-02-25 20:57:41")
        resp_size = len(response.SerializeToString())
        self.payload_record["receive"]["response"] = resp_size
        return iter([response])

# Integration Testable Client using FakeStub
class TestableClientIntegration(TestableChatClient):
    def __init__(self, payload_record):
        self.fake_payload = payload_record
        super().__init__()
        self.channel = FakeChannel()
        self.stub = FakeStub(self.fake_payload)
    def login_thread(self, username, password):
        response = self.stub.Login(chat_pb2.LoginRequest(username=username, password=password))
        if "Welcome" in response.server_message:
            self.username = username
            self.root.after(0, self.show_chat_page)
            self.append_message("Welcome, " + username + "!", sent_by_me=False)
        else:
            self.root.after(0, lambda: self.login_error_label.config(text=response.server_message))
    def register_thread(self, username, password, confirm):
        response = self.stub.Register(chat_pb2.RegisterRequest(username=username, password=password, confirm_password=confirm))
        if "successful" in response.server_message.lower():
            self.username = username
            self.root.after(0, self.show_chat_page)
            self.append_message("Welcome, " + username + "!", sent_by_me=False)
        else:
            self.root.after(0, lambda: self.register_error_label.config(text=response.server_message))

# Unit Tests for Client UI and Other Methods
class TestClientGRPCUnit(unittest.TestCase):
    def setUp(self):
        self.client = TestableChatClient()

    def tearDown(self):
        self.client.destroy()

    def test_build_welcome_frame(self):
        self.assertGreater(len(self.client.welcome_frame.winfo_children()), 0)

    def test_show_welcome_page(self):
        self.client.welcome_frame.pack = MagicMock()
        self.client.login_frame.pack_forget = MagicMock()
        self.client.register_frame.pack_forget = MagicMock()
        self.client.chat_frame.pack_forget = MagicMock()
        self.client.show_welcome_page()
        self.client.welcome_frame.pack.assert_called_once()

    def test_append_message(self):
        self.client.chat_display.configure(state='normal')
        self.client.chat_display.delete("1.0", tk.END)
        self.client.append_message("Test message", sent_by_me=True)
        content = self.client.chat_display.get("1.0", tk.END)
        self.assertIn("Test message", content)

    def test_send_message(self):
        fake_payload = {}
        self.client.stub = FakeStub(fake_payload)
        self.client.message_entry.insert(0, "@user Hello!")
        self.client.send_message()
        self.assertIn("send_message", fake_payload)
        self.assertGreater(fake_payload["send_message"]["request"], 0)

    def test_on_close(self):
        fake_channel = FakeChannel()
        fake_channel.close = MagicMock()
        self.client.channel = fake_channel
        self.client.stub = FakeStub({})
        self.client.username = "dummy"
        self.client.on_close()
        fake_channel.close.assert_called()


# Integration Tests for the Client using FakeStub.
class TestClientGRPCIntegration(unittest.TestCase):
    # Record payload sizes from each integration test.
    data_sizes = {}

    def setUp(self):
        self.fake_payload = {}
        self.client = TestableClientIntegration(self.fake_payload)

    def tearDown(self):
        test_name = self.id().split('.')[-1]
        TestClientGRPCIntegration.data_sizes[test_name] = self.fake_payload.copy()
        self.client.destroy()

    def test_login_flow(self):
        self.client.login_thread("testuser", "Password123!")
        time.sleep(0.2)
        self.client.root.update()
        try:
            info = self.client.chat_frame.pack_info()
        except tk.TclError:
            info = None
        self.assertIsNotNone(info, "Chat frame not packed => login might have failed.")

    def test_register_flow(self):
        self.client.register_thread("newuser", "Password123!", "Password123!")
        time.sleep(0.2)
        self.client.root.update()
        try:
            info = self.client.chat_frame.pack_info()
        except tk.TclError:
            info = None
        self.assertIsNotNone(info, "Chat frame not packed => registration might have failed.")

    def test_receive_flow(self):
        self.client.username = "testuser"
        self.client.show_chat_page()
        self.client.receive_messages_stream()
        content = self.client.chat_display.get("1.0", tk.END)
        self.assertIn("Hello from server", content)

    @classmethod
    def tearDownClass(cls):
        if cls.data_sizes:
            print("\nFinal Integration Payload Sizes:", file=sys.__stdout__)
            for test_name, payload in cls.data_sizes.items():
                print(f"{test_name}: {payload}", file=sys.__stdout__)
            sys.__stdout__.flush()

# Regression Tests for Client Integration Payloads
class TestClientGRPCRegression(unittest.TestCase):
    """
    Baseline payload sizes (in bytes) based on previous runs to serve as compairson point for regression tests
    IDEA: By comparing current payload sizes against these baselines, we can detect unintended changes or regressions 
    in the client–server protocol or the message serialization --> tests will fail if the sizes deviate significantly
    """
    BASELINE_SIZES = {
        "test_login_flow": {"login": {"request": 24, "response": 23}},
        "test_register_flow": {"register": {"request": 37, "response": 52}},
        "test_receive_flow": {"receive": {"request": 10, "response": 48}},
    }
    VARIATION_PERCENT = 0.20

    @classmethod
    def setUpClass(cls):
        if not hasattr(TestClientGRPCIntegration, 'data_sizes') or not TestClientGRPCIntegration.data_sizes:
            raise unittest.SkipTest("Integration tests were skipped; skipping regression tests.")
        cls.current_sizes = TestClientGRPCIntegration.data_sizes

    def assertWithinVariation(self, baseline, current, label):
        allowed = baseline * self.VARIATION_PERCENT
        self.assertTrue(abs(baseline - current) <= allowed,
                        f"{label} size {current} deviates more than {self.VARIATION_PERCENT*100}% from baseline {baseline}")

    def test_payload_sizes(self):
        for test_name, baselines in self.BASELINE_SIZES.items():
            self.assertIn(test_name, self.current_sizes, f"Test '{test_name}' not found in integration payload sizes")
            current = self.current_sizes[test_name]
            for method, baseline_vals in baselines.items():
                self.assertIn(method, current, f"Method '{method}' not found in payload sizes for {test_name}")
                for part in ["request", "response"]:
                    self.assertWithinVariation(baseline_vals[part], current[method][part],
                                               f"{test_name} - {method} {part}")

if __name__ == '__main__':
    unittest.main()