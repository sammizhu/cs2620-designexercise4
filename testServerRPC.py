"""
  coverage run --source=serverRPC testServerRPC.py
  coverage report -m
"""

import unittest
import time
import grpc
import random
import string
import bcrypt
import traceback
import socket
import sys
from datetime import datetime
from unittest.mock import patch

import chat_pb2
import chat_pb2_grpc
import serverRPC

# Dummy database classes for unit testing
class DummyCursor:
    def __init__(self, responses):
        self.responses = responses
        self.index = 0

    def execute(self, query, params=None):
        self.last_query = query
        self.last_params = params

    def fetchone(self):
        if self.responses:
            return self.responses[0]
        return None

    def fetchall(self):
        return self.responses

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, tb):
        pass

class DummyConnection:
    def __init__(self, responses):
        self.responses = responses

    def cursor(self):
        return DummyCursor(self.responses)

    def commit(self):
        pass

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, tb):
        pass

class ExceptionConnection:
    """A dummy connection that always raises an exception on __enter__"""
    def __enter__(self):
        raise Exception("DB error")
    def __exit__(self, exc_type, exc_value, tb):
        pass

# Dummy datetime for streaming tests
class DummyDatetime:
    def strftime(self, fmt):
        return "2025-02-25 20:57:41"

# Dummy connection for CheckMessages streaming tests
class DummyConnectForCheck:
    def __init__(self):
        self.call_count = 0
    def cursor(self):
        self.call_count += 1
        if self.call_count == 1:
            # Unread count query.
            return DummyCursor([{'cnt': 2}])
        elif self.call_count == 2:
            # Sender count query
            return DummyCursor([{'sender': 'alice', 'num': 2}])
        elif self.call_count == 3:
            # Fetch messages for sender
            return DummyCursor([{'messageid': 1, 'sender': 'alice', 'message': 'Hello', 'datetime': DummyDatetime()}])
        else:
            return DummyCursor([])
    def commit(self):
        pass
    def __enter__(self):
        return self
    def __exit__(self, exc_type, exc_value, tb):
        pass

# UNIT TESTS: Helper Functions
class TestUnitHelpers(unittest.TestCase):
    def test_check_valid_password(self):
        self.assertFalse(serverRPC.checkValidPassword("shrt1!"))
        self.assertFalse(serverRPC.checkValidPassword("alllowercase1!"))
        self.assertFalse(serverRPC.checkValidPassword("ALLUPPERCASE!"))
        self.assertFalse(serverRPC.checkValidPassword("ValidPassword1"))
        self.assertTrue(serverRPC.checkValidPassword("Valid1!"))

    def test_hash_pass(self):
        password = "Valid1!"
        hashed = serverRPC.hashPass(password)
        self.assertTrue(bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8')))

    @patch('serverRPC.connectsql')
    def test_check_real_username_found(self, mock_connectsql):
        dummy_conn = DummyConnection([{'cnt': 1}])
        mock_connectsql.return_value = dummy_conn
        self.assertTrue(serverRPC.checkRealUsername("existing_user"))

    @patch('serverRPC.connectsql')
    def test_check_real_username_not_found(self, mock_connectsql):
        dummy_conn = DummyConnection([{'cnt': 0}])
        mock_connectsql.return_value = dummy_conn
        self.assertFalse(serverRPC.checkRealUsername("nonexistent_user"))

    @patch('serverRPC.connectsql')
    def test_check_real_password_success(self, mock_connectsql):
        password = "Valid1!"
        hashed = serverRPC.hashPass(password)
        dummy_conn = DummyConnection([{'password': hashed}])
        mock_connectsql.return_value = dummy_conn
        self.assertTrue(serverRPC.checkRealPassword("dummy", password))

    @patch('serverRPC.connectsql')
    def test_check_real_password_failure(self, mock_connectsql):
        password = "Valid1!"
        hashed = serverRPC.hashPass(password)
        dummy_conn = DummyConnection([{'password': hashed}])
        mock_connectsql.return_value = dummy_conn
        self.assertFalse(serverRPC.checkRealPassword("dummy", "WrongPass1!"))

# UNIT TESTS: ChatService Methods (using mocks)
class DummyContext:
    def __init__(self):
        self.metadata = {}
        self.cancelled = False
    def invocation_metadata(self):
        return []
    def cancel(self):
        self.cancelled = True

class TestUnitChatService(unittest.TestCase):
    def setUp(self):
        self.service = serverRPC.ChatService()
        self.ctx = DummyContext()

    @patch('serverRPC.connectsql')
    @patch('serverRPC.checkRealUsername')
    @patch('serverRPC.checkValidPassword')
    def test_register_missing_fields(self, mock_valid, mock_realuser, mock_connect):
        req = chat_pb2.RegisterRequest(username="", password="Valid1!", confirm_password="Valid1!")
        resp = self.service.Register(req, self.ctx)
        self.assertIn("All fields are required", resp.server_message)

    @patch('serverRPC.checkRealUsername', return_value=True)
    def test_register_username_taken(self, mock_realuser):
        req = chat_pb2.RegisterRequest(username="taken", password="Valid1!", confirm_password="Valid1!")
        resp = self.service.Register(req, self.ctx)
        self.assertIn("Username taken", resp.server_message)

    @patch('serverRPC.checkRealUsername', return_value=False)
    @patch('serverRPC.checkValidPassword', return_value=False)
    def test_register_invalid_password(self, mock_valid, mock_realuser):
        req = chat_pb2.RegisterRequest(username="newuser", password="invalid", confirm_password="invalid")
        resp = self.service.Register(req, self.ctx)
        self.assertIn("Invalid password", resp.server_message)

    @patch('serverRPC.checkRealUsername', return_value=False)
    @patch('serverRPC.checkValidPassword', return_value=True)
    def test_register_password_mismatch(self, mock_valid, mock_realuser):
        req = chat_pb2.RegisterRequest(username="newuser", password="Valid1!", confirm_password="Mismatch1!")
        resp = self.service.Register(req, self.ctx)
        self.assertIn("Passwords do not match", resp.server_message)

    @patch('serverRPC.connectsql', return_value=DummyConnection([]))
    @patch('serverRPC.checkRealUsername', return_value=False)
    @patch('serverRPC.checkValidPassword', return_value=True)
    def test_register_success(self, mock_valid, mock_realuser, mock_connect):
        req = chat_pb2.RegisterRequest(username="newuser", password="Valid1!", confirm_password="Valid1!")
        resp = self.service.Register(req, self.ctx)
        self.assertIn("Registration successful", resp.server_message)

    @patch('serverRPC.traceback.print_exc', lambda *args, **kwargs: None)
    @patch('serverRPC.connectsql', return_value=ExceptionConnection())
    @patch('serverRPC.checkRealUsername', return_value=False)
    @patch('serverRPC.checkValidPassword', return_value=True)
    def test_register_exception(self, mock_valid, mock_realuser, mock_connect):
        req = chat_pb2.RegisterRequest(username="newuser", password="Valid1!", confirm_password="Valid1!")
        resp = self.service.Register(req, self.ctx)
        self.assertIn("Server error during registration", resp.server_message)

    @patch('serverRPC.checkRealUsername', return_value=False)
    def test_login_user_not_found(self, mock_realuser):
        req = chat_pb2.LoginRequest(username="nouser", password="whatever")
        resp = self.service.Login(req, self.ctx)
        self.assertIn("User not found", resp.server_message)

    @patch('serverRPC.checkRealUsername', return_value=True)
    @patch('serverRPC.checkRealPassword', return_value=False)
    def test_login_wrong_password(self, mock_realpass, mock_realuser):
        req = chat_pb2.LoginRequest(username="dummy", password="wrongpass")
        resp = self.service.Login(req, self.ctx)
        self.assertIn("Incorrect password", resp.server_message)

    @patch('serverRPC.connectsql')
    @patch('serverRPC.checkRealUsername', return_value=True)
    @patch('serverRPC.checkRealPassword', return_value=True)
    def test_login_already_logged_in(self, mock_realpass, mock_realuser, mock_connect):
        dummy_conn = DummyConnection([{'active': 1}])
        mock_connect.return_value = dummy_conn
        req = chat_pb2.LoginRequest(username="dummy", password="Valid1!")
        resp = self.service.Login(req, self.ctx)
        self.assertIn("already logged in", resp.server_message.lower())

    @patch('serverRPC.connectsql')
    @patch('serverRPC.checkRealUsername', return_value=True)
    @patch('serverRPC.checkRealPassword', return_value=True)
    def test_login_success(self, mock_realpass, mock_realuser, mock_connect):
        dummy_conn = DummyConnection([{'active': 0}])
        mock_connect.return_value = dummy_conn
        req = chat_pb2.LoginRequest(username="dummy", password="Valid1!")
        resp = self.service.Login(req, self.ctx)
        self.assertIn("welcome, dummy", resp.server_message.lower())

    @patch('serverRPC.connectsql', return_value=ExceptionConnection())
    @patch('serverRPC.traceback.print_exc', lambda *args, **kwargs: None)
    def test_login_db_error(self, mock_connect):
        req = chat_pb2.LoginRequest(username="dummy", password="Valid1!")
        with self.assertRaises(Exception):
            _ = self.service.Login(req, self.ctx)

    @patch('serverRPC.checkRealUsername', return_value=False)
    def test_send_message_invalid_format(self, mock_realuser):
        req = chat_pb2.GeneralMessage(command="sendmessage", message="Hello without at-sign")
        resp = self.service.SendMessage(req, self.ctx)
        self.assertIn("use '@username message'", resp.server_message)

    @patch('serverRPC.checkRealUsername', return_value=False)
    def test_send_message_unknown_recipient(self, mock_realuser):
        req = chat_pb2.GeneralMessage(command="sendmessage", message="@unknown Hi there")
        resp = self.service.SendMessage(req, self.ctx)
        self.assertIn("Recipient does not exist", resp.server_message)

    @patch('serverRPC.connectsql')
    @patch('serverRPC.checkRealUsername', return_value=True)
    def test_send_message_success(self, mock_realuser, mock_connect):
        dummy_conn = DummyConnection([])
        mock_connect.return_value = dummy_conn
        req = chat_pb2.GeneralMessage(command="sendmessage", message="@recipient Hi!")
        self.ctx.invocation_metadata = lambda: [("username", "sender")]
        resp = self.service.SendMessage(req, self.ctx)
        self.assertTrue(resp.success)

    @patch('serverRPC.connectsql', return_value=ExceptionConnection())
    @patch('serverRPC.traceback.print_exc', lambda *args, **kwargs: None)
    @patch('serverRPC.checkRealUsername', return_value=True)
    def test_send_message_exception(self, mock_realuser, mock_connect):
        req = chat_pb2.GeneralMessage(command="sendmessage", message="@recipient Hi!")
        self.ctx.invocation_metadata = lambda: [("username", "sender")]
        resp = self.service.SendMessage(req, self.ctx)
        self.assertIn("Error storing message", resp.server_message)

    @patch('serverRPC.connectsql')
    def test_logoff_empty_username(self, mock_connect):
        req = chat_pb2.LogoffRequest(username="")
        resp = self.service.Logoff(req, self.ctx)
        self.assertIn("No username provided", resp.server_message)

    @patch('serverRPC.connectsql')
    def test_logoff_success(self, mock_connect):
        dummy_conn = DummyConnection([])
        mock_connect.return_value = dummy_conn
        req = chat_pb2.LogoffRequest(username="dummy")
        resp = self.service.Logoff(req, self.ctx)
        self.assertIn("logged off", resp.server_message.lower())

    @patch('serverRPC.connectsql', return_value=ExceptionConnection())
    @patch('serverRPC.traceback.print_exc', lambda *args, **kwargs: None)
    def test_logoff_exception(self, mock_connect):
        req = chat_pb2.LogoffRequest(username="dummy")
        resp = self.service.Logoff(req, self.ctx)
        self.assertIn("Logoff error", resp.server_message)

    @patch('serverRPC.connectsql')
    def test_search_users_success(self, mock_connect):
        dummy_conn = DummyConnection([{'username': 'user1'}, {'username': 'user2'}, {'username': 'dummy'}])
        mock_connect.return_value = dummy_conn
        req = chat_pb2.SearchRequest(username="dummy")
        resp = self.service.SearchUsers(req, self.ctx)
        self.assertTrue(resp.success)
        self.assertIn("user list retrieved", resp.server_message.lower())
        self.assertNotIn("dummy", resp.usernames)

    @patch('serverRPC.connectsql', return_value=ExceptionConnection())
    @patch('serverRPC.traceback.print_exc', lambda *args, **kwargs: None)
    def test_search_users_exception(self, mock_connect):
        req = chat_pb2.SearchRequest(username="dummy")
        resp = self.service.SearchUsers(req, self.ctx)
        self.assertIn("Error searching users", resp.server_message)

    @patch('serverRPC.connectsql')
    def test_delete_last_message_no_username(self, mock_connect):
        def gen():
            yield chat_pb2.DeleteRequest(username="", confirmation="")
        responses = list(self.service.DeleteLastMessage(gen(), self.ctx))
        self.assertTrue(any("No username provided" in resp.server_message for resp in responses))

    @patch('serverRPC.connectsql')
    def test_deactivate_account_cancel(self, mock_connect):
        def gen():
            yield chat_pb2.DeactivateRequest(username="dummy", confirmation="")
            yield chat_pb2.DeactivateRequest(username="dummy", confirmation="no")
        responses = list(self.service.DeactivateAccount(gen(), self.ctx))
        self.assertTrue(any("deactivation canceled" in resp.server_message.lower() for resp in responses))
    
    @patch('serverRPC.connectsql')
    def test_deactivate_account_success(self, mock_connect):
        dummy_conn = DummyConnection([])
        mock_connect.return_value = dummy_conn
        def gen():
            yield chat_pb2.DeactivateRequest(username="dummy", confirmation="")
            yield chat_pb2.DeactivateRequest(username="dummy", confirmation="yes")
        responses = list(self.service.DeactivateAccount(gen(), self.ctx))
        self.assertTrue(any("removed" in resp.server_message.lower() for resp in responses))
    
    @patch('serverRPC.connectsql', return_value=ExceptionConnection())
    @patch('serverRPC.traceback.print_exc', lambda *args, **kwargs: None)
    def test_deactivate_account_exception(self, mock_connect):
        def gen():
            yield chat_pb2.DeactivateRequest(username="dummy", confirmation="")
            yield chat_pb2.DeactivateRequest(username="dummy", confirmation="yes")
        responses = list(self.service.DeactivateAccount(gen(), self.ctx))
        self.assertTrue(any("Error:" in resp.server_message for resp in responses))

# UNIT TESTS: Streaming Methods for CheckMessages and ReceiveMessages
class DummyStreamingContext:
    def __init__(self):
        self._active = True
        self.calls = 0
    def is_active(self):
        self.calls += 1
        if self.calls > 1:
            self._active = False
        return self._active

class TestUnitCheckMessages(unittest.TestCase):
    def setUp(self):
        self.service = serverRPC.ChatService()
        self.ctx = DummyContext()

    @patch('serverRPC.connectsql', return_value=DummyConnection([{'cnt': 0}]))
    def test_check_messages_no_unread(self, mock_connect):
        def gen():
            yield chat_pb2.CheckMessagesRequest(username="dummy")
        responses = list(self.service.CheckMessages(gen(), self.ctx))
        self.assertTrue(any("0 unread messages" in resp.server_message for resp in responses))

    @patch('serverRPC.connectsql', return_value=DummyConnectForCheck())
    def test_check_messages_full_flow(self, mock_connect):
        def gen():
            yield chat_pb2.CheckMessagesRequest(username="dummy")
            yield chat_pb2.CheckMessagesRequest(username="dummy", choice="1")
            yield chat_pb2.CheckMessagesRequest(username="dummy", sender="alice")
        responses = list(self.service.CheckMessages(gen(), self.ctx))
        self.assertTrue(any("alice: Hello" in resp.server_message for resp in responses))
    
    @patch('serverRPC.connectsql', return_value=DummyConnectForCheck())
    def test_check_messages_invalid_choice(self, mock_connect):
        def gen():
            yield chat_pb2.CheckMessagesRequest(username="dummy")
            yield chat_pb2.CheckMessagesRequest(username="dummy", choice="invalid")
        responses = list(self.service.CheckMessages(gen(), self.ctx))
        self.assertTrue(any("Invalid choice" in resp.server_message for resp in responses))
    
    @patch('serverRPC.connectsql', return_value=DummyConnectForCheck())
    def test_check_messages_no_sender(self, mock_connect):
        def gen():
            yield chat_pb2.CheckMessagesRequest(username="dummy")
            yield chat_pb2.CheckMessagesRequest(username="dummy", choice="1")
            yield chat_pb2.CheckMessagesRequest(username="dummy", sender="   ")
        responses = list(self.service.CheckMessages(gen(), self.ctx))
        self.assertTrue(any("No sender provided" in resp.server_message for resp in responses))

class TestUnitReceiveMessages(unittest.TestCase):
    @patch('serverRPC.connectsql')
    def test_receive_messages_no_messages(self, mock_connect):
        dummy_conn = DummyConnection([])
        mock_connect.return_value = dummy_conn
        req = chat_pb2.ReceiveRequest(username="dummy")
        ctx = DummyStreamingContext()
        responses = list(serverRPC.ChatService().ReceiveMessages(req, ctx))
        self.assertEqual(len(responses), 0)
    
    @patch('serverRPC.connectsql')
    def test_receive_messages_with_message(self, mock_connect):
        dummy_msg = {'messageid': 1, 'sender': 'dummy', 'message': 'Hello', 'datetime': DummyDatetime()}
        class CustomDummyConnection(DummyConnection):
            def __init__(self):
                self.call_count = 0
            def cursor(self):
                self.call_count += 1
                if self.call_count == 1:
                    return DummyCursor([dummy_msg])
                else:
                    return DummyCursor([])
        mock_connect.return_value = CustomDummyConnection()
        req = chat_pb2.ReceiveRequest(username="dummy")
        ctx = DummyStreamingContext()
        responses = list(serverRPC.ChatService().ReceiveMessages(req, ctx))
        self.assertGreaterEqual(len(responses), 1)
        self.assertEqual(responses[0].sender, "dummy")
        self.assertEqual(responses[0].message, "Hello")
        self.assertEqual(responses[0].timestamp, "2025-02-25 20:57:41")


# Integration Tests for Full Chat Service Flow
def get_message_size(message):
    return len(message.SerializeToString())

def is_server_available(host, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(1)
    try:
        s.connect((host, port))
        return True
    except Exception:
        return False
    finally:
        s.close()

class TestIntegrationFlow(unittest.TestCase):
    HOST = '10.250.213.39' # Can also replace with arg1 value from command line
    PORT = 65432

    @classmethod
    def setUpClass(cls):
        if not is_server_available(cls.HOST, cls.PORT):
            raise unittest.SkipTest("gRPC server not available at {}:{}".format(cls.HOST, cls.PORT))
        random_suffix = ''.join(random.choices(string.ascii_lowercase + string.digits, k=6))
        cls.username = f"testuser_{random_suffix}"
        cls.password = "Valid1!"
        cls.channel = grpc.insecure_channel(f"{cls.HOST}:{cls.PORT}")
        cls.stub = chat_pb2_grpc.ChatStub(cls.channel)
        cls.data_sizes = {}

    @classmethod
    def tearDownClass(cls):
        try:
            logoff_req = chat_pb2.LogoffRequest(username=cls.username)
            cls.stub.Logoff(logoff_req, metadata=(('username', cls.username),))
        except Exception:
            pass
        # Print final payload sizes to original stdout
        print("\nFinal Integration Payload Sizes:", file=sys.__stdout__)
        for step, sizes in cls.data_sizes.items():
            print(f"{step}: request = {sizes['request']} bytes, response = {sizes['response']} bytes", file=sys.__stdout__)
        sys.__stdout__.flush()
        cls.channel.close()

    def test_full_flow(self):
        # 1. REGISTER
        register_req = chat_pb2.RegisterRequest(
            username=self.username,
            password=self.password,
            confirm_password=self.password
        )
        reg_req_size = get_message_size(register_req)
        reg_resp = self.stub.Register(register_req)
        reg_resp_size = len(reg_resp.SerializeToString())
        self.__class__.data_sizes["register"] = {"request": reg_req_size, "response": reg_resp_size}
        self.assertIn("successful", reg_resp.server_message.lower(), "Registration failed")
        
        # 2. SEARCH USERS
        search_req = chat_pb2.SearchRequest(username=self.username)
        search_req_size = get_message_size(search_req)
        search_resp = self.stub.SearchUsers(search_req, metadata=(('username', self.username),))
        search_resp_size = len(search_resp.SerializeToString())
        self.__class__.data_sizes["search"] = {"request": search_req_size, "response": search_resp_size}
        self.assertTrue(search_resp.success, "Search users failed")
        self.assertNotIn(self.username, search_resp.usernames,
                         "Search results should not include the test user's own username")
        
        # 3. SEND CHAT MESSAGE (self-directed)
        message_text = f"@{self.username} Hello, integration test message."
        send_req = chat_pb2.GeneralMessage(command="sendmessage", message=message_text)
        send_req_size = get_message_size(send_req)
        send_resp = self.stub.SendMessage(send_req, metadata=(('username', self.username),))
        send_resp_size = len(send_resp.SerializeToString())
        self.__class__.data_sizes["send_message"] = {"request": send_req_size, "response": send_resp_size}
        self.assertTrue(send_resp.success, "Sending chat message failed")
        
        # 4. DELETE LAST MESSAGE (bidirectional streaming)
        delete_req_sizes = []
        delete_resp_sizes = []
        delete_msgs = []
        def delete_generator():
            req1 = chat_pb2.DeleteRequest(username=self.username, confirmation="")
            delete_req_sizes.append(get_message_size(req1))
            yield req1
            time.sleep(0.1)
            req2 = chat_pb2.DeleteRequest(username=self.username, confirmation="yes")
            delete_req_sizes.append(get_message_size(req2))
            yield req2

        for resp in self.stub.DeleteLastMessage(delete_generator(), metadata=(('username', self.username),)):
            delete_resp_sizes.append(len(resp.SerializeToString()))
            delete_msgs.append(resp.server_message)
        self.__class__.data_sizes["delete"] = {"request": sum(delete_req_sizes), "response": sum(delete_resp_sizes)}
        self.assertTrue(any("deleted" in msg.lower() for msg in delete_msgs),
                        "Delete last message did not confirm deletion")
        
        # 5. CHECK MESSAGES (bidirectional streaming)
        check_req_sizes = []
        check_resp_sizes = []
        check_msgs = []
        def check_generator():
            req1 = chat_pb2.CheckMessagesRequest(username=self.username)
            check_req_sizes.append(get_message_size(req1))
            yield req1
            time.sleep(0.1)
            req2 = chat_pb2.CheckMessagesRequest(username=self.username, choice="2")
            check_req_sizes.append(get_message_size(req2))
            yield req2

        for resp in self.stub.CheckMessages(check_generator(), metadata=(('username', self.username),)):
            check_resp_sizes.append(len(resp.SerializeToString()))
            check_msgs.append(resp.server_message)
        self.__class__.data_sizes["check"] = {"request": sum(check_req_sizes), "response": sum(check_resp_sizes)}
        self.assertTrue(any("0 unread messages" in resp.server_message.lower() for resp in list(self.stub.CheckMessages(check_generator(), metadata=(('username', self.username),)))),
                        "Check messages did not report 0 unread messages")
        
        # 6. LOGOFF
        logoff_req = chat_pb2.LogoffRequest(username=self.username)
        logoff_req_size = get_message_size(logoff_req)
        logoff_resp = self.stub.Logoff(logoff_req, metadata=(('username', self.username),))
        logoff_resp_size = len(logoff_resp.SerializeToString())
        self.__class__.data_sizes["logoff"] = {"request": logoff_req_size, "response": logoff_resp_size}
        self.assertIn("logged off", logoff_resp.server_message.lower(), "Logoff failed")

# Regression Tests
class TestRegressionFlow(unittest.TestCase):
    """
    Baseline payload sizes (in bytes) based on previous runs to serve as compairson point for regression tests
    IDEA: By comparing current payload sizes against these baselines, we can detect unintended changes or regressions 
    in the client–server protocol or the message serialization --> tests will fail if the sizes deviate significantly
    """
    BASELINE_SIZES = {
        "register": {"request": 35, "response": 52},
        "search": {"request": 17, "response": 154},
        "send_message": {"request": 64, "response": 2},
        "delete": {"request": 39, "response": 180},
        "check": {"request": 17, "response": 193},
        "logoff": {"request": 17, "response": 46},
    }
    VARIATION_PERCENT = 0.20

    @classmethod
    def setUpClass(cls):
        # Only re-run the integration tests if data_sizes is empty
        if not hasattr(TestIntegrationFlow, 'data_sizes') or not TestIntegrationFlow.data_sizes:
            integration_suite = unittest.TestLoader().loadTestsFromTestCase(TestIntegrationFlow)
            result = unittest.TestResult()
            integration_suite.run(result)
        cls.current_sizes = TestIntegrationFlow.data_sizes

    def assertWithinVariation(self, baseline, current, label):
        allowed_variation = baseline * self.VARIATION_PERCENT
        self.assertTrue(abs(baseline - current) <= allowed_variation,
                        f"{label} size {current} deviates more than {self.VARIATION_PERCENT*100}% from baseline {baseline}")

    def test_payload_sizes(self):
        for step, baseline in self.BASELINE_SIZES.items():
            self.assertIn(step, self.current_sizes, f"Step '{step}' not found in current payload sizes")
            current = self.current_sizes[step]
            with self.subTest(step=step, message="Request size"):
                self.assertWithinVariation(baseline["request"], current["request"], f"{step} request")
            with self.subTest(step=step, message="Response size"):
                self.assertWithinVariation(baseline["response"], current["response"], f"{step} response")

if __name__ == '__main__':
    runner = unittest.TextTestRunner(stream=sys.__stdout__, verbosity=2)
    unittest.main(testRunner=runner)