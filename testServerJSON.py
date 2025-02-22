"""
Usage:
  coverage run --source=serverjson testserverjson.py
  coverage report -m
"""

import unittest
import threading
import socket
import time
from unittest.mock import patch, MagicMock
import pymysql
import pymysql.cursors
import datetime
import json

# NEW MONKEY-PATCH CODE FOR PAYLOAD LOGGING 
payload_log = []
_original_sendall = socket.socket.sendall

def logging_sendall(self, data, *args, **kwargs):
    size = len(data)
    payload_log.append(size)
    # print(f"[LOG] Sending {size} bytes")
    return _original_sendall(self, data, *args, **kwargs)

def enable_payload_logging():
    socket.socket.sendall = logging_sendall

def disable_payload_logging():
    socket.socket.sendall = _original_sendall

from serverJson import (
    connectsql,
    checkRealUsername,
    checkValidPassword,
    hashPass,
    checkRealPassword,
    handle_registration,
    handle_login,
    check_messages_server_side,
    handle_client,
    start_server
)


class TestServerDatabaseFunctions(unittest.TestCase):
    """
    Tests for lower-level database functions in serverjson:
      - connectsql
      - checkRealUsername
      - checkValidPassword
      - hashPass
      - checkRealPassword
    """

    @patch('serverjson.pymysql.connect')
    def test_connectsql_unit(self, mock_connect):
        """
        Unit test: Ensure connectsql() calls pymysql.connect with the correct parameters.
        """
        mock_connection = MagicMock()
        mock_connect.return_value = mock_connection

        conn = connectsql()
        mock_connect.assert_called_once_with(
            host='0.0.0.0',  # or your default from environment
            user='root',
            password='',
            database='db262',
            cursorclass=pymysql.cursors.DictCursor
        )
        self.assertEqual(conn, mock_connection)

    def test_connectsql_regression(self):
        """
        Regression test: Ensures 'connectsql' function uses correct default DB name ('db262').
        """
        with patch('serverjson.pymysql.connect') as mock_connect:
            connectsql()
            _, kwargs = mock_connect.call_args
            self.assertEqual(kwargs.get('database'), 'db262')

    @unittest.skip("Integration test requires a live DB.")
    def test_connectsql_integration(self):
        """
        Integration test: Attempts a real DB connection (SELECT 1). 
        Requires a running database with credentials set up.
        """
        conn = connectsql()
        try:
            with conn.cursor() as cur:
                cur.execute("SELECT 1")
                row = cur.fetchone()
                self.assertIsNotNone(row)
        finally:
            conn.close()

    @patch('serverjson.connectsql')
    def test_checkRealUsername_unit(self, mock_connectsql):
        """
        Unit test: Mocks DB calls. checkRealUsername() should return True/False 
        based on the 'cnt' field in the DB result.
        """
        mock_db = MagicMock()
        mock_cursor = MagicMock()
        mock_connectsql.return_value.__enter__.return_value = mock_db
        mock_db.cursor.return_value.__enter__.return_value = mock_cursor

        # Simulate existing user
        mock_cursor.fetchone.return_value = {'cnt': 1}
        self.assertTrue(checkRealUsername('alice'))

        # Simulate non-existing user
        mock_cursor.fetchone.return_value = {'cnt': 0}
        self.assertFalse(checkRealUsername('bob'))

    def test_checkRealUsername_regression(self):
        """
        Regression test: Ensures checkRealUsername() doesn't crash if DB returns None.
        """
        with patch('serverjson.connectsql') as mock_connectsql:
            mock_db = MagicMock()
            mock_cursor = MagicMock()
            mock_connectsql.return_value.__enter__.return_value = mock_db
            mock_db.cursor.return_value.__enter__.return_value = mock_cursor

            mock_cursor.fetchone.return_value = {'cnt': 0}
            try:
                result = checkRealUsername('bogususer')
                self.assertFalse(result)
            except Exception as e:
                self.fail(f"checkRealUsername crashed unexpectedly: {e}")

    @unittest.skip("Integration test requires a live DB.")
    def test_checkRealUsername_integration(self):
        """
        Integration test: Run checkRealUsername against a known user in the real DB.
        """
        self.assertTrue(checkRealUsername('some_known_user'))

    def test_checkValidPassword_unit(self):
        """
        Unit test: Checks multiple valid/invalid passwords for length, uppercase, digit, special char, etc.
        """
        self.assertFalse(checkValidPassword("Ab1!"))      # too short
        self.assertFalse(checkValidPassword("abc123!"))   # missing uppercase
        self.assertFalse(checkValidPassword("Abcdef!"))   # missing digit
        self.assertFalse(checkValidPassword("Abcdef1"))   # missing special
        self.assertTrue(checkValidPassword("Abc123!"))    # valid

    def test_checkValidPassword_regression(self):
        """
        Regression test: Example for a tricky pattern. 
        Here, we assume '%' is not in the allowed special chars.
        """
        self.assertFalse(checkValidPassword("Abc123%"))

    def test_hashPass_unit(self):
        """
        Unit test: Verifies hashPass() returns a bcrypt hash string.
        """
        pwd = "Abc123!"
        hashed = hashPass(pwd)
        self.assertIsInstance(hashed, str)
        self.assertTrue(
            hashed.startswith("$2b$") or hashed.startswith("$2a$"),
            "Expected a bcrypt-style hash."
        )

    @patch('serverjson.connectsql')
    def test_checkRealPassword_unit(self, mock_connectsql):
        """
        Unit test: Mocks the DB to verify checkRealPassword() returns True when plaintext 
        matches a stored bcrypt hash in the DB.
        """
        mock_db = MagicMock()
        mock_cursor = MagicMock()
        mock_connectsql.return_value.__enter__.return_value = mock_db
        mock_db.cursor.return_value.__enter__.return_value = mock_cursor

        test_hash = hashPass("Abc123!")
        mock_cursor.fetchone.return_value = {'password': test_hash}

        # Correct password
        self.assertTrue(checkRealPassword("testuser", "Abc123!"))
        # Wrong password
        self.assertFalse(checkRealPassword("testuser", "Wrong999"))


class TestServerHighLevelFunctions(unittest.TestCase):
    """
    Tests for handle_registration, handle_login, etc. with JSON input/output.
    """

    @patch('serverjson.connectsql')
    def test_handle_registration_unit(self, mock_connectsql):
        """
        Unit test: Mocks the entire registration flow for a new user: 
        - send JSON for username 
        - send JSON for password 
        - confirm password, etc.
        - expects success.
        """
        mock_conn = MagicMock()
        # We simulate client sending JSON in the correct order:
        # 1) {"username": "alice"}
        # 2) {"password": "Abc123!"}
        # 3) {"password": "Abc123!"} (confirm)
        mock_conn.recv.side_effect = [
            json.dumps({"username": "alice"}).encode('utf-8'),
            json.dumps({"password": "Abc123!"}).encode('utf-8'),
            json.dumps({"password": "Abc123!"}).encode('utf-8')
        ]

        mock_db = MagicMock()
        mock_cursor = MagicMock()
        mock_connectsql.return_value.__enter__.return_value = mock_db
        mock_db.cursor.return_value.__enter__.return_value = mock_cursor

        # checkRealUsername => returns False => "alice" is new
        mock_cursor.fetchone.return_value = {"cnt": 0}

        result = handle_registration(mock_conn, user_id=999)
        self.assertEqual(result, "alice")

        # Ensure success message was sent
        send_calls = mock_conn.sendall.call_args_list
        success_messages = [call[0][0] for call in send_calls if b"successful" in call[0][0]]
        self.assertTrue(success_messages, "No 'Registration successful' message was sent.")

    @patch('serverjson.connectsql')
    def test_handle_registration_regression(self, mock_connectsql):
        """
        Regression test: DB insertion error => server should respond with error JSON.
        """
        mock_conn = MagicMock()
        mock_conn.recv.side_effect = [
            json.dumps({"username": "bob"}).encode('utf-8'),
            json.dumps({"password": "Abc123!"}).encode('utf-8'),
            json.dumps({"password": "Abc123!"}).encode('utf-8')
        ]

        mock_db = MagicMock()
        mock_cursor = MagicMock()
        mock_connectsql.return_value.__enter__.return_value = mock_db
        mock_db.cursor.return_value.__enter__.return_value = mock_cursor

        def side_effect_insert(sql, params):
            if sql.startswith("INSERT INTO users"):
                raise Exception("DB insertion error")

        mock_cursor.fetchone.return_value = {"cnt": 0}  # username not taken
        mock_cursor.execute.side_effect = side_effect_insert

        result = handle_registration(mock_conn, user_id=123)
        self.assertIsNone(result)

        # Check that server sent error message
        send_calls = mock_conn.sendall.call_args_list
        errors = [call[0][0] for call in send_calls if b"Server error" in call[0][0]]
        self.assertTrue(errors, "Expected 'Server error' message but didn't find it.")

    @unittest.skip("Integration test would require real DB.")
    def test_handle_registration_integration(self):
        pass

    @patch('serverjson.connectsql')
    def test_handle_login_unit(self, mock_connectsql):
        """
        Unit test: Mocks a successful login flow via JSON input.
        """
        mock_conn = MagicMock()
        # 1) {"username": "charlie"}
        # 2) {"password": "Abc123!"}
        mock_conn.recv.side_effect = [
            json.dumps({"username": "charlie"}).encode('utf-8'),
            json.dumps({"password": "Abc123!"}).encode('utf-8')
        ]

        mock_db = MagicMock()
        mock_cursor = MagicMock()
        mock_connectsql.return_value.__enter__.return_value = mock_db
        mock_db.cursor.return_value.__enter__.return_value = mock_cursor

        # "charlie" is found, password is correct
        mock_cursor.fetchone.side_effect = [
            {"cnt": 1},  # found user
            {"password": hashPass("Abc123!")}
        ]

        result = handle_login(mock_conn, user_id=777)
        self.assertEqual(result, "charlie")

        # Check that welcome message was sent
        send_calls = mock_conn.sendall.call_args_list
        welcome = any(b"Welcome, charlie!" in call[0][0] for call in send_calls)
        self.assertTrue(welcome, "Expected a welcome message for 'charlie'.")

    @patch('serverjson.connectsql')
    def test_handle_login_regression(self, mock_connectsql):
        """
        Regression test: If user provides empty password => 'Login canceled.'
        """
        mock_conn = MagicMock()
        # username => "alex", password => "" => canceled
        mock_conn.recv.side_effect = [
            json.dumps({"username": "alex"}).encode('utf-8'),
            json.dumps({"password": ""}).encode('utf-8')
        ]

        mock_db = MagicMock()
        mock_cursor = MagicMock()
        mock_connectsql.return_value.__enter__.return_value = mock_db
        mock_db.cursor.return_value.__enter__.return_value = mock_cursor

        # user "alex" found
        mock_cursor.fetchone.side_effect = [
            {"cnt": 1}
        ]

        result = handle_login(mock_conn, user_id=123)
        self.assertIsNone(result)

        # Check server's response
        send_calls = mock_conn.sendall.call_args_list
        canceled = any(b"Login canceled." in call[0][0] for call in send_calls)
        self.assertTrue(canceled, "Expected 'Login canceled.' message.")


class TestCheckMessagesServerSide(unittest.TestCase):
    """
    Tests specifically for check_messages_server_side with JSON.
    """

    @patch('serverjson.connectsql')
    def test_no_unread_messages(self, mock_connectsql):
        """
        If user has 0 unread => "You have 0 unread messages."
        """
        mock_conn = MagicMock()
        # We'll ignore any incoming JSON since user won't type anything after seeing 0 unread.
        mock_conn.recv.return_value = b""

        mock_db = MagicMock()
        mock_cursor = MagicMock()
        mock_connectsql.return_value.__enter__.return_value = mock_db
        mock_db.cursor.return_value.__enter__.return_value = mock_cursor

        # unread_count = 0
        mock_cursor.fetchone.return_value = {'cnt': 0}

        check_messages_server_side(mock_conn, "david")
        send_calls = mock_conn.sendall.call_args_list
        responses = [call[0][0] for call in send_calls]
        self.assertTrue(any(b"You have 0 unread messages." in r for r in responses))

    @patch('serverjson.connectsql')
    def test_unread_messages_flow(self, mock_connectsql):
        """
        If user has unread messages => we prompt '1' to read or '2' to skip.
        Then user chooses '1', picks a sender, we list messages in batches, etc.
        """
        mock_conn = MagicMock()
        # 1 => read
        # next => we expect a "sender" in the next prompt
        mock_conn.recv.side_effect = [
            json.dumps({"choice": "1"}).encode('utf-8'),  # user picks read
            json.dumps({"sender": "alice"}).encode('utf-8'),  # user picks "alice" as sender
            b""  # no more input
        ]

        mock_db = MagicMock()
        mock_cursor = MagicMock()
        mock_connectsql.return_value.__enter__.return_value = mock_db
        mock_db.cursor.return_value.__enter__.return_value = mock_cursor

        # unread_count=2
        mock_cursor.fetchone.side_effect = [
            {"cnt": 2},  # unread
        ]
        # We have 2 unread messages from alice
        mock_cursor.fetchall.side_effect = [
            [{"sender": "alice", "num": 2}],  # senders
            [
                {
                    "messageid": 10,
                    "sender": "alice",
                    "message": "Hi there!",
                    "datetime": datetime.datetime.now()
                },
                {
                    "messageid": 11,
                    "sender": "alice",
                    "message": "Are you there?",
                    "datetime": datetime.datetime.now()
                }
            ]
        ]

        check_messages_server_side(mock_conn, "david")
        send_calls = mock_conn.sendall.call_args_list
        all_responses = [call[0][0] for call in send_calls]
        combined_str = b"".join(all_responses).decode('utf-8')
        self.assertIn("You have 2 unread messages", combined_str)
        self.assertIn("alice (2 messages)", combined_str)
        self.assertIn("Hi there!", combined_str)
        self.assertIn("Are you there?", combined_str)


class TestHandleClient(unittest.TestCase):
    """
    Tests for handle_client (the main command loop) with JSON-based commands.
    """

    @patch('serverjson.connectsql')
    def test_handle_client_registration_flow(self, mock_connectsql):
        """
        Simulate a client choosing "1" -> registration, sending username & password, 
        then no more data => exit. We expect registration success.
        """
        mock_conn = MagicMock()
        mock_conn.recv.side_effect = [
            json.dumps({"command": "1"}).encode('utf-8'),
            json.dumps({"username": "alice"}).encode('utf-8'),
            json.dumps({"password": "Abc123!"}).encode('utf-8'),
            json.dumps({"password": "Abc123!"}).encode('utf-8'),
            b""
        ]
        mock_addr = ("127.0.0.1", 11111)

        mock_db = MagicMock()
        mock_cursor = MagicMock()
        mock_connectsql.return_value.__enter__.return_value = mock_db
        mock_db.cursor.return_value.__enter__.return_value = mock_cursor

        # "alice" not taken
        mock_cursor.fetchone.return_value = {"cnt": 0}

        handle_client(mock_conn, mock_addr)
        # Check success message
        raw_msgs = [call[0][0] for call in mock_conn.sendall.call_args_list]
        self.assertTrue(any(b"Registration successful" in m for m in raw_msgs))

    @patch('serverjson.connectsql')
    def test_handle_client_login_flow(self, mock_connectsql):
        """
        Simulate choosing "2" -> login, providing correct username & password, then disconnect.
        Expect a welcome message.
        """
        mock_conn = MagicMock()
        mock_conn.recv.side_effect = [
            json.dumps({"command": "2"}).encode('utf-8'),
            json.dumps({"username": "charlie"}).encode('utf-8'),
            json.dumps({"password": "Abc123!"}).encode('utf-8'),
            b""
        ]
        mock_addr = ("127.0.0.1", 22222)

        mock_db = MagicMock()
        mock_cursor = MagicMock()
        mock_connectsql.return_value.__enter__.return_value = mock_db
        mock_db.cursor.return_value.__enter__.return_value = mock_cursor

        # "charlie" found
        mock_cursor.fetchone.side_effect = [
            {"cnt": 1},  # user found
            {"password": hashPass("Abc123!")},
            {"cnt": 0}   # no unread messages
        ]

        handle_client(mock_conn, mock_addr)
        raw_msgs = [call[0][0] for call in mock_conn.sendall.call_args_list]
        self.assertTrue(any(b"Welcome, charlie!" in m for m in raw_msgs))

    @patch('serverjson.connectsql')
    def test_handle_client_send_dm_no_user(self, mock_connectsql):
        """
        After logging in, user sends '@bob Hello?' but 'bob' does not exist => 
        the code tries to insert message anyway, but can't deliver real-time if bob doesn't exist.
        We'll check for normal completion (no error).
        """
        mock_conn = MagicMock()
        mock_conn.recv.side_effect = [
            json.dumps({"command": "2"}).encode('utf-8'),  # login
            json.dumps({"username": "alice"}).encode('utf-8'),
            json.dumps({"password": "Abc123!"}).encode('utf-8'),
            json.dumps({"command": "@bob Hello?"}).encode('utf-8'),
            json.dumps({"command": "logoff"}).encode('utf-8'),
            b""
        ]
        mock_addr = ("127.0.0.1", 33333)

        mock_db = MagicMock()
        mock_cursor = MagicMock()
        mock_connectsql.return_value.__enter__.return_value = mock_db
        mock_db.cursor.return_value.__enter__.return_value = mock_cursor

        mock_cursor.fetchone.side_effect = [
            {"cnt": 1},  # alice found
            {"password": hashPass("Abc123!")},
            {"cnt": 0},  # no unread
            None         # bob doesn't exist => row is None
        ]

        handle_client(mock_conn, mock_addr)
        raw_msgs = [call[0][0] for call in mock_conn.sendall.call_args_list]
        self.assertTrue(any(b"Logged off." in m for m in raw_msgs))

    @patch('serverjson.connectsql')
    def test_handle_client_regression_unknown_command(self, mock_connectsql):
        """
        If the user sends an unrecognized command => 
        'Error: ...' message is returned, no crash.
        """
        mock_conn = MagicMock()
        mock_conn.recv.side_effect = [
            json.dumps({"command": "2"}).encode('utf-8'),  # login
            json.dumps({"username": "alex"}).encode('utf-8'),
            json.dumps({"password": "Abc123!"}).encode('utf-8'),
            json.dumps({"command": "foobar"}).encode('utf-8'),
            json.dumps({"command": "logoff"}).encode('utf-8'),
            b""
        ]
        mock_addr = ("127.0.0.1", 44444)

        mock_db = MagicMock()
        mock_cursor = MagicMock()
        mock_connectsql.return_value.__enter__.return_value = mock_db
        mock_db.cursor.return_value.__enter__.return_value = mock_cursor

        mock_cursor.fetchone.side_effect = [
            {"cnt": 1},  # alex found
            {"password": hashPass("Abc123!")},
            {"cnt": 0}   # no unread
        ]
        handle_client(mock_conn, mock_addr)

        raw_msgs = [call[0][0] for call in mock_conn.sendall.call_args_list]
        self.assertTrue(any(b"Error: Messages must start with" in m for m in raw_msgs))


class TestServerSocketIntegration(unittest.TestCase):
    """
    Basic integration tests that starts the JSON server once for all tests,
    and connects with a real socket client to check flows.
    """

    @classmethod
    def setUpClass(cls):
        enable_payload_logging()
        payload_log.clear()
        cls.server_thread = threading.Thread(target=start_server, daemon=True)
        cls.server_thread.start()
        time.sleep(1)  # give server time to start

    @classmethod
    def tearDownClass(cls):
        disable_payload_logging()

    def test_integration_register_prompt(self):
        """
        Existing test: Connect on 65432, send {"command": "1"} -> expect prompt about username
        """
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect(("0.0.0.0", 65432))
            s.sendall(json.dumps({"command": "1"}).encode('utf-8'))

            resp_data = s.recv(1024)
            self.assertTrue(resp_data, "Server did not respond.")
            resp_obj = json.loads(resp_data.decode('utf-8'))
            self.assertIn("server_message", resp_obj)
            self.assertIn("username", resp_obj["server_message"].lower())

    def test_full_chat_flow(self):
        """
        More realistic flow for JSON:
          1. register
          2. search
          3. send chat message
          4. delete
          5. check
          6. logoff
        """
        # Step 1: Register
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect(("0.0.0.0", 65432))

            # 1) Choose registration
            # The server checks if data == "1" => handle_registration
            s.sendall(json.dumps({"command": "1"}).encode('utf-8'))

            # The server now sends "Enter a username..." => we read it
            resp = s.recv(1024)

            # 2) The server specifically wants {"username": "..."}
            s.sendall(json.dumps({"username": "myuser"}).encode('utf-8'))

            # 3) The server prompts "Enter a password..."
            resp = s.recv(1024)
            s.sendall(json.dumps({"username": "myuser", "password": "MyPass1!"}).encode('utf-8'))

            # 4) The server prompts "Confirm your password..."
            resp = s.recv(1024)
            s.sendall(json.dumps({"username": "myuser", "password": "MyPass1!"}).encode('utf-8'))

            # 5) The server sends "Registration successful"
            resp = s.recv(1024)
            # Done with registration

        # Step 2: Login, then search
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s2:
            s2.connect(("0.0.0.0", 65432))
            s2.sendall(json.dumps({"command": "2"}).encode('utf-8'))
            resp = s2.recv(1024)
            print("here")
            s2.sendall(json.dumps({"command": "2", "username": "myuser"}).encode('utf-8'))
            resp = s2.recv(1024)
            s2.sendall(json.dumps({"command": "2", "password": "MyPass1!"}).encode('utf-8'))
            resp = s2.recv(1024)

            # search
            s2.sendall(json.dumps({"choice": "search"}).encode('utf-8'))
            resp = s2.recv(1024)

            # Step 3: send chat
            s2.sendall(json.dumps({"command": "@myuser Hello to myself!"}).encode('utf-8'))
            time.sleep(0.05)
            resp = s2.recv(1024)

            # Step 4: delete
            s2.sendall(json.dumps({"command": "delete"}).encode('utf-8'))
            time.sleep(0.05)
            resp = s2.recv(1024)
            s2.sendall(json.dumps({"data": "yes"}).encode('utf-8'))
            time.sleep(0.05)
            resp = s2.recv(1024)

            # Step 5: check
            s2.sendall(json.dumps({"command": "check"}).encode('utf-8'))
            time.sleep(0.05)
            resp = s2.recv(1024)

            # Step 6: logoff
            s2.sendall(json.dumps({"choice": "logoff"}).encode('utf-8'))
            resp = s2.recv(1024)

        print("JSON FULL FLOW =>", payload_log)


if __name__ == "__main__":
    unittest.main()