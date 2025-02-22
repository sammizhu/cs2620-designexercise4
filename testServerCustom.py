"""
Usage:
  coverage run --source=serverCustom testServerCustom.py
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

from serverCustom import (
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
    This test class covers database-related functions such as connectsql,
    checkRealUsername, checkValidPassword, hashPass, and checkRealPassword.
    """

    @patch('serverCustom.pymysql.connect')
    def test_connectsql_unit(self, mock_connect):
        """
        Unit test: Verifies connectsql() calls pymysql.connect with the correct parameters 
        and returns the mock connection object.
        """
        mock_connection = MagicMock()
        mock_connect.return_value = mock_connection

        conn = connectsql()
        mock_connect.assert_called_once_with(
            host='0.0.0.0',
            user='root',
            password='',
            database='db262',
            cursorclass=pymysql.cursors.DictCursor
        )
        self.assertEqual(conn, mock_connection)

    def test_connectsql_regression(self):
        """
        Regression test: Ensures the 'connectsql' function uses the correct default database name ('db262').
        """
        with patch('serverCustom.pymysql.connect') as mock_connect:
            connectsql()
            _, kwargs = mock_connect.call_args
            self.assertEqual(kwargs.get('database'), 'db262')

    @unittest.skip("Integration test requires a live DB.")
    def test_connectsql_integration(self):
        """
        Integration test: Attempts to connect to a real DB and run a trivial query (SELECT 1).
        Requires an actual DB connection.
        """
        conn = connectsql()
        try:
            with conn.cursor() as cur:
                cur.execute("SELECT 1")
                row = cur.fetchone()
                self.assertIsNotNone(row)
        finally:
            conn.close()

    @patch('serverCustom.connectsql')
    def test_checkRealUsername_unit(self, mock_connectsql):
        """
        Unit test: Mocks DB calls for checkRealUsername() to verify that the function 
        returns True/False based on the 'cnt' field from the DB.
        """
        mock_db = MagicMock()
        mock_cursor = MagicMock()
        mock_connectsql.return_value.__enter__.return_value = mock_db
        mock_db.cursor.return_value.__enter__.return_value = mock_cursor

        mock_cursor.fetchone.return_value = {'cnt': 1}
        self.assertTrue(checkRealUsername('alice'))

        mock_cursor.fetchone.return_value = {'cnt': 0}
        self.assertFalse(checkRealUsername('bob'))

    def test_checkRealUsername_regression(self):
        """
        Regression test: Ensures checkRealUsername() does not crash when DB returns None.
        """
        with patch('serverCustom.connectsql') as mock_connectsql:
            mock_db = MagicMock()
            mock_cursor = MagicMock()
            mock_connectsql.return_value.__enter__.return_value = mock_db
            mock_db.cursor.return_value.__enter__.return_value = mock_cursor
            mock_cursor.fetchone.return_value = None
            try:
                result = checkRealUsername('bogususer')
                self.assertFalse(result)
            except Exception as e:
                self.fail(f"Regression bug: checkRealUsername crashed with {e}")

    @unittest.skip("Integration test requires a live DB.")
    def test_checkRealUsername_integration(self):
        """
        Integration test: Attempts checkRealUsername against a known user in the real DB.
        """
        self.assertTrue(checkRealUsername('test_user'))

    def test_checkValidPassword_unit(self):
        """
        Unit test: Checks various valid and invalid passwords to confirm
        checkValidPassword() enforces length, uppercase, lowercase, number, and symbol.
        """
        self.assertFalse(checkValidPassword("Ab1!"))
        self.assertFalse(checkValidPassword("abc123!"))
        self.assertFalse(checkValidPassword("Abcdef!"))
        self.assertFalse(checkValidPassword("Abcdef1"))
        self.assertTrue(checkValidPassword("Abc123!"))

    def test_checkValidPassword_regression(self):
        """
        Regression test: Ensures a specific pattern ('Abc123%') is still flagged as invalid,
        presumably due to special symbol requirements or other constraints.
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
            hashed.startswith("$2b$") or hashed.startswith("$2a$")
        )

    @patch('serverCustom.connectsql')
    def test_checkRealPassword_unit(self, mock_connectsql):
        """
        Unit test: Mocks DB to verify checkRealPassword() returns True when 
        provided with the correct plaintext password matching a stored hash.
        """
        mock_db = MagicMock()
        mock_cursor = MagicMock()
        mock_connectsql.return_value.__enter__.return_value = mock_db
        mock_db.cursor.return_value.__enter__.return_value = mock_cursor

        test_hash = hashPass("Abc123!")
        mock_cursor.fetchone.return_value = {'password': test_hash}
        self.assertTrue(checkRealPassword("testuser", "Abc123!"))
        self.assertFalse(checkRealPassword("testuser", "wrongPass1!"))


class TestServerHighLevelFunctions(unittest.TestCase):
    """
    This test class covers higher-level server functions like handle_registration and handle_login.
    It uses mocking to simulate client input/output and DB operations.
    """

    @patch('serverCustom.connectsql')
    def test_handle_registration_unit(self, mock_connectsql):
        """
        Unit test: Verifies handle_registration() logic when the username is new, 
        and passwords match, leading to a successful registration.
        """
        mock_conn = MagicMock()
        mock_conn.recv.side_effect = [
            b"alice",
            b"Abc123!",
            b"Abc123!"
        ]

        mock_db = MagicMock()
        mock_cursor = MagicMock()
        mock_connectsql.return_value.__enter__.return_value = mock_db
        mock_db.cursor.return_value.__enter__.return_value = mock_cursor

        mock_cursor.fetchone.return_value = {"cnt": 0}

        result = handle_registration(mock_conn, user_id=123)
        self.assertEqual(result, "alice")

        sendall_calls = mock_conn.sendall.call_args_list
        self.assertTrue(any(b"Registration successful" in call[0][0] for call in sendall_calls))

    @patch('serverCustom.connectsql')
    def test_handle_registration_regression(self, mock_connectsql):
        """
        Regression test: Checks handle_registration() properly handles DB insertion errors 
        and sends "Server error. Registration canceled." to the client.
        """
        mock_conn = MagicMock()
        mock_conn.recv.side_effect = [
            b"bob",
            b"Abc123!",
            b"Abc123!"
        ]

        mock_db = MagicMock()
        mock_cursor = MagicMock()
        mock_connectsql.return_value.__enter__.return_value = mock_db
        mock_db.cursor.return_value.__enter__.return_value = mock_cursor

        def db_side_effect(sql, params):
            if sql.startswith("SELECT COUNT(*)"):
                return
            elif sql.startswith("INSERT INTO users"):
                raise Exception("DB insertion error!")

        mock_cursor.fetchone.return_value = {"cnt": 0}
        mock_cursor.execute.side_effect = db_side_effect

        result = handle_registration(mock_conn, user_id=123)
        self.assertIsNone(result)

        sendall_calls = mock_conn.sendall.call_args_list
        msgs = [call[0][0] for call in sendall_calls]
        self.assertTrue(
            any(b"Server error. Registration canceled." in msg for msg in msgs)
        )

    @patch('serverCustom.connectsql')
    def test_handle_login_unit(self, mock_connectsql):
        """
        Unit test: Simulates a client providing a valid username/password. 
        Expects 'Welcome, charlie!' after successful login.
        """
        mock_conn = MagicMock()
        mock_conn.recv.side_effect = [
            b"charlie",
            b"Abc123!"
        ]

        mock_db = MagicMock()
        mock_cursor = MagicMock()
        mock_connectsql.return_value.__enter__.return_value = mock_db
        mock_db.cursor.return_value.__enter__.return_value = mock_cursor

        mock_cursor.fetchone.side_effect = [
            {"cnt": 1},
            {"password": hashPass("Abc123!")}
        ]

        result = handle_login(mock_conn, user_id=999)
        self.assertEqual(result, "charlie")

        sendall_calls = mock_conn.sendall.call_args_list
        self.assertTrue(any(b"Welcome, charlie!" in call[0][0] for call in sendall_calls))

    @patch('serverCustom.connectsql')
    def test_handle_login_regression(self, mock_connectsql):
        """
        Regression test: If the client provides an empty password, 
        handle_login() should cancel the login and return None.
        """
        mock_conn = MagicMock()
        mock_conn.recv.side_effect = [
            b"charlie",
            b""
        ]

        mock_db = MagicMock()
        mock_cursor = MagicMock()
        mock_connectsql.return_value.__enter__.return_value = mock_db
        mock_db.cursor.return_value.__enter__.return_value = mock_cursor

        mock_cursor.fetchone.return_value = {"cnt": 1}

        result = handle_login(mock_conn, user_id=123)
        self.assertIsNone(result)
        sendall_calls = mock_conn.sendall.call_args_list
        self.assertTrue(any(b"Login canceled." in call[0][0] for call in sendall_calls))

    @patch('serverCustom.connectsql')
    def test_check_messages_server_side_unit_zero_unread(self, mock_connectsql):
        """
        Unit test: Simulates a user with 0 unread messages. 
        Ensures the server replies 'You have 0 unread messages.' 
        """
        mock_conn = MagicMock()
        mock_conn.recv.return_value = b""

        mock_db = MagicMock()
        mock_cursor = MagicMock()
        mock_connectsql.return_value.__enter__.return_value = mock_db
        mock_db.cursor.return_value.__enter__.return_value = mock_cursor

        mock_cursor.fetchone.return_value = {"cnt": 0}

        check_messages_server_side(mock_conn, "david")
        sendall_calls = mock_conn.sendall.call_args_list
        self.assertTrue(any(b"You have 0 unread messages." in c[0][0] for c in sendall_calls))

    @patch('serverCustom.connectsql')
    def test_check_messages_server_side_unit_unread_flow(self, mock_connectsql):
        """
        Unit test: Mocks a scenario where the user has 2 unread messages from alice. 
        We then simulate reading them and check the server sends the correct messages.
        """
        mock_conn = MagicMock()
        mock_conn.recv.side_effect = [
            b"1",  # read
            b"alice",
            b""    # after reading batch
        ]

        mock_db = MagicMock()
        mock_cursor = MagicMock()
        mock_connectsql.return_value.__enter__.return_value = mock_db
        mock_db.cursor.return_value.__enter__.return_value = mock_cursor

        mock_cursor.fetchone.side_effect = [
            {"cnt": 2},  # unread
        ]

        mock_cursor.fetchall.return_value = [{"sender": "alice", "num": 2}]

        def fetchall_side_effect():
            now = datetime.datetime.now()
            return [
                {
                    "messageid": 10,
                    "sender": "alice",
                    "message": "Hi there!",
                    "datetime": now
                },
                {
                    "messageid": 11,
                    "sender": "alice",
                    "message": "Are you there?",
                    "datetime": now
                },
            ]
        mock_cursor.fetchall.side_effect = [
            mock_cursor.fetchall.return_value,
            fetchall_side_effect()
        ]

        check_messages_server_side(mock_conn, "david")
        sendall_calls = mock_conn.sendall.call_args_list
        txts = [call[0][0] for call in sendall_calls]

        self.assertTrue(any(b"You have 2 unread messages." in t for t in txts))
        self.assertTrue(any(b"alice (2 messages)" in t for t in txts))
        self.assertTrue(any(b"Hi there!" in t for t in txts))
        self.assertTrue(any(b"Are you there?" in t for t in txts))

    def test_check_messages_server_side_regression(self):
        """
        Regression test: Ensures check_messages_server_side does not crash if fetchall() returns None. 
        """
        with patch('serverCustom.connectsql') as mock_connectsql:
            mock_conn = MagicMock()
            mock_conn.recv.return_value = b"1"
            mock_db = MagicMock()
            mock_cursor = MagicMock()
            mock_connectsql.return_value.__enter__.return_value = mock_db
            mock_db.cursor.return_value.__enter__.return_value = mock_cursor

            mock_cursor.fetchone.return_value = {"cnt": 2}
            mock_cursor.fetchall.return_value = None
            try:
                check_messages_server_side(mock_conn, "alex")
            except Exception as e:
                self.fail(f"Regression: crashed with {e}")


class TestHandleClient(unittest.TestCase):
    """
    Tests for handle_client, which manages the main command loop for a connected user, 
    including registration, login, direct messages, 'check', 'search', 'delete', 'deactivate', etc.
    """

    @patch('serverCustom.connectsql')
    def test_handle_client_unit_registration_flow(self, mock_connectsql):
        """
        Unit test: Simulates choosing option '1' (registration) with matching passwords, 
        then disconnecting. Expects a success message.
        """
        mock_conn = MagicMock()
        mock_conn.recv.side_effect = [
            b"1",        # register
            b"alice",
            b"Abc123!",
            b"Abc123!",
            b""          # disconnect
        ]
        mock_addr = ("127.0.0.1", 12345)

        mock_db = MagicMock()
        mock_cursor = MagicMock()
        mock_connectsql.return_value.__enter__.return_value = mock_db
        mock_db.cursor.return_value.__enter__.return_value = mock_cursor

        mock_cursor.fetchone.return_value = {"cnt": 0}  # 'alice' doesn't exist
        handle_client(mock_conn, mock_addr)

        raw_msgs = [call[0][0] for call in mock_conn.sendall.call_args_list]
        self.assertTrue(any(b"Registration successful" in m for m in raw_msgs))

    @patch('serverCustom.connectsql')
    def test_handle_client_unit_login_flow(self, mock_connectsql):
        """
        Unit test: Simulates choosing option '2' (login) with correct username/password, 
        then logging off. Expects a welcome message and final logoff.
        """
        mock_conn = MagicMock()
        mock_conn.recv.side_effect = [
            b"2",          # login
            b"charlie",
            b"Abc123!",
            b""            # disconnect
        ]
        mock_addr = ("127.0.0.1", 23456)

        mock_db = MagicMock()
        mock_cursor = MagicMock()
        mock_connectsql.return_value.__enter__.return_value = mock_db
        mock_db.cursor.return_value.__enter__.return_value = mock_cursor

        mock_cursor.fetchone.side_effect = [
            {"cnt": 1},  # charlie found
            {"password": hashPass("Abc123!")},
            {"cnt": 0}   # no unread messages (check_messages_server_side call)
        ]
        handle_client(mock_conn, mock_addr)

        raw_msgs = [call[0][0] for call in mock_conn.sendall.call_args_list]
        self.assertTrue(any(b"Welcome, charlie!" in m for m in raw_msgs))

    @patch('serverCustom.connectsql')
    def test_handle_client_unit_logoff_flow(self, mock_connectsql):
        """
        Unit test: After logging in, the user issues 'logoff'. 
        Verifies the server sends a logoff message back.
        """
        mock_conn = MagicMock()
        mock_conn.recv.side_effect = [
            b"2",
            b"alex",
            b"Abc123!",
            b"logoff",
            b""
        ]
        mock_addr = ("127.0.0.1", 34567)

        mock_db = MagicMock()
        mock_cursor = MagicMock()
        mock_connectsql.return_value.__enter__.return_value = mock_db
        mock_db.cursor.return_value.__enter__.return_value = mock_cursor

        mock_cursor.fetchone.side_effect = [
            {"cnt": 1},
            {"password": hashPass("Abc123!")},
            {"cnt": 0}  # no unread 
        ]
        handle_client(mock_conn, mock_addr)

        raw_msgs = [call[0][0] for call in mock_conn.sendall.call_args_list]
        self.assertTrue(any(b"Logged off." in m for m in raw_msgs))

    @patch('serverCustom.connectsql')
    def test_handle_client_regression_unknown_command(self, mock_connectsql):
        """
        Regression test: If user sends a command that is not '1', '2', or recognized subcommands, 
        the server should not crash.
        """
        mock_conn = MagicMock()
        mock_conn.recv.side_effect = [
            b"garbage",
            b"logoff",
            b""
        ]
        mock_addr = ("127.0.0.1", 45678)

        mock_db = MagicMock()
        mock_cursor = MagicMock()
        mock_connectsql.return_value.__enter__.return_value = mock_db
        mock_db.cursor.return_value.__enter__.return_value = mock_cursor

        handle_client(mock_conn, mock_addr)

        # Just ensuring no crash
        self.assertTrue(True)

    @patch('serverCustom.connectsql')
    def test_handle_client_unit_send_message_success(self, mock_connectsql):
        """
        Unit test: After login, user sends '@bob Hello Bob!'. If 'bob' is active, 
        the message is inserted, delivered, and user eventually logs off.
        """
        mock_conn = MagicMock()
        mock_conn.recv.side_effect = [
            b"2",                # login
            b"alice",           # user
            b"Abc123!",         # pass
            b"@bob Hello Bob!", # DM
            b"logoff",          # done
            b""                 # disconnect
        ]
        mock_addr = ("127.0.0.1", 9999)

        mock_db = MagicMock()
        mock_cursor = MagicMock()
        mock_connectsql.return_value.__enter__.return_value = mock_db
        mock_db.cursor.return_value.__enter__.return_value = mock_cursor

        mock_cursor.fetchone.side_effect = [
            {"cnt": 1},  # alice found
            {"password": hashPass("Abc123!")},
            {"cnt": 0},  # no unread
            {"socket_id": "1111", "active": 1}
        ]
        mock_cursor.fetchall.return_value = [ {"messageid": 1} ]

        with patch('serverCustom.clients', {1111: MagicMock()}):
            handle_client(mock_conn, mock_addr)

        raw_msgs = [call[0][0] for call in mock_conn.sendall.call_args_list]
        self.assertFalse(any(b"Username does not exist." in m for m in raw_msgs),
                         "We expected a successful DM, not 'Username does not exist.'")
        self.assertTrue(any(b"Logged off." in m for m in raw_msgs),
                        "Eventually user typed 'logoff'")

    @patch('serverCustom.connectsql')
    def test_handle_client_unit_send_message_no_user(self, mock_connectsql):
        """
        Unit test: After login, user sends '@bob Hello?' but 'bob' doesn't exist. 
        Should see 'Username does not exist.' in server output.
        """
        mock_conn = MagicMock()
        mock_conn.recv.side_effect = [
            b"2",                # login
            b"alice",
            b"Abc123!",
            b"@bob Hello?",
            b"logoff",
            b""
        ]
        mock_addr = ("127.0.0.1", 8888)

        mock_db = MagicMock()
        mock_cursor = MagicMock()
        mock_connectsql.return_value.__enter__.return_value = mock_db
        mock_db.cursor.return_value.__enter__.return_value = mock_cursor

        mock_cursor.fetchone.side_effect = [
            {"cnt": 1},
            {"password": hashPass("Abc123!")},
            {"cnt": 0},
            None
        ]

        handle_client(mock_conn, mock_addr)
        raw_msgs = [call[0][0] for call in mock_conn.sendall.call_args_list]
        self.assertTrue(any(b"Username does not exist." in m for m in raw_msgs))

    @patch('serverCustom.connectsql')
    def test_handle_client_unit_check_command(self, mock_connectsql):
        """
        Unit test: After login, user types 'check' to see unread messages.
        We mock 1 unread message from 'alice' to confirm server output.
        """
        mock_conn = MagicMock()
        mock_conn.recv.side_effect = [
            b"2",
            b"alex",
            b"Abc123!",
            b"check",
            b"logoff",
            b""
        ]
        mock_addr = ("127.0.0.1", 11111)

        mock_db = MagicMock()
        mock_cursor = MagicMock()
        mock_connectsql.return_value.__enter__.return_value = mock_db
        mock_db.cursor.return_value.__enter__.return_value = mock_cursor

        mock_cursor.fetchone.side_effect = [
            {"cnt": 1},
            {"password": hashPass("Abc123!")},
            {"cnt": 1}
        ]
        mock_cursor.fetchall.return_value = [
            {"sender": "alice", "num": 1}
        ]
        def fetchall_side_effect():
            now = datetime.datetime.now()
            return [
                {
                    "messageid": 10,
                    "sender": "alice",
                    "message": "Hi from alice!",
                    "datetime": now
                }
            ]
        mock_cursor.fetchall.side_effect = [
            mock_cursor.fetchall.return_value,
            fetchall_side_effect()
        ]

        handle_client(mock_conn, mock_addr)
        raw_msgs = [call[0][0] for call in mock_conn.sendall.call_args_list]
        self.assertTrue(any(b"You have 1 unread messages." in m for m in raw_msgs))

    @patch('serverCustom.connectsql')
    def test_handle_client_unit_search_command(self, mock_connectsql):
        """
        Unit test: After login, user types 'search'. The server should retrieve a list 
        of all users and exclude the current user from the displayed list.
        """
        mock_conn = MagicMock()
        mock_conn.recv.side_effect = [
            b"2",
            b"alex",
            b"Abc123!",
            b"search",
            b"logoff",
            b""
        ]
        mock_addr = ("127.0.0.1", 22222)

        mock_db = MagicMock()
        mock_cursor = MagicMock()
        mock_connectsql.return_value.__enter__.return_value = mock_db
        mock_db.cursor.return_value.__enter__.return_value = mock_cursor

        mock_cursor.fetchone.side_effect = [
            {"cnt": 1},
            {"password": hashPass("Abc123!")},
            {"cnt": 0}
        ]
        mock_cursor.fetchall.return_value = [
            {"username": "alice"},
            {"username": "alex"},
            {"username": "bob"},
        ]

        handle_client(mock_conn, mock_addr)
        raw_msgs = [call[0][0] for call in mock_conn.sendall.call_args_list]
        self.assertTrue(any(b"alice, bob" in m for m in raw_msgs))

    @patch('serverCustom.connectsql')
    def test_handle_client_unit_delete_command_no_message(self, mock_connectsql):
        """
        Unit test: After login, user issues 'delete' but no unread messages 
        they previously sent are found, so the server should respond accordingly.
        """
        mock_conn = MagicMock()
        mock_conn.recv.side_effect = [
            b"2",
            b"alex",
            b"Abc123!",
            b"delete",
            b"logoff",
            b""
        ]
        mock_addr = ("127.0.0.1", 33333)

        mock_db = MagicMock()
        mock_cursor = MagicMock()
        mock_connectsql.return_value.__enter__.return_value = mock_db
        mock_db.cursor.return_value.__enter__.return_value = mock_cursor

        mock_cursor.fetchone.side_effect = [
            {"cnt": 1},
            {"password": hashPass("Abc123!")},
            {"cnt": 0},
            None
        ]
        handle_client(mock_conn, mock_addr)
        raw_msgs = [call[0][0] for call in mock_conn.sendall.call_args_list]
        self.assertTrue(any(b"You have not sent any messages able to be deleted." in m for m in raw_msgs))

    @patch('serverCustom.connectsql')
    def test_handle_client_unit_delete_command_success(self, mock_connectsql):
        """
        Unit test: If user has an unread message they sent, and they confirm deletion, 
        the server should delete it and report success.
        """
        mock_conn = MagicMock()
        mock_conn.recv.side_effect = [
            b"2",
            b"alex",
            b"Abc123!",
            b"delete",
            b"yes",
            b"logoff",
            b""
        ]
        mock_addr = ("127.0.0.1", 44444)

        mock_db = MagicMock()
        mock_cursor = MagicMock()
        mock_connectsql.return_value.__enter__.return_value = mock_db
        mock_db.cursor.return_value.__enter__.return_value = mock_cursor

        mock_cursor.fetchone.side_effect = [
            {"cnt": 1},
            {"password": hashPass("Abc123!")},
            {"cnt": 0},
            {"messageid": 99}
        ]
        handle_client(mock_conn, mock_addr)
        raw_msgs = [call[0][0] for call in mock_conn.sendall.call_args_list]
        self.assertTrue(any(b"Your last message has been deleted." in m for m in raw_msgs))

    @patch('serverCustom.connectsql')
    def test_handle_client_unit_deactivate_command_success(self, mock_connectsql):
        """
        Unit test: After issuing 'deactivate' and confirming 'yes', 
        the server removes the user's account and messages.
        """
        mock_conn = MagicMock()
        mock_conn.recv.side_effect = [
            b"2",
            b"alex",
            b"Abc123!",
            b"deactivate",
            b"yes",
            b""
        ]
        mock_addr = ("127.0.0.1", 55555)

        mock_db = MagicMock()
        mock_cursor = MagicMock()
        mock_connectsql.return_value.__enter__.return_value = mock_db
        mock_db.cursor.return_value.__enter__.return_value = mock_cursor

        mock_cursor.fetchone.side_effect = [
            {"cnt": 1},
            {"password": hashPass("Abc123!")},
            {"cnt": 0}
        ]
        handle_client(mock_conn, mock_addr)

        raw_msgs = [call[0][0] for call in mock_conn.sendall.call_args_list]
        self.assertTrue(any(b"Your account and all your sent messages have been removed." in m for m in raw_msgs))


class TestServerSocketIntegration(unittest.TestCase):
    """
    A basic integration test that starts the server in a daemon thread
    and tries to connect with a socket client.
    """
    @classmethod
    def setUpClass(cls):
        enable_payload_logging()
        payload_log.clear()
        cls.server_thread = threading.Thread(target=start_server, daemon=True)
        cls.server_thread.start()
        time.sleep(1)

    @classmethod
    def tearDownClass(cls):
        disable_payload_logging()

    def test_integration_server_basic(self):
        """
        Connects to the server on port 65432 and sends '1' to simulate 
        the user selecting 'register'. Expects some prompt about username.
        """
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect(("0.0.0.0", 65432))
            s.sendall(b"1")
            resp = s.recv(1024).decode()
            self.assertIn("Enter a username", resp)

    def test_full_chat_flow(self):
        """
        More realistic flow:
          1. register
          2. search
          3. send chat message
          4. delete it
          5. check messages
          6. log off
        """
        # Step 1: Register
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect(("0.0.0.0", 65432))
            # Choose register
            s.sendall(b"1")

            # "Enter a username"
            resp = s.recv(1024)
            s.sendall(b"myuser")
            resp = s.recv(1024)  # "Enter a password"
            s.sendall(b"MyPass1!")
            resp = s.recv(1024)  # "Confirm your password"
            s.sendall(b"MyPass1!")
            # "Registration successful"
            resp = s.recv(1024)

        # Step 2: Search (must login first, so let's open a new socket and login)
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s2:
            s2.connect(("0.0.0.0", 65432))
            # Choose login
            s2.sendall(b"2")

            # "Enter your username"
            resp = s2.recv(1024)
            s2.sendall(b"myuser")

            # "Enter your password"
            resp = s2.recv(1024)
            s2.sendall(b"MyPass1!")

            # "Welcome, myuser!"
            resp = s2.recv(1024)

            # Now search
            s2.sendall(b"search")
            resp = s2.recv(1024)
            # This should contain a list of users

            # -- Step 3: Send a chat message
            s2.sendall(b"@myuser Hello to myself!")
            resp = s2.recv(1024)

            # -- Step 4: Delete the last message
            s2.sendall(b"delete")
            resp = s2.recv(1024)
            # The server should prompt "Are you sure"
            s2.sendall(b"yes")
            resp = s2.recv(1024)

            # -- Step 5: Check messages
            s2.sendall(b"check")
            resp = s2.recv(1024)

            # -- Step 6: Log off
            s2.sendall(b"logoff")
            resp = s2.recv(1024)

        print("CUSTOM FULL FLOW =>", payload_log)


if __name__ == "__main__":
    unittest.main()