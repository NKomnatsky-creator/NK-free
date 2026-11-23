"""Тест аудита смены адреса сервера лицензий в журнале событий."""
import os
import sys
import time
import tempfile
import threading
import unittest
from contextlib import contextmanager
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


@contextmanager
def env_patch(**values):
    backup = {k: os.environ.get(k) for k in values}
    for key, value in values.items():
        if value is None:
            os.environ.pop(key, None)
        else:
            os.environ[key] = str(value)
    try:
        yield
    finally:
        for key, value in backup.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value


_tmp = tempfile.mkdtemp(prefix='license-audit-test-')
with env_patch(DATA_DIR=_tmp, LICENSE_SERVER_URL='http://127.0.0.1:9',
               LICENSE_VALIDATE_TIMEOUT='0.3', LICENSE_SERVER_REDEEM_TOKEN=None):
    import server as servermod


class FakeDB:
    def __init__(self):
        self.logs = []
        self.users = {}

    def get_session_user(self, user_id):
        return self.users.get(user_id, {'id': user_id, 'role': 'admin',
                                        'must_change_password': False})

    def is_api_token_active(self, token_hash):
        return True

    @contextmanager
    def _conn(self):
        yield self

    def _log(self, conn, user_id, action, details, ip):
        self.logs.append((user_id, action, details, ip))


class AuditTest(unittest.TestCase):
    def setUp(self):
        self.handler = object.__new__(servermod.FixedServer)
        self.handler.db = FakeDB()
        self.handler._lock = threading.Lock()
        self.handler.sessions = {
            'admin-session': {'user': {'id': 7, 'role': 'admin', 'must_change_password': False},
                              'last_activity': time.time()}
        }

    def test_change_is_written_to_audit_log(self):
        result = self.handler.handle_log_license_server_change(
            {'session_id': 'admin-session',
             'details': 'http://127.0.0.1:8100 → http://127.0.0.1:8101'},
            '192.168.1.20')
        self.assertEqual(result, {'status': 'success'})
        self.assertEqual(self.handler.db.logs,
                         [(7, 'Смена сервера лицензий',
                           'http://127.0.0.1:8100 → http://127.0.0.1:8101',
                           '192.168.1.20')])

    def test_requires_admin(self):
        self.handler.db.users[8] = {'id': 8, 'role': 'user', 'must_change_password': False}
        self.handler.sessions['user-session'] = {
            'user': {'id': 8, 'role': 'user', 'must_change_password': False},
            'last_activity': time.time()}
        result = self.handler.handle_log_license_server_change(
            {'session_id': 'user-session', 'details': 'x'}, '127.0.0.1')
        self.assertEqual(result['status'], 'error')
        self.assertEqual(self.handler.db.logs, [])


if __name__ == '__main__':
    unittest.main()
