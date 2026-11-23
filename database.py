import sqlite3
import hashlib
import os
import hmac
import json
import logging
import secrets
import re
import shutil
import tempfile
import threading
from datetime import datetime, timedelta
from contextlib import contextmanager
from typing import Optional, List, Tuple
from urllib.parse import urlparse

from cryptography.fernet import Fernet, InvalidToken

import totp
import kdf

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
# Данные можно вынести в отдельный том (Docker): код остаётся только для чтения.
DATA_DIR = os.environ.get('DATA_DIR') or BASE_DIR
os.makedirs(DATA_DIR, exist_ok=True)
KEY_FILE = os.environ.get('FERNET_KEY_FILE') or os.path.join(DATA_DIR, 'secret.key')

MIN_PASSWORD_LEN = 8
MAX_LOGIN_ATTEMPTS = 5
BAN_MINUTES = 15
ALLOWED_ROLES = ('user', 'manager', 'admin')
THEMES = ('system', 'light', 'dark')
FONT_RE = re.compile(r'^[A-Za-z0-9 ,\-]+$')
MAX_TEXT_LEN = 200
MAX_CSS_LEN = 20000
PASSWORD_MASK = '••••••••'

log = logging.getLogger('db')
_ip_ban_lock = threading.Lock()
_pragma_initialized = False
_pragma_lock = threading.Lock()


def _load_or_create_key() -> bytes:
    # При включённом master-password ключ не лежит на диске: он выводится из
    # пароля в start.py и передаётся через окружение. Без него — отказ запуска.
    if kdf.enabled():
        key = kdf.key_from_environment()
        if key is None:
            raise RuntimeError('Включён master-password. Запустите систему через '
                               '"python start.py" и введите мастер-пароль.')
        return key
    if os.path.exists(KEY_FILE):
        with open(KEY_FILE, 'rb') as f:
            return f.read()
    key = Fernet.generate_key()
    try:
        fd = os.open(KEY_FILE, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, 'wb') as f:
            f.write(key)
    except FileExistsError:
        with open(KEY_FILE, 'rb') as f:
            return f.read()
    try:
        os.chmod(KEY_FILE, 0o600)
    except OSError:
        pass
    return key


def _is_safe_url(url: str) -> bool:
    if not url:
        return False
    try:
        p = urlparse(url.strip())
    except Exception:
        return False
    return p.scheme in ('http', 'https')


def _sanitize_snapshot(value):
    """Убирает пароли из старых snapshot'ов истории (они там хранились открыто)."""
    if not value:
        return value
    try:
        diff = json.loads(value) if isinstance(value, str) else dict(value)
    except (TypeError, ValueError):
        return None
    if not isinstance(diff, dict):
        return None
    pwd = diff.get('password')
    if isinstance(pwd, dict):
        diff['password'] = {
            'from': PASSWORD_MASK if pwd.get('from') else '',
            'to': PASSWORD_MASK if pwd.get('to') else '',
        }
    return json.dumps(diff, ensure_ascii=False)


def _sanitize_css(css: str) -> str:
    """CSS вставляется в <style>, поэтому любые угловые скобки недопустимы."""
    css = str(css or '')[:MAX_CSS_LEN]
    css = css.replace('<', '').replace('>', '')
    css = re.sub(r'javascript\s*:', '', css, flags=re.I)
    css = re.sub(r'expression\s*\(', '', css, flags=re.I)
    return css


class Database:
    def __init__(self, db_name=None):
        if db_name is None:
            db_name = os.path.join(DATA_DIR, 'passwords.db')
        self.db_name = db_name
        self._fernet = Fernet(_load_or_create_key())
        self._ensure_pragmas()
        self.init_database()

    def _ensure_pragmas(self):
        global _pragma_initialized
        with _pragma_lock:
            if _pragma_initialized:
                return
            conn = sqlite3.connect(self.db_name, timeout=15.0)
            try:
                conn.execute("PRAGMA journal_mode = WAL")
                conn.execute("PRAGMA synchronous = NORMAL")
                conn.execute("PRAGMA wal_autocheckpoint = 1000")
                conn.commit()
            finally:
                conn.close()
            _pragma_initialized = True

    @contextmanager
    def _conn(self):
        conn = sqlite3.connect(self.db_name, timeout=15.0)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        conn.execute("PRAGMA busy_timeout = 5000")
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def init_database(self):
        with self._conn() as conn:
            c = conn.cursor()
            c.execute('''CREATE TABLE IF NOT EXISTS users
                         (
                             id
                             INTEGER
                             PRIMARY
                             KEY
                             AUTOINCREMENT,
                             username
                             TEXT
                             UNIQUE
                             NOT
                             NULL,
                             password_hash
                             TEXT
                             NOT
                             NULL,
                             salt
                             TEXT
                             NOT
                             NULL,
                             is_admin
                             INTEGER
                             DEFAULT
                             0,
                             role
                             TEXT
                             DEFAULT
                             'user',
                             names
                             TEXT
                             NOT
                             NULL,
                             must_change_password
                             INTEGER
                             DEFAULT
                             0,
                             is_active
                             INTEGER
                             DEFAULT
                             1,
                             created_at
                             TIMESTAMP
                             DEFAULT
                             CURRENT_TIMESTAMP
                         )''')
            c.execute('''CREATE TABLE IF NOT EXISTS passwords
                         (
                             id
                             INTEGER
                             PRIMARY
                             KEY
                             AUTOINCREMENT,
                             service_name
                             TEXT
                             NOT
                             NULL,
                             username
                             TEXT,
                             encrypted_password
                             TEXT
                             NOT
                             NULL,
                             url
                             TEXT,
                             notes
                             TEXT,
                             category
                             TEXT
                             DEFAULT
                             'Без категории',
                             created_by
                             INTEGER
                             NOT
                             NULL,
                             created_at
                             TIMESTAMP
                             DEFAULT
                             CURRENT_TIMESTAMP,
                             last_modified_by
                             INTEGER,
                             last_modified_at
                             TIMESTAMP
                             DEFAULT
                             CURRENT_TIMESTAMP,
                             deleted_at
                             TIMESTAMP
                             DEFAULT
                             NULL,
                             is_pinned
                             INTEGER
                             DEFAULT
                             0,
                             pinned_at
                             TIMESTAMP
                             DEFAULT
                             NULL,
                             expires_at
                             TIMESTAMP
                             DEFAULT
                             NULL,
                             is_leaked
                             INTEGER
                             DEFAULT
                             0,
                             last_used_at
                             TIMESTAMP
                             DEFAULT
                             NULL,
                             sort_order
                             INTEGER
                             DEFAULT
                             0
                         )''')
            c.execute('''CREATE TABLE IF NOT EXISTS password_history
                         (
                             id
                             INTEGER
                             PRIMARY
                             KEY
                             AUTOINCREMENT,
                             password_id
                             INTEGER
                             NOT
                             NULL,
                             encrypted_password
                             TEXT
                             NOT
                             NULL,
                             changed_by
                             INTEGER
                             NOT
                             NULL,
                             changed_at
                             TIMESTAMP
                             DEFAULT
                             CURRENT_TIMESTAMP,
                             snapshot
                             TEXT
                             DEFAULT
                             NULL,
                             change_type
                             TEXT
                             DEFAULT
                             'update'
                         )''')
            c.execute('''CREATE TABLE IF NOT EXISTS logs
                         (
                             id
                             INTEGER
                             PRIMARY
                             KEY
                             AUTOINCREMENT,
                             user_id
                             INTEGER,
                             action
                             TEXT
                             NOT
                             NULL,
                             details
                             TEXT,
                             ip
                             TEXT,
                             created_at
                             TIMESTAMP
                             DEFAULT
                             CURRENT_TIMESTAMP
                         )''')
            c.execute('''CREATE TABLE IF NOT EXISTS settings
                         (
                             key
                             TEXT
                             PRIMARY
                             KEY,
                             value
                             TEXT
                             NOT
                             NULL
                         )''')
            c.execute('''CREATE TABLE IF NOT EXISTS ip_bans
                         (
                             ip
                             TEXT
                             PRIMARY
                             KEY,
                             attempts
                             INTEGER
                             DEFAULT
                             0,
                             banned_until
                             TIMESTAMP
                         )''')
            c.execute('''CREATE TABLE IF NOT EXISTS vaults
                         (
                             id
                             INTEGER
                             PRIMARY
                             KEY
                             AUTOINCREMENT,
                             name
                             TEXT
                             NOT
                             NULL,
                             created_by
                             INTEGER
                             NOT
                             NULL,
                             created_at
                             TIMESTAMP
                             DEFAULT
                             CURRENT_TIMESTAMP
                         )''')
            c.execute('''CREATE TABLE IF NOT EXISTS vault_members
            (
                vault_id
                INTEGER
                NOT
                NULL,
                user_id
                INTEGER
                NOT
                NULL,
                PRIMARY
                KEY
                         (
                vault_id,
                user_id
                         ))''')
            c.execute('''CREATE TABLE IF NOT EXISTS vault_passwords
            (
                vault_id
                INTEGER
                NOT
                NULL,
                password_id
                INTEGER
                NOT
                NULL,
                PRIMARY
                KEY
                         (
                vault_id,
                password_id
                         ))''')
            c.execute('''CREATE TABLE IF NOT EXISTS shared_links
                         (
                             id
                             INTEGER
                             PRIMARY
                             KEY
                             AUTOINCREMENT,
                             token
                             TEXT
                             UNIQUE
                             NOT
                             NULL,
                             password_id
                             INTEGER
                             NOT
                             NULL,
                             created_by
                             INTEGER
                             NOT
                             NULL,
                             expires_at
                             TIMESTAMP
                             NOT
                             NULL,
                             used
                             INTEGER
                             DEFAULT
                             0
                         )''')

            c.execute('''CREATE TABLE IF NOT EXISTS notifications
                         (
                             id INTEGER PRIMARY KEY AUTOINCREMENT,
                             user_id INTEGER NOT NULL,
                             type TEXT NOT NULL DEFAULT 'info',
                             title TEXT NOT NULL,
                             message TEXT NOT NULL DEFAULT '',
                             is_read INTEGER DEFAULT 0,
                             created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                         )''')
            c.execute('''CREATE TABLE IF NOT EXISTS api_tokens
                         (
                             id INTEGER PRIMARY KEY AUTOINCREMENT,
                             user_id INTEGER NOT NULL,
                             name TEXT NOT NULL,
                             token_hash TEXT UNIQUE NOT NULL,
                             last_used_at TIMESTAMP,
                             expires_at TIMESTAMP,
                             is_active INTEGER DEFAULT 1,
                             created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                         )''')
            c.execute('''CREATE TABLE IF NOT EXISTS recovery_codes
                         (
                             id INTEGER PRIMARY KEY AUTOINCREMENT,
                             user_id INTEGER NOT NULL,
                             code_hash TEXT NOT NULL,
                             used_at TIMESTAMP,
                             created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                         )''')
            c.execute('''CREATE TABLE IF NOT EXISTS share_access
                         (
                             id INTEGER PRIMARY KEY AUTOINCREMENT,
                             share_id INTEGER NOT NULL,
                             ip TEXT,
                             user_agent TEXT,
                             success INTEGER DEFAULT 1,
                             created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                         )''')

            u_cols = [r[1] for r in c.execute("PRAGMA table_info(users)").fetchall()]
            if 'totp_secret' not in u_cols:
                c.execute("ALTER TABLE users ADD COLUMN totp_secret TEXT DEFAULT NULL")
            if 'totp_enabled' not in u_cols:
                c.execute("ALTER TABLE users ADD COLUMN totp_enabled INTEGER DEFAULT 0")
            if 'pending_totp_secret' not in u_cols:
                c.execute("ALTER TABLE users ADD COLUMN pending_totp_secret TEXT DEFAULT NULL")
            if 'sso_provider' not in u_cols:
                c.execute("ALTER TABLE users ADD COLUMN sso_provider TEXT DEFAULT NULL")
            if 'sso_sub' not in u_cols:
                c.execute("ALTER TABLE users ADD COLUMN sso_sub TEXT DEFAULT NULL")
            if 'sso_email' not in u_cols:
                c.execute("ALTER TABLE users ADD COLUMN sso_email TEXT DEFAULT NULL")
            if 'auth_source' not in u_cols:
                c.execute("ALTER TABLE users ADD COLUMN auth_source TEXT DEFAULT 'local'")

            s_cols = [r[1] for r in c.execute("PRAGMA table_info(shared_links)").fetchall()]
            for col, ddl in (
                ('pass_hash', 'TEXT DEFAULT NULL'),
                ('max_views', 'INTEGER DEFAULT 0'),
                ('views', 'INTEGER DEFAULT 0'),
                ('one_time', 'INTEGER DEFAULT 0'),
                ('revoked_at', 'TIMESTAMP DEFAULT NULL'),
            ):
                if col not in s_cols:
                    c.execute(f"ALTER TABLE shared_links ADD COLUMN {col} {ddl}")

            p_cols = [r[1] for r in c.execute("PRAGMA table_info(passwords)").fetchall()]
            if 'expires_at' not in p_cols:
                c.execute("ALTER TABLE passwords ADD COLUMN expires_at TIMESTAMP DEFAULT NULL")
            if 'is_leaked' not in p_cols:
                c.execute("ALTER TABLE passwords ADD COLUMN is_leaked INTEGER DEFAULT 0")
            if 'last_used_at' not in p_cols:
                c.execute("ALTER TABLE passwords ADD COLUMN last_used_at TIMESTAMP DEFAULT NULL")
            if 'sort_order' not in p_cols:
                c.execute("ALTER TABLE passwords ADD COLUMN sort_order INTEGER DEFAULT 0")

            # Очистка истории: раньше diff пароля сохранялся в открытом виде.
            for row in c.execute(
                    "SELECT id, snapshot FROM password_history WHERE snapshot IS NOT NULL AND snapshot != ''").fetchall():
                clean = _sanitize_snapshot(row['snapshot'])
                if clean != row['snapshot']:
                    c.execute("UPDATE password_history SET snapshot=? WHERE id=?",
                              (clean, row['id']))

            c.execute("INSERT OR IGNORE INTO settings (key, value) VALUES ('min_pwd_len', '8')")
            c.execute("INSERT OR IGNORE INTO settings (key, value) VALUES ('max_pwd_age_days', '90')")

            _branding_defaults = {'brand_color': '#4f46e5', 'brand_color_2': '#8b5cf6', 'company_name': 'NK Secure',
                                  'logo_text': 'NK', 'logo_url': '', 'radius_card': '16', 'radius_modal': '24',
                                  'font_family': 'Outfit', 'theme_default': 'system', 'custom_css': ''}
            for k, v in _branding_defaults.items():
                c.execute("INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)", (k, v))

            c.execute("SELECT COUNT(*) FROM users WHERE username='admin'")
            if c.fetchone()[0] == 0:
                default_pwd = os.environ.get('DEFAULT_ADMIN_PASSWORD') or secrets.token_urlsafe(12)
                self._create_user(conn, 'admin', default_pwd, 'Администратор', is_admin=1, role='admin', must_change=1)

                # Секрет не должен попадать в stdout/логи контейнера.
                hint = 'Пароль задан переменной DEFAULT_ADMIN_PASSWORD.'
                if not os.environ.get('DEFAULT_ADMIN_PASSWORD'):
                    try:
                        pwd_file = os.path.join(DATA_DIR, '.initial_admin_password')
                        fd = os.open(pwd_file, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
                        with os.fdopen(fd, 'w', encoding='utf-8') as f:
                            f.write(default_pwd + '\n')
                        hint = f'Пароль записан в {pwd_file} (права 0600).'
                    except OSError:
                        hint = 'Не удалось записать пароль в файл — задайте DEFAULT_ADMIN_PASSWORD.'
                print("\n" + "=" * 60, flush=True)
                print(" 🔐 СОЗДАН АККАУНТ АДМИНИСТРАТОРА", flush=True)
                print(" Логин:  admin", flush=True)
                print(f" {hint}", flush=True)
                print(" Смените пароль при первом входе.", flush=True)
                print("=" * 60 + "\n", flush=True)

    @staticmethod
    def _hash(password: str, salt: bytes) -> str:
        return hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 200_000).hex()

    def _create_user(self, conn, username, password, names, is_admin=0, role='user', must_change=0):
        salt = os.urandom(16)
        conn.execute(
            "INSERT INTO users (username, password_hash, salt, names, is_admin, role, must_change_password) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (username, self._hash(password, salt), salt.hex(), names, is_admin, role, must_change))

    def _log(self, conn, user_id, action, details="", ip=None):
        conn.execute("INSERT INTO logs (user_id, action, details, ip) VALUES (?, ?, ?, ?)",
                     (user_id, action, details, ip))

    def get_logs(self, filters=None) -> List[dict]:
        filters = filters or {}
        sql = ("SELECT l.id, l.user_id, l.action, l.details, l.ip, l.created_at, u.username "
               "FROM logs l LEFT JOIN users u ON l.user_id = u.id WHERE 1=1")
        params = []
        user_id = filters.get('user_id')
        if user_id not in (None, '', 'all'):
            try:
                params.append(int(user_id))
                sql += " AND l.user_id=?"
            except (TypeError, ValueError):
                pass
        action = str(filters.get('action') or '').strip()
        if action:
            params.append(f'%{action}%')
            sql += " AND l.action LIKE ?"
        ip = str(filters.get('ip') or '').strip()
        if ip:
            params.append(f'%{ip}%')
            sql += " AND l.ip LIKE ?"
        date_from = str(filters.get('date_from') or '').strip()[:10]
        if date_from:
            params.append(date_from)
            sql += " AND date(l.created_at) >= ?"
        date_to = str(filters.get('date_to') or '').strip()[:10]
        if date_to:
            params.append(date_to)
            sql += " AND date(l.created_at) <= ?"
        try:
            limit = int(filters.get('limit', 1000) or 1000)
        except (TypeError, ValueError):
            limit = 1000
        limit = max(1, min(10000, limit))
        sql += " ORDER BY l.created_at DESC, l.id DESC LIMIT ?"
        params.append(limit)
        with self._conn() as conn:
            rows = conn.execute(sql, tuple(params)).fetchall()
        return [dict(r) for r in rows]

    def cleanup_logs(self, days=90):
        with self._conn() as conn:
            conn.execute("DELETE FROM logs WHERE created_at < datetime('now', ?)", (f'-{days} days',))

    def make_backup(self, backup_dir=None):
        backup_dir = backup_dir or os.path.join(DATA_DIR, 'backups')
        os.makedirs(backup_dir, exist_ok=True)
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        target = os.path.join(backup_dir, f'passwords_{timestamp}.db')
        src = sqlite3.connect(self.db_name)
        dst = sqlite3.connect(target)
        src.backup(dst)
        src.close()
        dst.close()
        backups = sorted([os.path.join(backup_dir, f) for f in os.listdir(backup_dir) if f.startswith('passwords_')])
        for old in backups[:-30]:
            try:
                os.remove(old)
            except:
                pass
        return target

    def _min_pwd_len(self) -> int:
        """Единая политика минимальной длины пароля для всех операций."""
        try:
            return max(1, min(128, int(self.get_setting('min_pwd_len', MIN_PASSWORD_LEN))))
        except (TypeError, ValueError):
            return MIN_PASSWORD_LEN

    def get_setting(self, key, default=None):
        with self._conn() as conn:
            row = conn.execute("SELECT value FROM settings WHERE key=?", (key,)).fetchone()
            return row['value'] if row else default

    def set_setting(self, key, value):
        with self._conn() as conn:
            conn.execute("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)", (key, str(value)))

    def get_all_settings(self) -> dict:
        with self._conn() as conn:
            rows = conn.execute("SELECT key, value FROM settings").fetchall()
        return {r['key']: r['value'] for r in rows}

    def get_public_settings(self) -> dict:
        with self._conn() as conn:
            rows = conn.execute("SELECT key, value FROM settings").fetchall()
        settings = {r['key']: r['value'] for r in rows}
        return {
            'brand': settings.get('brand_color', '#4f46e5'), 'brand2': settings.get('brand_color_2', '#8b5cf6'),
            'company': settings.get('company_name', 'NK Secure'), 'logo_text': settings.get('logo_text', ''),
            'logo_url': settings.get('logo_url', ''), 'radius_card': settings.get('radius_card', '16'),
            'radius_modal': settings.get('radius_modal', '24'), 'font': settings.get('font_family', 'Outfit'),
            'theme_default': settings.get('theme_default', 'system'), 'custom_css': settings.get('custom_css', ''),
        }

    def save_branding(self, data: dict, admin_id: int) -> Tuple[bool, str]:
        hex_re = re.compile(r'^#[0-9a-fA-F]{6}$')
        with self._conn() as conn:
            admin = conn.execute("SELECT role FROM users WHERE id=?", (admin_id,)).fetchone()
            if not admin or admin['role'] != 'admin':
                return False, "Только администратор может менять брендинг"
            updates = {}
            allowed_keys = ['brand_color', 'brand_color_2', 'company_name', 'logo_text', 'logo_url', 'radius_card',
                            'radius_modal', 'font_family', 'theme_default', 'custom_css']
            for k in allowed_keys:
                if k in data:
                    updates[k] = str(data[k]).strip()
            for key in ('brand_color', 'brand_color_2'):
                if key in updates and not hex_re.match(updates[key]):
                    return False, f"Неверный формат {key}"
            for key in ('radius_card', 'radius_modal'):
                if key in updates:
                    if not updates[key].isdigit() or not (0 <= int(updates[key]) <= 200):
                        return False, f"Неверное значение {key}"
            if 'font_family' in updates and not FONT_RE.match(updates['font_family']):
                return False, "Неверное название шрифта"
            if 'theme_default' in updates and updates['theme_default'] not in THEMES:
                return False, "Неверная тема по умолчанию"
            if updates.get('logo_url'):
                if len(updates['logo_url']) > 500 or not _is_safe_url(updates['logo_url']):
                    return False, "logo_url должен быть корректной ссылкой http(s)"
            for key in ('company_name', 'logo_text', 'font_family', 'theme_default'):
                if key in updates:
                    updates[key] = updates[key][:MAX_TEXT_LEN]
            if 'custom_css' in updates:
                updates['custom_css'] = _sanitize_css(updates['custom_css'])
            for k, v in updates.items():
                conn.execute("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)", (k, v))
            self._log(conn, admin_id, "Изменение брендинга", ", ".join(updates.keys()))
        return True, "OK"

    def check_ip_ban(self, ip: str) -> Tuple[bool, int]:
        with _ip_ban_lock:
            with self._conn() as conn:
                row = conn.execute("SELECT attempts, banned_until FROM ip_bans WHERE ip=?", (ip,)).fetchone()
                if not row:
                    return False, 0
                if row['banned_until']:
                    try:
                        ban_time = datetime.fromisoformat(row['banned_until'])
                    except ValueError:
                        return False, 0
                    if datetime.now() < ban_time:
                        return True, int((ban_time - datetime.now()).total_seconds() / 60) + 1
                    else:
                        conn.execute("DELETE FROM ip_bans WHERE ip=?", (ip,))
                return False, 0

    def get_banned_ips(self):
        with self._conn() as conn:
            rows = conn.execute("SELECT * FROM ip_bans WHERE banned_until > ?",
                                (datetime.now().isoformat(),)).fetchall()
            return [dict(r) for r in rows]

    def unban_ip(self, ip):
        with self._conn() as conn:
            conn.execute("DELETE FROM ip_bans WHERE ip=?", (ip,))

    def record_failed_attempt(self, ip: str):
        with _ip_ban_lock:
            with self._conn() as conn:
                row = conn.execute("SELECT attempts FROM ip_bans WHERE ip=?", (ip,)).fetchone()
                attempts = row['attempts'] + 1 if row else 1
                banned_until = None
                if attempts >= MAX_LOGIN_ATTEMPTS:
                    banned_until = (datetime.now() + timedelta(minutes=BAN_MINUTES)).isoformat()
                    self._log(conn, None, "IP Заблокирован",
                              f"IP: {ip} ({MAX_LOGIN_ATTEMPTS} неверных попыток)", ip)
                conn.execute(
                    "INSERT INTO ip_bans (ip, attempts, banned_until) VALUES (?, ?, ?) ON CONFLICT(ip) DO UPDATE SET attempts=excluded.attempts, banned_until=excluded.banned_until",
                    (ip, attempts, banned_until))

    def reset_ip_attempts(self, ip: str):
        with _ip_ban_lock:
            with self._conn() as conn:
                conn.execute("DELETE FROM ip_bans WHERE ip=?", (ip,))

    def authenticate_user(self, username: str, password: str) -> Tuple[bool, Optional[dict]]:
        with self._conn() as conn:
            row = conn.execute(
                "SELECT id, username, password_hash, salt, is_admin, role, must_change_password, is_active, totp_enabled "
                "FROM users WHERE username=?",
                (username,)).fetchone()
        if not row:
            self._hash(password, os.urandom(16))
            return False, None
        computed = self._hash(password, bytes.fromhex(row['salt']))
        if not hmac.compare_digest(computed, row['password_hash']):
            return False, None
        if not row['is_active']:
            return False, {"disabled": True}
        return True, {'id': row['id'], 'username': row['username'], 'is_admin': bool(row['is_admin']),
                      'role': row['role'] or 'user', 'must_change_password': bool(row['must_change_password']),
                      'totp_enabled': bool(row['totp_enabled'])}

    def get_sso_user(self, provider: str, subject: str) -> Optional[dict]:
        with self._conn() as conn:
            row = conn.execute(
                "SELECT id FROM users WHERE sso_provider=? AND sso_sub=?",
                (provider, subject)).fetchone()
        return dict(row) if row else None

    def sso_authenticate(self, provider: str, subject: str, username: str,
                         email: str = '', names: str = '', role: str = 'user') -> Tuple[bool, Optional[dict]]:
        """Находит или создаёт пользователя, пришедшего через LDAP/OIDC.

        Локальные аккаунты НЕ связываются автоматически по имени: иначе
        внешний провайдер смог бы перехватить существующий аккаунт. Для
        новых пользователей создаётся уникальный логин и негодный локальный
        пароль, поэтому вход по паролю невозможен.
        """
        if provider not in ('ldap', 'oidc'):
            return False, None
        subject = str(subject or '').strip()
        username = re.sub(r'[^A-Za-z0-9_.\-@]', '_', str(username or '').strip())[:100]
        if not subject or not username:
            return False, None
        role = role if role in ALLOWED_ROLES else 'user'
        email = str(email or '').strip()[:200]
        names = str(names or username)[:200]
        with self._conn() as conn:
            row = conn.execute(
                "SELECT id, username, role, is_active, must_change_password, is_admin "
                "FROM users WHERE sso_provider=? AND sso_sub=?", (provider, subject)).fetchone()
            if row:
                if not row['is_active']:
                    return False, {"disabled": True}
                conn.execute("UPDATE users SET sso_email=?, names=? WHERE id=?", (email, names, row['id']))
                user = dict(row)
                user['role'] = user['role'] or 'user'
                user['is_admin'] = bool(user['is_admin'])
                user['must_change_password'] = bool(user['must_change_password'])
                user['totp_enabled'] = bool(conn.execute(
                    "SELECT totp_enabled FROM users WHERE id=?", (row['id'],)).fetchone()[0])
                return True, user

            # Не связываем по имени существующий локальный аккаунт.
            candidate = username
            suffix = 1
            while conn.execute("SELECT 1 FROM users WHERE username=?", (candidate,)).fetchone():
                suffix += 1
                candidate = f'{username[:90]}_{suffix}'[:100]
            salt = os.urandom(16)
            conn.execute(
                "INSERT INTO users (username, password_hash, salt, names, is_admin, role, "
                "must_change_password, is_active, sso_provider, sso_sub, sso_email, auth_source) "
                "VALUES (?, ?, ?, ?, ?, ?, 0, 1, ?, ?, ?, ?)",
                (candidate, self._hash(secrets.token_urlsafe(32), salt), salt.hex(), names,
                 1 if role == 'admin' else 0, role, provider, subject, email, provider))
            new_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
            self._log(conn, new_id, "Вход через SSO", f"Провайдер: {provider}, пользователь: {candidate}")
            return True, {
                'id': new_id, 'username': candidate, 'role': role,
                'is_admin': role == 'admin', 'must_change_password': False,
                'totp_enabled': False,
            }

    def get_session_user(self, user_id: int) -> Optional[dict]:
        """Актуальные права пользователя для проверки на каждом запросе."""
        with self._conn() as conn:
            row = conn.execute(
                "SELECT id, username, is_admin, role, must_change_password, is_active FROM users WHERE id=?",
                (user_id,)).fetchone()
        if not row or not row['is_active']:
            return None
        return {'id': row['id'], 'username': row['username'], 'is_admin': bool(row['is_admin']),
                'role': row['role'] or 'user', 'must_change_password': bool(row['must_change_password'])}

    def update_user(self, user_id, names, role, is_active, admin_id):
        if role not in ALLOWED_ROLES:
            return False, "Неизвестная роль"
        with self._conn() as conn:
            admin = conn.execute("SELECT role FROM users WHERE id=?", (admin_id,)).fetchone()
            if not admin or admin['role'] not in ('admin', 'manager'):
                return False, "Нет прав"
            target = conn.execute("SELECT role FROM users WHERE id=?", (user_id,)).fetchone()
            if not target:
                return False, "Не найден"
            if admin['role'] != 'admin' and (role == 'admin' or target['role'] == 'admin'):
                return False, "Только администратор может управлять администраторами"
            if user_id == admin_id and (role != 'admin' or not is_active):
                return False, "Нельзя понизить или заблокировать самого себя"
            is_adm = 1 if role == 'admin' else 0
            conn.execute("UPDATE users SET names=?, role=?, is_admin=?, is_active=? WHERE id=?",
                         (names, role, is_adm, is_active, user_id))
            self._log(conn, admin_id, "Редактирование пользователя", f"ID: {user_id}")
        return True, "OK"

    def add_user(self, username: str, password: str, names: str, role: str, admin_id: int) -> Tuple[bool, str]:
        if not username or len(username) < 3:
            return False, "Логин минимум 3 символа"
        if role not in ALLOWED_ROLES:
            return False, "Неизвестная роль"
        min_len = self._min_pwd_len()
        if not isinstance(password, str) or len(password) < min_len:
            return False, f"Пароль минимум {min_len} символов"
        with self._conn() as conn:
            admin = conn.execute("SELECT is_admin, role FROM users WHERE id=?", (admin_id,)).fetchone()
            if not admin or admin['role'] not in ('admin', 'manager'):
                return False, "Нет прав"
            if admin['role'] == 'manager' and role == 'admin':
                return False, "Только администратор может создавать администраторов"
            if conn.execute("SELECT 1 FROM users WHERE username=?", (username,)).fetchone():
                return False, "Пользователь уже существует"
            is_adm = 1 if role == 'admin' else 0
            self._create_user(conn, username, password, names or username, is_admin=is_adm, role=role, must_change=1)
            self._log(conn, admin_id, "Создание пользователя", f"Добавлен {username} с ролью {role}")
        return True, "OK"

    def import_users(self, users_list, admin_id):
        if not isinstance(users_list, list):
            return False, "Ожидался список"
        if len(users_list) > 1000:
            return False, "Слишком много записей (макс. 1000)"
        added = 0
        errors = []
        min_len = self._min_pwd_len()
        with self._conn() as conn:
            admin = conn.execute("SELECT role FROM users WHERE id=?", (admin_id,)).fetchone()
            if not admin or admin['role'] not in ('admin', 'manager'):
                return False, "Нет прав"
            for i, u in enumerate(users_list, 1):
                if not isinstance(u, dict):
                    continue
                username = str(u.get('username', '')).strip()
                names = str(u.get('names', '')).strip() or username
                role = str(u.get('role', 'user')).strip() or 'user'
                password = str(u.get('password', '')).strip()
                if not username or len(username) < 3:
                    errors.append(f"#{i}: логин < 3 символов")
                    continue
                if role not in ALLOWED_ROLES:
                    errors.append(f"#{i} ({username}): неверная роль")
                    continue
                if admin['role'] == 'manager' and role == 'admin':
                    errors.append(f"#{i} ({username}): менеджер не может создавать админов")
                    continue
                if not password:
                    password = secrets.token_urlsafe(12)
                if len(password) < min_len:
                    errors.append(f"#{i} ({username}): пароль < {min_len}")
                    continue
                if conn.execute("SELECT 1 FROM users WHERE username=?", (username,)).fetchone():
                    errors.append(f"#{i} ({username}): уже существует")
                    continue
                is_adm = 1 if role == 'admin' else 0
                self._create_user(conn, username, password, names, is_admin=is_adm, role=role, must_change=1)
                added += 1
            self._log(conn, admin_id, "Импорт пользователей", f"Добавлено: {added}")
        msg = f"Импортировано: {added}"
        if errors:
            msg += " | Ошибки: " + "; ".join(errors[:10])
        return True, msg

    def delete_user(self, user_id: int, admin_id: int, admin_role: str) -> Tuple[bool, str]:
        if admin_role not in ('admin', 'manager'):
            return False, "Нет прав"
        with self._conn() as conn:
            if user_id == admin_id:
                return False, "Нельзя удалить самого себя"
            user = conn.execute("SELECT username, role FROM users WHERE id=?", (user_id,)).fetchone()
            if not user:
                return False, "Не найден"
            if admin_role == 'manager' and user['role'] == 'admin':
                return False, "Менеджер не может удалить администратора"
            conn.execute("DELETE FROM users WHERE id=?", (user_id,))
            self._log(conn, admin_id, "Удаление пользователя", f"Удален {user['username']}")
        return True, "OK"

    def transfer_passwords(self, from_id, to_id, admin_id):
        with self._conn() as conn:
            if not conn.execute("SELECT 1 FROM users WHERE id=?", (to_id,)).fetchone():
                return False, "Получатель не найден"
            conn.execute("UPDATE passwords SET created_by=? WHERE created_by=?", (to_id, from_id))
            self._log(conn, admin_id, "Передача паролей", f"От {from_id} к {to_id}")
        return True, "OK"

    def get_user_details(self, user_id):
        with self._conn() as conn:
            u = conn.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
            if not u:
                return None
            p_count = conn.execute("SELECT COUNT(*) FROM passwords WHERE created_by=? AND deleted_at IS NULL",
                                   (user_id,)).fetchone()[0]
            logs = conn.execute(
                "SELECT action, details, created_at FROM logs WHERE user_id=? ORDER BY created_at DESC LIMIT 10",
                (user_id,)).fetchall()
            fails = conn.execute(
                "SELECT COUNT(*) FROM logs WHERE action='Неудачный вход' AND instr(details, ?) > 0 AND created_at > datetime('now', '-1 day')",
                (f"логин: {u['username']}",)).fetchone()[0]
            return {'user': dict(u), 'passwords_count': p_count, 'logs': [dict(l) for l in logs], 'fails_24h': fails}

    def change_own_password(self, user_id: int, old_password: str, new_password: str) -> Tuple[bool, str]:
        if not isinstance(old_password, str) or not isinstance(new_password, str):
            return False, "Некорректные пароли"
        min_len = self._min_pwd_len()
        if len(new_password) < min_len:
            return False, f"Пароль минимум {min_len} символов"
        with self._conn() as conn:
            row = conn.execute("SELECT password_hash, salt FROM users WHERE id=?", (user_id,)).fetchone()
            if not row:
                return False, "Пользователь не найден"
            computed = self._hash(old_password, bytes.fromhex(row['salt']))
            if not hmac.compare_digest(computed, row['password_hash']):
                return False, "Неверный старый пароль"
            salt = os.urandom(16)
            conn.execute("UPDATE users SET password_hash=?, salt=?, must_change_password=0 WHERE id=?",
                         (self._hash(new_password, salt), salt.hex(), user_id))
            self._log(conn, user_id, "Смена своего пароля", "")
        return True, "OK"

    def reset_user_password(self, user_id: int, new_password: str, admin_id: int, admin_role: str) -> Tuple[bool, str]:
        if admin_role not in ('admin', 'manager'):
            return False, "Нет прав"
        min_len = self._min_pwd_len()
        if not isinstance(new_password, str) or len(new_password) < min_len:
            return False, f"Пароль минимум {min_len} символов"
        with self._conn() as conn:
            target = conn.execute("SELECT username, role FROM users WHERE id=?", (user_id,)).fetchone()
            if not target:
                return False, "Пользователь не найден"
            if admin_role == 'manager' and target['role'] == 'admin':
                return False, "Менеджер не может менять пароль администратора"
            salt = os.urandom(16)
            conn.execute("UPDATE users SET password_hash=?, salt=?, must_change_password=1 WHERE id=?",
                         (self._hash(new_password, salt), salt.hex(), user_id))
            self._log(conn, admin_id, "Сброс пароля пользователя", f"Пользователь: {target['username']}")
        return True, "OK"

    def _enc(self, text: str) -> str:
        return self._fernet.encrypt((text or '').encode()).decode()

    def _dec(self, token: str) -> Optional[str]:
        try:
            return self._fernet.decrypt(token.encode()).decode()
        except InvalidToken:
            return None

    @staticmethod
    def _validate_url(url: str) -> str:
        if not url:
            return ''
        url = url.strip()
        if url and not _is_safe_url(url):
            return ''
        return url

    def add_password(self, service_name, username, password, url, notes, category, user_id, expires_at=None,
                     owner_id=None):
        if not service_name:
            return False, "Название обязательно"
        with self._conn() as conn:
            actual_owner = owner_id if owner_id else user_id
            conn.execute(
                "INSERT INTO passwords (service_name, username, encrypted_password, url, notes, category, created_by, last_modified_by, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (service_name, username, self._enc(password), self._validate_url(url), notes, category, actual_owner,
                 user_id, expires_at if expires_at else None))
            self._log(conn, user_id, "Добавление пароля", f"Сервис: {service_name}")
        return True, "OK"

    def mark_password_used(self, password_id: int, user_id: int):
        with self._conn() as conn:
            conn.execute("UPDATE passwords SET last_used_at=CURRENT_TIMESTAMP WHERE id=? AND created_by=?",
                         (password_id, user_id))

    def set_leaked(self, password_id: int, user_id: int, role: str, leaked: bool) -> bool:
        with self._conn() as conn:
            row = conn.execute("SELECT created_by FROM passwords WHERE id=? AND deleted_at IS NULL",
                               (password_id,)).fetchone()
            if not row:
                return False
            if role not in ('admin', 'manager') and row['created_by'] != user_id:
                return False
            conn.execute("UPDATE passwords SET is_leaked=? WHERE id=?", (1 if leaked else 0, password_id))
        return True

    def _diff_snapshot(self, old: dict, new: dict) -> dict:
        fields = ('service_name', 'username', 'password', 'url', 'notes', 'category', 'expires_at')
        diff = {}
        for f in fields:
            o = old.get(f) or ''
            n = new.get(f) or ''
            if str(o) != str(n):
                if f == 'password':
                    # В историю пишем только факт изменения, не сами пароли.
                    diff[f] = {'from': PASSWORD_MASK if o else '', 'to': PASSWORD_MASK if n else ''}
                else:
                    diff[f] = {'from': o, 'to': n}
        return diff

    def update_password(self, password_id: int, user_id: int, role: str, data: dict):
        with self._conn() as conn:
            row = conn.execute("SELECT * FROM passwords WHERE id=? AND deleted_at IS NULL", (password_id,)).fetchone()
            if not row:
                return False, "Пароль не найден"
            if role not in ('admin', 'manager') and row['created_by'] != user_id:
                return False, "Нет прав"
            old_password_dec = self._dec(row['encrypted_password'])
            if old_password_dec is None:
                return False, "Ошибка расшифровки"

            old_dec = {'service_name': row['service_name'], 'username': row['username'], 'password': old_password_dec,
                       'url': row['url'], 'notes': row['notes'], 'category': row['category'],
                       'expires_at': row['expires_at']}
            new_vals = {'service_name': data.get('service_name', old_dec['service_name']),
                        'username': data.get('username', old_dec['username']),
                        'password': data.get('password', old_dec['password']), 'url': data.get('url', old_dec['url']),
                        'notes': data.get('notes', old_dec['notes']),
                        'category': data.get('category', old_dec['category']),
                        'expires_at': data.get('expires_at', old_dec['expires_at'])}

            if not new_vals['expires_at']:
                new_vals['expires_at'] = None

            diff = self._diff_snapshot(old_dec, new_vals)
            if not diff:
                return True, "Без изменений"
            conn.execute(
                "INSERT INTO password_history (password_id, encrypted_password, changed_by, snapshot, change_type) VALUES (?, ?, ?, ?, ?)",
                (password_id, self._enc(old_dec['password']), user_id, json.dumps(diff, ensure_ascii=False),
                 'password' if 'password' in diff else 'fields'))
            conn.execute(
                "UPDATE passwords SET service_name=?, username=?, encrypted_password=?, url=?, notes=?, category=?, last_modified_by=?, last_modified_at=CURRENT_TIMESTAMP, expires_at=? WHERE id=?",
                (new_vals['service_name'], new_vals['username'], self._enc(new_vals['password']),
                 self._validate_url(new_vals['url']), new_vals['notes'], new_vals['category'], user_id,
                 new_vals['expires_at'], password_id))
            self._log(conn, user_id, "Изменение пароля", f"Сервис: {new_vals['service_name']}")
        return True, "OK"

    def get_passwords(self, user_id: int, is_admin: bool, role: str, filter_type='all') -> List[dict]:
        with self._conn() as conn:
            sql = '''SELECT p.*, u1.username AS created_by_name, u2.username AS modified_by_name \
                     FROM passwords p \
                              JOIN users u1 ON p.created_by = u1.id \
                              LEFT JOIN users u2 ON p.last_modified_by = u2.id \
                     WHERE p.deleted_at IS NULL'''
            params = []
            if role not in ('admin', 'manager'):
                sql += " AND (p.created_by = ? OR p.id IN (SELECT password_id FROM vault_passwords vp JOIN vault_members vm ON vp.vault_id = vm.vault_id WHERE vm.user_id = ?))"
                params.extend([user_id, user_id])
            if filter_type == 'leaks':
                sql += " AND p.is_leaked = 1"
            elif filter_type == 'old':
                try:
                    max_age = max(1, min(3650, int(self.get_setting('max_pwd_age_days', 90))))
                except (TypeError, ValueError):
                    max_age = 90
                sql += " AND p.last_modified_at < datetime('now', ?)"
                params.append(f'-{max_age} days')
            sql += " ORDER BY p.sort_order ASC, p.is_pinned DESC, p.pinned_at DESC, p.last_modified_at DESC"
            rows = conn.execute(sql, tuple(params)).fetchall()

        result = []
        for r in rows:
            dec = self._dec(r['encrypted_password'])
            result.append({
                'id': r['id'], 'service_name': r['service_name'], 'username': r['username'],
                'password': dec if dec is not None else '', 'password_error': dec is None, 'url': r['url'],
                'notes': r['notes'], 'category': r['category'],
                'created_by': r['created_by'],
                'created_by_name': r['created_by_name'],
                'created_at': r['created_at'], 'last_modified_at': r['last_modified_at'],
                'is_pinned': bool(r['is_pinned']), 'is_leaked': bool(r['is_leaked']), 'expires_at': r['expires_at'],
                'last_used_at': r['last_used_at'], 'sort_order': r['sort_order']
            })
        return result

    def get_all_passwords_admin(self, filter_type='all'):
        return self.get_passwords(0, True, 'admin', filter_type)

    def update_password_order(self, user_id: int, role: str, ordered_ids: list) -> Tuple[bool, str]:
        if not isinstance(ordered_ids, list) or len(ordered_ids) > 10000:
            return False, "Неверный формат данных"
        ids = []
        for value in ordered_ids:
            try:
                ids.append(int(value))
            except (TypeError, ValueError):
                return False, "Неверный формат данных"
        is_admin = role in ('admin', 'manager')
        with self._conn() as conn:
            for index, pid in enumerate(ids):
                if is_admin:
                    conn.execute("UPDATE passwords SET sort_order=? WHERE id=?", (index, pid))
                else:
                    conn.execute("UPDATE passwords SET sort_order=? WHERE id=? AND created_by=?",
                                 (index, pid, user_id))
            self._log(conn, user_id, "Изменение порядка паролей", f"Обновлено: {len(ids)}")
        return True, "OK"

    def delete_password(self, password_id: int, user_id: int, role: str):
        with self._conn() as conn:
            if role in ('admin', 'manager'):
                cur = conn.execute(
                    "UPDATE passwords SET deleted_at=CURRENT_TIMESTAMP WHERE id=? AND deleted_at IS NULL",
                    (password_id,))
            else:
                cur = conn.execute(
                    "UPDATE passwords SET deleted_at=CURRENT_TIMESTAMP WHERE id=? AND created_by=? AND deleted_at IS NULL",
                    (password_id, user_id))
            if cur.rowcount == 0:
                return False, "Не найдено или нет прав"
            self._log(conn, user_id, "Удаление пароля (в корзину)", f"ID: {password_id}")
        return True, "OK"

    def restore_password(self, password_id: int, user_id: int, role: str):
        with self._conn() as conn:
            if role in ('admin', 'manager'):
                cur = conn.execute("UPDATE passwords SET deleted_at=NULL WHERE id=? AND deleted_at IS NOT NULL",
                                   (password_id,))
            else:
                cur = conn.execute(
                    "UPDATE passwords SET deleted_at=NULL WHERE id=? AND created_by=? AND deleted_at IS NOT NULL",
                    (password_id, user_id))
            if cur.rowcount == 0:
                return False, "Не найдено или нет прав"
            self._log(conn, user_id, "Восстановление пароля", f"ID: {password_id}")
        return True, "OK"

    def purge_password(self, password_id: int, user_id: int, role: str):
        with self._conn() as conn:
            if role in ('admin', 'manager'):
                cur = conn.execute("DELETE FROM passwords WHERE id=? AND deleted_at IS NOT NULL", (password_id,))
            else:
                cur = conn.execute("DELETE FROM passwords WHERE id=? AND created_by=? AND deleted_at IS NOT NULL",
                                   (password_id, user_id))
            if cur.rowcount == 0:
                return False, "Не найдено или нет прав"
            self._log(conn, user_id, "Окончательное удаление пароля", f"ID: {password_id}")
        return True, "OK"

    def toggle_pin(self, password_id: int, user_id: int, role: str) -> Tuple[bool, str, bool]:
        with self._conn() as conn:
            row = conn.execute("SELECT created_by, is_pinned FROM passwords WHERE id=? AND deleted_at IS NULL",
                               (password_id,)).fetchone()
            if not row:
                return False, "Не найдено", False
            if role not in ('admin', 'manager') and row['created_by'] != user_id:
                return False, "Нет прав", False
            new_state = 0 if row['is_pinned'] else 1
            conn.execute(
                "UPDATE passwords SET is_pinned=?, pinned_at=CASE WHEN ?=1 THEN CURRENT_TIMESTAMP ELSE NULL END WHERE id=?",
                (new_state, new_state, password_id))
            self._log(conn, user_id, "Закрепление пароля" if new_state else "Открепление пароля",
                      f"ID: {password_id}")
        return True, "OK", bool(new_state)

    def get_history(self, password_id: int, user_id: int, role: str) -> Optional[List[dict]]:
        with self._conn() as conn:
            row = conn.execute("SELECT created_by FROM passwords WHERE id=?", (password_id,)).fetchone()
            if not row:
                return None
            if role not in ('admin', 'manager') and row['created_by'] != user_id:
                return None
            rows = conn.execute(
                "SELECT h.id, h.changed_at, h.change_type, h.snapshot, u.username AS changed_by FROM password_history h JOIN users u ON h.changed_by = u.id WHERE h.password_id = ? ORDER BY h.changed_at DESC LIMIT 200",
                (password_id,)).fetchall()
        result = []
        for r in rows:
            diff = {}
            try:
                clean = _sanitize_snapshot(r['snapshot'])
                diff = json.loads(clean) if clean else {}
            except (TypeError, ValueError):
                pass
            result.append({'id': r['id'], 'changed_at': r['changed_at'], 'change_type': r['change_type'],
                           'changed_by': r['changed_by'], 'diff': diff})
        return result

    def get_trash(self, user_id: int, role: str) -> List[dict]:
        with self._conn() as conn:
            sql = "SELECT p.*, u1.username AS created_by_name FROM passwords p JOIN users u1 ON p.created_by = u1.id WHERE p.deleted_at IS NOT NULL"
            params = ()
            if role not in ('admin', 'manager'):
                sql += " AND p.created_by = ?"
                params = (user_id,)
            rows = conn.execute(sql, params).fetchall()
        return [
            {'id': r['id'], 'service_name': r['service_name'], 'username': r['username'], 'deleted_at': r['deleted_at']}
            for r in rows]

    def auto_clean_trash(self):
        with self._conn() as conn:
            conn.execute(
                "DELETE FROM passwords WHERE deleted_at IS NOT NULL AND deleted_at < datetime('now', '-30 days')")

    def import_passwords(self, passwords_list, user_id: int):
        if not isinstance(passwords_list, list):
            return False, "Ожидался список", 0
        if len(passwords_list) > 10000:
            return False, "Слишком много записей", 0
        added = 0
        with self._conn() as conn:
            for p in passwords_list:
                if not isinstance(p, dict):
                    continue
                service = str(p.get('service_name', '')).strip()
                pwd = str(p.get('password', ''))
                if not service or not pwd:
                    continue
                conn.execute(
                    "INSERT INTO passwords (service_name, username, encrypted_password, url, notes, category, created_by, last_modified_by) VALUES (?,?,?,?,?,?,?,?)",
                    (service, str(p.get('username', '')), self._enc(pwd), self._validate_url(str(p.get('url', ''))),
                     str(p.get('notes', '')), str(p.get('category', 'Импорт')) or 'Импорт', user_id, user_id))
                added += 1
            self._log(conn, user_id, "Импорт паролей", f"Добавлено: {added}")
        return True, f"Импортировано: {added}", added

    def export_passwords(self, user_id: int, role: str, filter_type: str = 'all') -> List[dict]:
        return self.get_passwords(user_id, role in ('admin', 'manager'), role, filter_type)

    def create_share(self, password_id: int, user_id: int, role: str, hours: int = 24,
                     password: str = '', max_views: int = 0, one_time: bool = False):
        with self._conn() as conn:
            row = conn.execute("SELECT created_by FROM passwords WHERE id=? AND deleted_at IS NULL",
                               (password_id,)).fetchone()
            if not row:
                return False, "Не найдено", None
            if role not in ('admin', 'manager') and row['created_by'] != user_id:
                return False, "Нет прав", None
            hours = max(1, min(24 * 30, int(hours or 24)))
            max_views = max(0, min(1000, int(max_views or 0)))
            token = secrets.token_urlsafe(24)
            expires = (datetime.now() + timedelta(hours=hours)).isoformat()
            pass_hash = None
            if password:
                pass_hash = hashlib.sha256(f'{token}:{password}'.encode()).hexdigest()
            conn.execute(
                "INSERT INTO shared_links (token, password_id, created_by, expires_at, pass_hash, max_views, one_time) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (token, password_id, user_id, expires, pass_hash, max_views, 1 if one_time else 0))
            self._log(conn, user_id, "Создание общей ссылки", f"ID пароля: {password_id}")
        return True, "OK", token

    def use_share(self, token: str, password: str = '', ip: str = None,
                  user_agent: str = '') -> Tuple[bool, Optional[dict]]:
        def _access(conn, share_id, ok):
            conn.execute(
                "INSERT INTO share_access (share_id, ip, user_agent, success) VALUES (?, ?, ?, ?)",
                (share_id, ip, (user_agent or '')[:300], 1 if ok else 0))

        with self._conn() as conn:
            row = conn.execute(
                "SELECT s.id, s.expires_at, s.used, s.pass_hash, s.max_views, s.views, s.one_time, s.revoked_at, "
                "p.service_name, p.username, p.encrypted_password "
                "FROM shared_links s JOIN passwords p ON s.password_id = p.id "
                "WHERE s.token=? AND p.deleted_at IS NULL",
                (token,)).fetchone()
            if not row or row['revoked_at']:
                return False, None
            # Ограничение онлайн-перебора пароля общей ссылки.
            fails = conn.execute(
                "SELECT COUNT(*) FROM share_access WHERE share_id=? AND success=0 "
                "AND created_at > datetime('now', '-10 minutes') AND ip IS ?",
                (row['id'], ip)).fetchone()[0]
            if fails >= 5:
                _access(conn, row['id'], False)
                return False, None
            try:
                exp = datetime.fromisoformat(row['expires_at'])
            except (TypeError, ValueError):
                return False, None
            if datetime.now() > exp:
                return False, None
            if row['pass_hash']:
                provided = hashlib.sha256(f'{token}:{password or ""}'.encode()).hexdigest()
                if not hmac.compare_digest(row['pass_hash'], provided):
                    _access(conn, row['id'], False)
                    return False, None
            # Атомарное «занятие» просмотра: параллельные запросы не должны
            # использовать одноразовую ссылку дважды или превысить max_views.
            try:
                cur = conn.execute(
                    "UPDATE shared_links SET views=views+1, "
                    "used=CASE WHEN one_time=1 THEN 1 ELSE used END "
                    "WHERE id=? AND revoked_at IS NULL AND (one_time=0 OR used=0) "
                    "AND (max_views=0 OR max_views IS NULL OR views<max_views)",
                    (row['id'],))
            except sqlite3.OperationalError:
                # Конкурентная транзакция уже изменила ссылку.
                return False, None
            if cur.rowcount != 1:
                return False, None
            encrypted = row['encrypted_password']
            service_name = row['service_name']
            username = row['username']
            _access(conn, row['id'], True)
            conn.execute("INSERT INTO logs (user_id, action, details, ip) VALUES (?, ?, ?, ?)",
                         (None, "Использование общей ссылки", f"token={token[:8]}…", ip))
        pwd = self._dec(encrypted)
        if pwd is None:
            return False, None
        return True, {'service_name': service_name, 'username': username, 'password': pwd}

    def get_share_meta(self, token: str) -> Optional[dict]:
        """Информация о ссылке без расхода просмотров — для публичного экрана ввода пароля."""
        with self._conn() as conn:
            row = conn.execute(
                "SELECT s.id, s.expires_at, s.views, s.max_views, s.one_time, s.used, s.revoked_at, "
                "s.pass_hash IS NOT NULL AS password_required, p.service_name "
                "FROM shared_links s JOIN passwords p ON s.password_id = p.id "
                "WHERE s.token=? AND p.deleted_at IS NULL", (token,)).fetchone()
        if not row:
            return None
        data = dict(row)
        try:
            expired = datetime.now() > datetime.fromisoformat(data['expires_at'])
        except (TypeError, ValueError):
            expired = True
        exhausted = bool(data['max_views'] and data['views'] >= data['max_views'])
        data['expired'] = expired
        data['valid'] = not (expired or exhausted or data['revoked_at'] or
                             (data['one_time'] and data['used']))
        return data

    def get_shares(self, user_id: int, role: str) -> List[dict]:
        sql = ("SELECT s.id, s.token, s.expires_at, s.used, s.views, s.max_views, s.one_time, s.revoked_at, "
               "p.service_name FROM shared_links s JOIN passwords p ON s.password_id = p.id ")
        params = ()
        if role not in ('admin', 'manager'):
            sql += "WHERE s.created_by=? "
            params = (user_id,)
        sql += "ORDER BY s.expires_at DESC"
        with self._conn() as conn:
            rows = [dict(r) for r in conn.execute(sql, params).fetchall()]
        now = datetime.now()
        for row in rows:
            try:
                expired = now > datetime.fromisoformat(row['expires_at'])
            except (TypeError, ValueError):
                expired = True
            exhausted = bool(row['max_views'] and row['views'] >= row['max_views'])
            row['valid'] = not (expired or exhausted or row['revoked_at'] or (row['one_time'] and row['used']))
        return rows

    def revoke_share(self, share_id: int, user_id: int, role: str) -> bool:
        with self._conn() as conn:
            if role in ('admin', 'manager'):
                cur = conn.execute("UPDATE shared_links SET revoked_at=CURRENT_TIMESTAMP WHERE id=?", (share_id,))
            else:
                cur = conn.execute(
                    "UPDATE shared_links SET revoked_at=CURRENT_TIMESTAMP WHERE id=? AND created_by=?",
                    (share_id, user_id))
            if cur.rowcount:
                self._log(conn, user_id, "Отзыв общей ссылки", f"ID: {share_id}")
        return bool(cur.rowcount)

    def get_share_access(self, share_id: int, user_id: int, role: str) -> List[dict]:
        with self._conn() as conn:
            if role not in ('admin', 'manager'):
                allowed = conn.execute("SELECT 1 FROM shared_links WHERE id=? AND created_by=?",
                                       (share_id, user_id)).fetchone()
                if not allowed:
                    return []
            rows = conn.execute(
                "SELECT ip, user_agent, success, created_at FROM share_access WHERE share_id=? "
                "ORDER BY created_at DESC LIMIT 100", (share_id,)).fetchall()
        return [dict(r) for r in rows]

    def create_vault(self, name, admin_id):
        with self._conn() as conn:
            conn.execute("INSERT INTO vaults (name, created_by) VALUES (?, ?)", (name, admin_id))
            self._log(conn, admin_id, "Создание общей папки", name)
        return True, "OK"

    def get_vaults(self):
        with self._conn() as conn:
            rows = conn.execute('''SELECT v.*,
                                          u.username                                                         AS creator,
                                          (SELECT COUNT(*) FROM vault_passwords vp WHERE vp.vault_id = v.id) AS pwd_count,
                                          (SELECT COUNT(*) FROM vault_members vm WHERE vm.vault_id = v.id)   AS members_count
                                   FROM vaults v
                                            JOIN users u ON v.created_by = u.id''').fetchall()
            return [dict(r) for r in rows]

    def get_vault_details(self, vault_id):
        with self._conn() as conn:
            members = conn.execute("SELECT user_id FROM vault_members WHERE vault_id=?", (vault_id,)).fetchall()
            passwords = conn.execute("SELECT password_id FROM vault_passwords WHERE vault_id=?", (vault_id,)).fetchall()
            return {'members': [r['user_id'] for r in members], 'passwords': [r['password_id'] for r in passwords]}

    def update_vault(self, vault_id, members, passwords):
        with self._conn() as conn:
            if not conn.execute("SELECT 1 FROM vaults WHERE id=?", (vault_id,)).fetchone():
                return False, "Папка не найдена"
            conn.execute("DELETE FROM vault_members WHERE vault_id=?", (vault_id,))
            for uid in members or []:
                conn.execute("INSERT OR IGNORE INTO vault_members (vault_id, user_id) VALUES (?, ?)", (vault_id, uid))
            conn.execute("DELETE FROM vault_passwords WHERE vault_id=?", (vault_id,))
            for pid in passwords or []:
                conn.execute("INSERT OR IGNORE INTO vault_passwords (vault_id, password_id) VALUES (?, ?)",
                             (vault_id, pid))
        return True, "OK"

    def get_all_users(self) -> List[dict]:
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT id, username, is_admin, role, names, must_change_password, is_active, created_at FROM users ORDER BY username").fetchall()
        return [dict(r) for r in rows]

    def get_stats(self) -> dict:
        with self._conn() as conn:
            activity = conn.execute(
                "SELECT date(last_modified_at) AS day, COUNT(*) AS count FROM passwords WHERE last_modified_at >= date('now', '-7 days') GROUP BY day ORDER BY day").fetchall()
            users_count = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
            pwd_count = conn.execute("SELECT COUNT(*) FROM passwords WHERE deleted_at IS NULL").fetchone()[0]
            leaks = conn.execute("SELECT COUNT(*) FROM passwords WHERE is_leaked=1 AND deleted_at IS NULL").fetchone()[
                0]
            cats = conn.execute(
                "SELECT category, COUNT(*) AS count FROM passwords WHERE deleted_at IS NULL GROUP BY category").fetchall()
            top_users = conn.execute(
                "SELECT u.username, COUNT(p.id) AS count FROM users u LEFT JOIN passwords p ON u.id = p.created_by AND p.deleted_at IS NULL GROUP BY u.id ORDER BY count DESC LIMIT 5").fetchall()
            db_size_kb = round(os.path.getsize(self.db_name) / 1024, 1) if os.path.exists(self.db_name) else 0
        return {'users_count': users_count, 'passwords_count': pwd_count, 'activity': [dict(r) for r in activity],
                'leaks': leaks, 'categories': [dict(r) for r in cats], 'top_users': [dict(r) for r in top_users],
                'db_size_kb': db_size_kb}

    # ---------- Уведомления ----------

    def create_notification(self, user_id, title, message='', kind='info') -> bool:
        try:
            user_id = int(user_id)
        except (TypeError, ValueError):
            return False
        with self._conn() as conn:
            conn.execute(
                "INSERT INTO notifications (user_id, type, title, message) VALUES (?, ?, ?, ?)",
                (user_id, str(kind or 'info')[:40], str(title or '')[:200], str(message or '')[:1000]))
        return True

    def get_notifications(self, user_id, limit=50) -> List[dict]:
        try:
            limit = int(limit or 50)
        except (TypeError, ValueError):
            limit = 50
        limit = max(1, min(200, limit))
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT id, type, title, message, is_read, created_at FROM notifications "
                "WHERE user_id=? ORDER BY created_at DESC, id DESC LIMIT ?", (user_id, limit)).fetchall()
        return [dict(r) for r in rows]

    def get_unread_count(self, user_id) -> int:
        with self._conn() as conn:
            return conn.execute(
                "SELECT COUNT(*) FROM notifications WHERE user_id=? AND is_read=0", (user_id,)).fetchone()[0]

    def mark_notification_read(self, notification_id, user_id) -> bool:
        with self._conn() as conn:
            cur = conn.execute("UPDATE notifications SET is_read=1 WHERE id=? AND user_id=?",
                               (notification_id, user_id))
        return bool(cur.rowcount)

    def mark_all_notifications_read(self, user_id) -> int:
        with self._conn() as conn:
            cur = conn.execute("UPDATE notifications SET is_read=1 WHERE user_id=? AND is_read=0", (user_id,))
        return cur.rowcount

    # ---------- Центр безопасности ----------

    def get_security_report(self, user_id: int, role: str) -> dict:
        items = self.get_passwords(user_id, role in ('admin', 'manager'), role)
        try:
            max_age = max(1, min(3650, int(self.get_setting('max_pwd_age_days', 90))))
        except (TypeError, ValueError):
            max_age = 90

        def parse_dt(value):
            if not value:
                return None
            value = str(value).replace('T', ' ')[:19]
            for fmt in ('%Y-%m-%d %H:%M:%S', '%Y-%m-%d'):
                try:
                    return datetime.strptime(value, fmt)
                except ValueError:
                    continue
            return None

        now = datetime.now()
        counts = {}
        issues = []
        seen = {}

        for item in items:
            pwd = item.get('password') or ''
            if pwd:
                seen[pwd] = seen.get(pwd, 0) + 1

        for item in items:
            found = []
            pwd = item.get('password') or ''
            if pwd and (len(pwd) < 12 or pwd.isdigit() or pwd.isalpha()):
                found.append(('weak', 'high'))
            if pwd and seen.get(pwd, 0) > 1:
                found.append(('duplicate', 'medium'))
            if item.get('is_leaked'):
                found.append(('leaked', 'high'))
            last = parse_dt(item.get('last_modified_at'))
            if last and (now - last).days > max_age:
                found.append(('old', 'medium'))
            exp = parse_dt(item.get('expires_at'))
            if exp and exp < now:
                found.append(('expired', 'medium'))
            if not item.get('url'):
                found.append(('no_url', 'low'))

            for key, severity in found:
                counts[key] = counts.get(key, 0) + 1
                issues.append({'id': item['id'], 'service_name': item.get('service_name', ''),
                               'issue': key, 'severity': severity})

        order = {'high': 0, 'medium': 1, 'low': 2}
        issues.sort(key=lambda x: (order.get(x['severity'], 3), x['service_name']))
        return {
            'summary': {
                'total': len(items),
                'weak': counts.get('weak', 0),
                'duplicate': counts.get('duplicate', 0),
                'leaked': counts.get('leaked', 0),
                'old': counts.get('old', 0),
                'expired': counts.get('expired', 0),
                'no_url': counts.get('no_url', 0),
                'issues': len(issues),
                'healthy': len(items) - len({i['id'] for i in issues}),
            },
            'issues': issues[:300],
        }

    # ---------- Резервные копии ----------

    def list_backups(self, backup_dir=None) -> List[dict]:
        backup_dir = os.path.abspath(backup_dir or os.path.join(DATA_DIR, 'backups'))
        if not os.path.isdir(backup_dir):
            return []
        result = []
        for name in os.listdir(backup_dir):
            path = os.path.join(backup_dir, name)
            if not os.path.isfile(path) or not name.startswith('passwords_') or not name.endswith('.db'):
                continue
            st = os.stat(path)
            result.append({'name': name,
                           'size_kb': round(st.st_size / 1024, 1),
                           'created_at': datetime.fromtimestamp(st.st_mtime).isoformat(timespec='seconds')})
        return sorted(result, key=lambda x: x['name'], reverse=True)

    def restore_backup(self, name: str) -> Tuple[bool, str]:
        backup_dir = os.path.abspath(os.path.join(DATA_DIR, 'backups'))
        name = str(name or '')
        if not (name.startswith('passwords_') and name.endswith('.db')):
            return False, "Некорректное имя копии"
        path = os.path.abspath(os.path.join(backup_dir, name))
        if os.path.commonpath([backup_dir, path]) != backup_dir:
            return False, "Некорректный путь копии"
        if not os.path.isfile(path):
            return False, "Копия не найдена"
        try:
            with open(path, 'rb') as f:
                if f.read(16) != b'SQLite format 3\x00':
                    return False, "Файл не является базой SQLite"
        except OSError:
            return False, "Не удалось прочитать копию"
        # Уникальный временный файл: параллельные восстановления не перетирают друг друга.
        fd, tmp = tempfile.mkstemp(prefix='passwords_restore_', suffix='.db',
                                   dir=os.path.dirname(self.db_name) or '.')
        os.close(fd)
        try:
            shutil.copy2(path, tmp)
            os.replace(tmp, self.db_name)
            for suffix in ('-wal', '-shm'):
                try:
                    os.remove(self.db_name + suffix)
                except OSError:
                    pass
        except OSError as exc:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            return False, f"Ошибка восстановления: {exc}"
        return True, "База восстановлена. Перезапустите сервер."

    # ---------- API-токены ----------

    def create_api_token(self, user_id, name='CLI', days=30) -> Tuple[bool, str]:
        try:
            days = int(days)
        except (TypeError, ValueError):
            days = 30
        if days < 0:
            days = 30
        days = min(365, days)
        # 0 — бессрочный токен, как обещает интерфейс (expires_at = NULL).
        raw = 'pt_' + secrets.token_urlsafe(32)
        digest = hashlib.sha256(raw.encode()).hexdigest()
        expires = (datetime.now() + timedelta(days=days)).isoformat() if days else None
        with self._conn() as conn:
            conn.execute(
                "INSERT INTO api_tokens (user_id, name, token_hash, expires_at) VALUES (?, ?, ?, ?)",
                (user_id, str(name or 'CLI')[:100], digest, expires))
            self._log(conn, user_id, "Создание API-токена", str(name or 'CLI')[:100])
        return True, raw

    def get_api_token_user(self, token: str) -> Optional[dict]:
        if not token or not str(token).startswith('pt_'):
            return None
        digest = hashlib.sha256(str(token).encode()).hexdigest()
        with self._conn() as conn:
            row = conn.execute(
                "SELECT user_id, expires_at, is_active FROM api_tokens WHERE token_hash=?", (digest,)).fetchone()
            if not row or not row['is_active']:
                return None
            if row['expires_at'] and datetime.now() > datetime.fromisoformat(row['expires_at']):
                return None
            conn.execute("UPDATE api_tokens SET last_used_at=CURRENT_TIMESTAMP WHERE token_hash=?", (digest,))
            user_id = row['user_id']
        return self.get_session_user(user_id)

    def is_api_token_active(self, token_hash: str) -> bool:
        """Проверка хэша токена для уже выданных серверных сессий."""
        if not token_hash:
            return False
        with self._conn() as conn:
            row = conn.execute(
                "SELECT expires_at FROM api_tokens WHERE token_hash=? AND is_active=1",
                (token_hash,)).fetchone()
        if not row:
            return False
        if row['expires_at']:
            try:
                if datetime.now() > datetime.fromisoformat(row['expires_at']):
                    return False
            except ValueError:
                return False
        return True

    def list_api_tokens(self, user_id) -> List[dict]:
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT id, name, last_used_at, expires_at, is_active, created_at FROM api_tokens "
                "WHERE user_id=? ORDER BY created_at DESC", (user_id,)).fetchall()
        return [dict(r) for r in rows]

    def revoke_api_token(self, token_id, user_id) -> bool:
        with self._conn() as conn:
            cur = conn.execute("UPDATE api_tokens SET is_active=0 WHERE id=? AND user_id=?", (token_id, user_id))
        return bool(cur.rowcount)

    # ---------- TOTP ----------

    def get_totp_secret(self, user_id) -> Optional[str]:
        with self._conn() as conn:
            row = conn.execute("SELECT totp_secret FROM users WHERE id=?", (user_id,)).fetchone()
        if not row or not row['totp_secret']:
            return None
        return self._dec(row['totp_secret'])

    def totp_status(self, user_id) -> dict:
        with self._conn() as conn:
            row = conn.execute("SELECT totp_enabled FROM users WHERE id=?", (user_id,)).fetchone()
        return {'enabled': bool(row and row['totp_enabled'])}

    def start_totp_setup(self, user_id) -> Tuple[str, str]:
        """Готовит новый секрет, но НЕ выключает текущую 2FA до подтверждения кодом."""
        secret = totp.generate_secret()
        with self._conn() as conn:
            conn.execute("UPDATE users SET pending_totp_secret=? WHERE id=?",
                         (self._enc(secret), user_id))
        with self._conn() as conn:
            row = conn.execute("SELECT username FROM users WHERE id=?", (user_id,)).fetchone()
            username = row['username'] if row else 'user'
        return secret, totp.provisioning_uri(secret, username)

    def enable_totp(self, user_id, code, current_code='') -> Tuple[bool, str, Optional[list]]:
        """Подтверждает новый секрет. При ротации требует текущий фактор."""
        with self._conn() as conn:
            row = conn.execute(
                "SELECT totp_secret, pending_totp_secret, totp_enabled FROM users WHERE id=?",
                (user_id,)).fetchone()
        if not row:
            return False, "Пользователь не найден", None

        active_secret = self._dec(row['totp_secret']) if row['totp_secret'] else None
        pending_secret = self._dec(row['pending_totp_secret']) if row['pending_totp_secret'] else None
        if not pending_secret:
            return False, "Сначала настройте 2FA", None

        if row['totp_enabled'] and active_secret:
            current = str(current_code or '')
            valid_current = totp.verify_totp(active_secret, current)
            if not valid_current and current:
                digest = totp.hash_recovery_code(current)
                with self._conn() as conn:
                    cur = conn.execute(
                        "UPDATE recovery_codes SET used_at=CURRENT_TIMESTAMP "
                        "WHERE user_id=? AND code_hash=? AND used_at IS NULL",
                        (user_id, digest))
                valid_current = bool(cur.rowcount)
            if not valid_current:
                return False, "Введите текущий код 2FA", None

        if not totp.verify_totp(pending_secret, code):
            return False, "Неверный код", None

        codes = totp.generate_recovery_codes()
        with self._conn() as conn:
            conn.execute(
                "UPDATE users SET totp_secret=?, pending_totp_secret=NULL, totp_enabled=1 WHERE id=?",
                (self._enc(pending_secret), user_id))
            conn.execute("DELETE FROM recovery_codes WHERE user_id=?", (user_id,))
            for code_item in codes:
                conn.execute("INSERT INTO recovery_codes (user_id, code_hash) VALUES (?, ?)",
                             (user_id, totp.hash_recovery_code(code_item)))
            self._log(conn, user_id, "Включение/ротация 2FA", "")
        return True, "2FA включена", codes

    def disable_totp(self, user_id) -> bool:
        with self._conn() as conn:
            conn.execute(
                "UPDATE users SET totp_secret=NULL, pending_totp_secret=NULL, totp_enabled=0 WHERE id=?",
                (user_id,))
            conn.execute("DELETE FROM recovery_codes WHERE user_id=?", (user_id,))
            self._log(conn, user_id, "Отключение 2FA", "")
        return True

    def verify_second_factor(self, user_id, code) -> Tuple[bool, str]:
        secret = self.get_totp_secret(user_id)
        if secret and totp.verify_totp(secret, code):
            return True, 'totp'
        digest = totp.hash_recovery_code(code or '')
        with self._conn() as conn:
            cur = conn.execute(
                "UPDATE recovery_codes SET used_at=CURRENT_TIMESTAMP "
                "WHERE user_id=? AND code_hash=? AND used_at IS NULL", (user_id, digest))
        return (True, 'recovery') if cur.rowcount else (False, "Неверный код")