"""Мастер-пароль и вывод ключа шифрования (PBKDF2-HMAC-SHA256).

Режим master-passwordключается через `python master.py enable`. После включения
plaintext-ключ `secret.key` удаляется, а данные перешифровываются ключом,
выведенным из мастер-пароля. При старте `start.py` запрашивает пароль и
передаёт производный ключ дочерним процессам через переменную
MASTER_DERIVED_KEY. Без неё сервер отказывается запускаться.
"""

import base64
import getpass
import hashlib
import json
import os
import secrets
import sqlite3
import sys
import tempfile
from typing import Optional, Tuple

from cryptography.fernet import Fernet, InvalidToken

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.environ.get('DATA_DIR') or BASE_DIR
MASTER_FILE = os.environ.get('MASTER_CONFIG_FILE') or os.path.join(DATA_DIR, 'master.json')
KEY_FILE = os.environ.get('FERNET_KEY_FILE') or os.path.join(DATA_DIR, 'secret.key')
DB_FILE = os.path.join(DATA_DIR, 'passwords.db')
BACKUP_DIR = os.path.join(DATA_DIR, 'backups')

ITERATIONS = 600_000
VERIFIER_TEXT = b'passvault-master-verifier-v1'

# Все колонки, которые шифруются через Database._enc().
ENCRYPTED_COLUMNS = (
    ('passwords', 'encrypted_password'),
    ('password_history', 'encrypted_password'),
    ('users', 'totp_secret'),
    ('users', 'pending_totp_secret'),
)


class MasterError(Exception):
    pass


def _path(path: str) -> str:
    return path if os.path.isabs(path) else os.path.join(BASE_DIR, path)


def paths() -> dict:
    return {
        'master': _path(MASTER_FILE),
        'key': _path(KEY_FILE),
        'db': _path(DB_FILE),
        'backups': _path(BACKUP_DIR),
    }


def enabled() -> bool:
    return os.path.isfile(_path(MASTER_FILE))


def derive_key(master_password: str, salt: bytes, iterations: int = ITERATIONS) -> bytes:
    if not master_password or len(master_password) < 12:
        raise MasterError('Мастер-пароль должен быть не короче 12 символов')
    try:
        iterations = int(iterations)
    except (TypeError, ValueError):
        raise MasterError('Некорректное число итераций KDF')
    iterations = max(100_000, min(2_000_000, iterations))
    raw = hashlib.pbkdf2_hmac('sha256', master_password.encode('utf-8'), salt, iterations, dklen=32)
    return base64.urlsafe_b64encode(raw)


def _load_config() -> dict:
    path = _path(MASTER_FILE)
    if not os.path.isfile(path):
        raise MasterError('Мастер-пароль не включён')
    try:
        with open(path, 'r', encoding='utf-8') as f:
            cfg = json.load(f)
        salt = base64.b64decode(cfg['salt'], validate=True)
        iterations = int(cfg['iterations'])
        verifier = str(cfg['verifier'])
    except (OSError, ValueError, KeyError, TypeError) as exc:
        raise MasterError(f'Повреждена конфигурация мастер-пароля: {exc}')
    return {'salt': salt, 'iterations': iterations, 'verifier': verifier,
            'algorithm': cfg.get('algorithm', 'pbkdf2_hmac_sha256'),
            'encrypted_old_key': cfg.get('encrypted_old_key'), 'path': path}


def verify(master_password: str, cfg: Optional[dict] = None) -> bytes:
    """Проверяет мастер-пароль и возвращает производный Fernet-ключ."""
    cfg = cfg or _load_config()
    key = derive_key(master_password, cfg['salt'], cfg['iterations'])
    try:
        plain = Fernet(key).decrypt(cfg['verifier'].encode())
    except InvalidToken:
        raise MasterError('Неверный мастер-пароль')
    if not secrets.compare_digest(plain, VERIFIER_TEXT):
        raise MasterError('Неверный мастер-пароль')
    return key


def key_from_environment() -> Optional[bytes]:
    """Возвращает уже выведенный ключ из окружения, если он задан."""
    raw = os.environ.get('MASTER_DERIVED_KEY', '')
    if not raw:
        return None
    if not enabled():
        raise MasterError('MASTER_DERIVED_KEY задан, но мастер-пароль не включён')
    key = verify_from_key(raw)
    return key


def verify_from_key(raw: str) -> bytes:
    """Проверяет производный ключ по verifier (используется дочерними процессами)."""
    cfg = _load_config()
    key = raw.encode('ascii')
    try:
        Fernet(key)  # проверка формата
        plain = Fernet(key).decrypt(cfg['verifier'].encode())
    except (ValueError, TypeError, InvalidToken):
        raise MasterError('MASTER_DERIVED_KEY недействителен — перезапустите через start.py')
    if not secrets.compare_digest(plain, VERIFIER_TEXT):
        raise MasterError('MASTER_DERIVED_KEY недействителен — перезапустите через start.py')
    return key


def _atomic_write(path: str, data: bytes):
    directory = os.path.dirname(path) or '.'
    os.makedirs(directory, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=directory, prefix='.master-', suffix='.tmp')
    try:
        with os.fdopen(fd, 'wb') as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            try:
                os.unlink(tmp)
            except OSError:
                pass
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


def _read_plain_key() -> bytes:
    path = _path(KEY_FILE)
    if not os.path.isfile(path):
        raise MasterError('Не найден secret.key — нечем шифровать данные')
    with open(path, 'rb') as f:
        key = f.read().strip()
    try:
        Fernet(key)
    except ValueError:
        raise MasterError('secret.key повреждён')
    return key


def _reencrypt_file(db_path: str, old_key: bytes, new_key: bytes) -> int:
    old_fernet, new_fernet = Fernet(old_key), Fernet(new_key)
    conn = sqlite3.connect(db_path, timeout=15.0)
    changed = 0
    try:
        existing = {r[0] for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'").fetchall()}
        for table, column in ENCRYPTED_COLUMNS:
            if table not in existing:
                continue
            cols = {r[1] for r in conn.execute(f"PRAGMA table_info({table})").fetchall()}
            if column not in cols:
                continue
            rows = conn.execute(
                f"SELECT rowid, {column} FROM {table} WHERE {column} IS NOT NULL AND {column} != ''").fetchall()
            updates = []
            for rid, value in rows:
                try:
                    plain = old_fernet.decrypt(str(value).encode())
                except (InvalidToken, ValueError):
                    continue  # уже перешифровано или сторонние данные
                updates.append((new_fernet.encrypt(plain).decode(), rid))
            if updates:
                conn.executemany(f"UPDATE {table} SET {column}=? WHERE rowid=?", updates)
                changed += len(updates)
        conn.commit()
    finally:
        conn.close()
    return changed


def _reencrypt_all(old_key: bytes, new_key: bytes) -> dict:
    p = paths()
    stats = {'db': 0, 'backups': 0, 'backup_files': 0}
    if os.path.isfile(p['db']):
        stats['db'] = _reencrypt_file(p['db'], old_key, new_key)
    if os.path.isdir(p['backups']):
        for name in sorted(os.listdir(p['backups'])):
            if not (name.startswith('passwords_') and name.endswith('.db')):
                continue
            path = os.path.join(p['backups'], name)
            if not os.path.isfile(path):
                continue
            stats['backups'] += _reencrypt_file(path, old_key, new_key)
            stats['backup_files'] += 1
    return stats


def _prompt_master(confirm: bool = True, min_len: int = 12) -> str:
    if not sys.stdin.isatty():
        raise MasterError('Мастер-пароль можно задать только в интерактивном терминале '
                          '(или через переменную MASTER_PASSWORD)')
    first = getpass.getpass('Новый мастер-пароль (минимум 12 символов): ')
    if len(first) < min_len:
        raise MasterError('Мастер-пароль слишком короткий')
    if confirm:
        second = getpass.getpass('Повторите мастер-пароль: ')
        if not secrets.compare_digest(first, second):
            raise MasterError('Мастер-пароли не совпадают')
    return first


def enable(master_password: Optional[str] = None) -> dict:
    """Включаетmaster-password и перешифровывает все данные."""
    if enabled():
        raise MasterError('Мастер-пароль уже включён')
    p = paths()
    master_password = master_password or os.environ.get('MASTER_PASSWORD') or _prompt_master()
    if len(master_password) < 12:
        raise MasterError('Мастер-пароль должен быть не короче 12 символов')
    old_key = _read_plain_key()
    salt = os.urandom(16)
    new_key = derive_key(master_password, salt, ITERATIONS)
    stats = _reencrypt_all(old_key, new_key)
    cfg = {
        'version': 1,
        'algorithm': 'pbkdf2_hmac_sha256',
        'iterations': ITERATIONS,
        'salt': base64.b64encode(salt).decode('ascii'),
        'verifier': Fernet(new_key).encrypt(VERIFIER_TEXT).decode('ascii'),
        # Резервный ключ зашифрован новым ключом: снять master можно только зная пароль.
        'encrypted_old_key': Fernet(new_key).encrypt(old_key).decode('ascii'),
    }
    _atomic_write(p['master'], json.dumps(cfg, ensure_ascii=False, indent=2).encode('utf-8'))
    os.remove(p['key'])
    return stats


def disable(master_password: Optional[str] = None) -> dict:
    """Снимает master-password и возвращает исходный ключ из зашифрованной копии."""
    cfg = _load_config()
    if not cfg['encrypted_old_key']:
        raise MasterError('Резервная копия ключа отсутствует — снятие master невозможно')
    master_password = master_password or os.environ.get('MASTER_PASSWORD') or _prompt_master(confirm=False)
    key = verify(master_password, cfg)
    try:
        old_key = Fernet(key).decrypt(cfg['encrypted_old_key'].encode())
    except InvalidToken:
        raise MasterError('Не удалось восстановить исходный ключ')
    stats = _reencrypt_all(key, old_key)
    _atomic_write(_path(KEY_FILE), old_key + b'\n')
    os.remove(cfg['path'])
    return stats


def status() -> dict:
    if not enabled():
        return {'enabled': False, 'message': 'Мастер-пароль не включён'}
    cfg = _load_config()
    return {
        'enabled': True,
        'config': cfg['path'],
        'iterations': cfg['iterations'],
        'algorithm': cfg['algorithm'],
        'unlocked': bool(os.environ.get('MASTER_DERIVED_KEY')),
        'message': 'Мастер-пароль включён',
    }


def main():
    command = sys.argv[1] if len(sys.argv) > 1 else 'status'
    try:
        if command == 'status':
            print(json.dumps(status(), ensure_ascii=False, indent=2))
        elif command == 'enable':
            stats = enable()
            print(f"Мастер-пароль включён. Перешифровано: БД {stats['db']}, "
                  f"копии {stats['backups']} ({stats['backup_files']} файлов).")
            print('Запомните пароль: восстановить ключ без него невозможно.')
        elif command == 'disable':
            stats = disable()
            print(f"Мастер-пароль снят. Перешифровано обратно: БД {stats['db']}, "
                  f"копии {stats['backups']} ({stats['backup_files']} файлов).")
        elif command == 'verify':
            master_password = os.environ.get('MASTER_PASSWORD') or getpass.getpass('Мастер-пароль: ')
            verify(master_password)
            print('Мастер-пароль верен')
        else:
            raise MasterError('Команды: status | enable | disable | verify')
    except MasterError as exc:
        print(f'Ошибка: {exc}', file=sys.stderr)
        sys.exit(1)
    except KeyboardInterrupt:
        print('\nОтменено', file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()
