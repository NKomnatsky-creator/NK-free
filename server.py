import socket
import ssl
import json
import struct
import hashlib
import threading
import time
import secrets
import logging
import os
import ipaddress
from datetime import datetime

from database import Database
import license
import sso

logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s')
log = logging.getLogger('server')

TLS_CERT = os.environ.get('TLS_CERT')
TLS_KEY = os.environ.get('TLS_KEY')
SESSION_TTL = 3600
PENDING_2FA_TTL = 300
# Сессия, выданная по API-токену, переиспользуется в течение этого времени.
API_TOKEN_SESSION_TTL = 300
# Общий секрет фронтенда и бэкенда: разрешает доверять полю client_ip,
# когда app.py подключается не с loopback (например, из другого контейнера).
INTERNAL_API_SECRET = os.environ.get('INTERNAL_API_SECRET', '')


def _can_trust_client_ip(peer_ip, req) -> bool:
    try:
        if ipaddress.ip_address(str(peer_ip)).is_loopback:
            return True
    except ValueError:
        pass
    if INTERNAL_API_SECRET:
        return secrets.compare_digest(str(req.get('internal_secret') or ''), INTERNAL_API_SECRET)
    return False
MAX_REQUEST_BYTES = 12 * 1024 * 1024
MAX_RESPONSE_BYTES = 10 * 1024 * 1024
REQUEST_TIMEOUT = 15
HEADER_SIZE = 4


def _recv_exact(sock, n):
    buf = b''
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return None
        buf += chunk
    return buf


def _recv_message(sock):
    header = _recv_exact(sock, HEADER_SIZE)
    if header is None:
        return None
    length = struct.unpack('>I', header)[0]
    if length <= 0 or length > MAX_REQUEST_BYTES:
        raise ValueError(f"Недопустимая длина: {length}")
    return _recv_exact(sock, length)


def _send_message(sock, payload: bytes):
    sock.sendall(struct.pack('>I', len(payload)) + payload)


def _text(req, key, default=''):
    value = req.get(key, default)
    return value.strip() if isinstance(value, str) else default


class FixedServer:
    def __init__(self, host=None, port=5000):
        # По умолчанию бэкенд доступен только локально: трафик между app.py и
        # server.py не шифруется, если не заданы TLS_CERT/TLS_KEY.
        host = host or os.environ.get('SERVER_HOST', '127.0.0.1')
        self.db = Database()
        self.host, self.port = host, port
        self.running = False
        self.sessions = {}
        # Короткоживущие одноразовые токены после первого фактора входа.
        self.pending_logins = {}
        self._lock = threading.Lock()

    def start(self):
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server.bind((self.host, self.port))
        self.server.listen(16)
        self.server.settimeout(1)

        self._tls_ctx = None
        if TLS_CERT and TLS_KEY:
            self._tls_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            self._tls_ctx.load_cert_chain(TLS_CERT, TLS_KEY)
        else:
            log.warning("TLS не настроен: соединение с бэкендом не шифруется")

        self.running = True
        threading.Thread(target=self._cleanup_sessions, daemon=True).start()
        threading.Thread(target=self._background_tasks, daemon=True).start()
        threading.Thread(target=self._license_refresher, daemon=True).start()

        log.info("✓ Сервер слушает %s:%s", self.host, self.port)
        try:
            while self.running:
                try:
                    client, addr = self.server.accept()
                    if self._tls_ctx:
                        try:
                            client = self._tls_ctx.wrap_socket(client, server_side=True)
                        except ssl.SSLError as e:
                            log.warning("TLS handshake failed: %s", e)
                            client.close()
                            continue
                    threading.Thread(target=self.handle_client, args=(client, addr), daemon=True).start()
                except socket.timeout:
                    continue
        finally:
            self.server.close()

    def _license_refresher(self):
        while self.running:
            time.sleep(60)
            try:
                license.reload_license()
            except:
                pass

    def _background_tasks(self):
        last_backup_day = None
        while self.running:
            try:
                self.db.auto_clean_trash()
                self.db.cleanup_logs(days=90)
                if license.has_feature('backup'):
                    today = datetime.now().strftime('%Y-%m-%d')
                    if last_backup_day != today:
                        try:
                            self.db.make_backup()
                        except:
                            pass
                        last_backup_day = today
            except Exception as e:
                log.error(f"Ошибка фоновых задач: {e}")
            time.sleep(3600)

    def handle_client(self, client, addr):
        client.settimeout(REQUEST_TIMEOUT)
        try:
            body = _recv_message(client)
            if not body:
                return
            request = json.loads(body.decode('utf-8'))
            response = self.process_request(request, addr[0])
            payload = json.dumps(response, ensure_ascii=False).encode('utf-8')
            if len(payload) > MAX_RESPONSE_BYTES:
                payload = json.dumps({'status': 'error', 'message': 'Ответ слишком большой'}).encode('utf-8')
            _send_message(client, payload)
        except (ValueError, json.JSONDecodeError) as e:
            log.warning("Некорректный запрос от %s: %s", addr[0], e)
        except Exception:
            log.exception("Ошибка клиента %s", addr[0])
        finally:
            try:
                client.close()
            except:
                pass

    def _user(self, session_id):
        with self._lock:
            s = self.sessions.get(session_id)
            if not s:
                return None
            if time.time() - s['last_activity'] > SESSION_TTL:
                del self.sessions[session_id]
                return None
            # Права и статус могут измениться администратором — перепроверяем
            # их на каждом запросе, а не доверяем данным из сессии.
            # Сессия, выданная по API-токену, не должна жить после его отзыва.
            token_hash = s.get('api_token_hash')
            if token_hash and not self.db.is_api_token_active(token_hash):
                del self.sessions[session_id]
                return None
            current = self.db.get_session_user(s['user']['id'])
            if not current:
                del self.sessions[session_id]
                return None
            s['user'].update(current)
            s['last_activity'] = time.time()
            return s['user']

    def _invalidate_user_sessions(self, user_id: int, keep_session_id: str = None):
        with self._lock:
            for sid in list(self.sessions.keys()):
                if sid == keep_session_id:
                    continue
                if user_id is None or self.sessions[sid]['user']['id'] == user_id:
                    del self.sessions[sid]

    def _cleanup_sessions(self):
        while self.running:
            time.sleep(300)
            now = time.time()
            with self._lock:
                for sid in [k for k, v in self.sessions.items() if now - v['last_activity'] > SESSION_TTL]:
                    del self.sessions[sid]

    def process_request(self, req, ip):
        action = req.get('action', '')
        # Flask-фронтенд передаёт реальный IP клиента: иначе бэкенд видит
        # только адрес самого app.py и баны работают неправильно.
        client_ip = req.get('client_ip')
        if isinstance(client_ip, str) and _can_trust_client_ip(ip, req):
            try:
                ipaddress.ip_address(client_ip)
                ip = client_ip
            except ValueError:
                pass
        is_banned, minutes_left = self.db.check_ip_ban(ip)
        if is_banned:
            return {'status': 'error', 'message': f'Ваш IP заблокирован. Подождите {minutes_left} мин.'}
        handler = getattr(self, f'handle_{action}', None)
        if not handler:
            return {'status': 'error', 'message': f'Неизвестная команда: {action}'}
        try:
            return handler(req, ip)
        except Exception:
            log.exception("Ошибка в %s", action)
            return {'status': 'error', 'message': 'Внутренняя ошибка сервера'}

    def _require_auth(self, req):
        u = self._user(req.get('session_id'))
        if not u:
            return None, {'status': 'error', 'message': 'Сессия истекла'}
        if u.get('must_change_password') and req.get('action') not in ('change_own_password', 'logout', 'ping'):
            return None, {'status': 'error', 'message': 'Необходимо сменить временный пароль!', 'code': 'MUST_CHANGE_PWD'}
        return u, None

    def _require_admin(self, req):
        u, err = self._require_auth(req)
        if err:
            return None, err
        if u['role'] not in ('admin', 'manager'):
            return None, {'status': 'error', 'message': 'Нет прав'}
        return u, None

    def _issue_pending_login(self, user, ip):
        """Выдаёт токен, подтверждающий, что первый фактор уже пройден."""
        token = secrets.token_urlsafe(32)
        now = time.time()
        with self._lock:
            for key, value in list(self.pending_logins.items()):
                if value['expires'] <= now:
                    self.pending_logins.pop(key, None)
            self.pending_logins[token] = {
                'user_id': user['id'], 'ip': ip, 'expires': now + PENDING_2FA_TTL,
                'attempts': 0,
            }
        return token

    def handle_log_license_server_change(self, req, ip):
        """Аудит смены адреса issuing-сервера из веб-админки."""
        user, err = self._require_auth(req)
        if err:
            return err
        if user.get('role') != 'admin':
            return {'status': 'error', 'message': 'Нет прав'}
        details = _text(req, 'details')[:300]
        with self.db._conn() as conn:
            self.db._log(conn, user['id'], 'Смена сервера лицензий', details, ip)
        return {'status': 'success'}

    def handle_login(self, req, ip):
        username = _text(req, 'username')
        ok, user = self.db.authenticate_user(username, req.get('password', '') or '')
        if not ok:
            if user and user.get("disabled"):
                return {'status': 'error', 'message': 'Аккаунт заблокирован администратором.'}
            self.db.record_failed_attempt(ip)
            with self.db._conn() as conn:
                self.db._log(conn, None, "Неудачный вход", f"IP: {ip}, логин: {username}", ip)
            time.sleep(0.5)
            return {'status': 'error', 'message': 'Неверный логин или пароль'}
        self.db.reset_ip_attempts(ip)
        if user.get('totp_enabled'):
            with self.db._conn() as conn:
                self.db._log(conn, user['id'], "Запрос 2FA", f"IP: {ip}", ip)
            return {'status': 'totp_required', 'message': 'Введите код 2FA',
                    'user_id': user['id'], 'username': user['username'],
                    'login_token': self._issue_pending_login(user, ip)}
        sid = secrets.token_hex(16)
        with self._lock:
            self.sessions[sid] = {'user': user, 'last_activity': time.time()}
        with self.db._conn() as conn:
            self.db._log(conn, user['id'], "Вход", f"IP: {ip}", ip)
        return {'status': 'success', 'user': user, 'session_id': sid}

    def handle_verify_totp(self, req, ip):
        """Второй этап входа: нужен одноразовый токен, выданный после пароля/SSO."""
        login_token = str(req.get('login_token', '') or '')[:200]
        with self._lock:
            pending = self.pending_logins.get(login_token)
        if not pending or pending['expires'] <= time.time() or pending['ip'] != ip:
            return {'status': 'error', 'message': 'Сессия 2FA истекла. Войдите снова'}
        user_id = pending['user_id']
        code = str(req.get('code', '') or '')[:40]
        ok, _kind = self.db.verify_second_factor(user_id, code)
        if not ok:
            with self._lock:
                pending['attempts'] += 1
                if pending['attempts'] >= 5:
                    self.pending_logins.pop(login_token, None)
            self.db.record_failed_attempt(ip)
            return {'status': 'error', 'message': 'Неверный код 2FA'}
        with self._lock:
            self.pending_logins.pop(login_token, None)
        user = self.db.get_session_user(user_id)
        if not user:
            return {'status': 'error', 'message': 'Пользователь не найден'}
        user['totp_enabled'] = True
        self.db.reset_ip_attempts(ip)
        sid = secrets.token_hex(16)
        with self._lock:
            self.sessions[sid] = {'user': user, 'last_activity': time.time()}
        with self.db._conn() as conn:
            self.db._log(conn, user['id'], "Вход (2FA)", f"IP: {ip}", ip)
        return {'status': 'success', 'user': user, 'session_id': sid}

    def handle_sso_login(self, req, ip):
        cfg = sso.config()
        if not cfg:
            return {'status': 'error', 'message': 'Внешняя аутентификация не настроена'}
        provider = _text(req, 'provider')
        if provider != cfg['mode']:
            return {'status': 'error', 'message': 'Неверный провайдер аутентификации'}
        identity = req.get('identity')
        if not isinstance(identity, dict):
            return {'status': 'error', 'message': 'Некорректные данные провайдера'}
        subject = _text(identity, 'sub')[:300]
        username = _text(identity, 'username')[:100]
        if not subject or not username:
            return {'status': 'error', 'message': 'Провайдер не вернул идентификатор пользователя'}

        existing = self.db.get_sso_user(provider, subject)
        if not existing:
            ok, msg = license.check_user_limit(len(self.db.get_all_users()))
            if not ok:
                return {'status': 'error', 'message': msg}
        ok, user = self.db.sso_authenticate(
            provider, subject, username,
            email=_text(identity, 'email')[:200],
            names=_text(identity, 'name')[:200],
            role=str(identity.get('role') or 'user'))
        if not ok:
            if user and user.get('disabled'):
                return {'status': 'error', 'message': 'Аккаунт заблокирован администратором.'}
            return {'status': 'error', 'message': 'Не удалось войти через внешнего провайдера'}
        if user.get('totp_enabled'):
            return {'status': 'totp_required', 'message': 'Введите код 2FA',
                    'user_id': user['id'], 'username': user['username'], 'sso_provider': provider,
                    'login_token': self._issue_pending_login(user, ip)}
        sid = secrets.token_hex(16)
        with self._lock:
            self.sessions[sid] = {'user': user, 'last_activity': time.time()}
        with self.db._conn() as conn:
            self.db._log(conn, user['id'], f"Вход ({provider.upper()})", f"IP: {ip}", ip)
        return {'status': 'success', 'user': user, 'session_id': sid}

    def handle_api_token_auth(self, req, ip):
        """Обмен API-токена на короткоживущую серверную сессию для API-запросов."""
        token = str(req.get('token', '') or '')[:300]
        user = self.db.get_api_token_user(token)
        if not user:
            return {'status': 'error', 'message': 'Недействительный API-токен'}
        token_hash = hashlib.sha256(token.encode()).hexdigest()
        now = time.time()
        with self._lock:
            # Переиспользуем сессию того же токена: иначе каждый API-запрос
            # создаёт новую запись, и память растёт до TTL-очистки.
            for existing_sid, sess in self.sessions.items():
                if (sess.get('api_token_hash') == token_hash
                        and sess['user']['id'] == user['id']
                        and now - sess['last_activity'] < API_TOKEN_SESSION_TTL):
                    sess['user'].update(user)
                    sess['last_activity'] = now
                    return {'status': 'success', 'user': dict(sess['user']),
                            'session_id': existing_sid}
            sid = secrets.token_hex(16)
            self.sessions[sid] = {
                'user': user, 'last_activity': now, 'api_token_hash': token_hash,
            }
        return {'status': 'success', 'user': user, 'session_id': sid}

    def handle_logout(self, req, ip):
        sid = req.get('session_id')
        u = self._user(sid)
        if u:
            with self.db._conn() as conn:
                self.db._log(conn, u['id'], "Выход", f"IP: {ip}", ip)
        with self._lock:
            self.sessions.pop(sid, None)
        return {'status': 'success'}

    def handle_ping(self, req, ip):
        return {'status': 'success', 'message': 'pong'}

    def handle_get_passwords(self, req, ip):
        u, err = self._require_auth(req)
        if err:
            return err
        return {'status': 'success', 'data': self.db.get_passwords(u['id'], u['is_admin'], u['role'], req.get('filter_type', 'all'))}

    def handle_add_password(self, req, ip):
        u, err = self._require_auth(req)
        if err:
            return err
        ok, msg = self.db.add_password(
            _text(req, 'service_name'), _text(req, 'username'), req.get('password', ''),
            _text(req, 'url'), _text(req, 'notes'),
            _text(req, 'category', 'Без категории') or 'Без категории', u['id'], expires_at=req.get('expires_at'))
        return {'status': 'success' if ok else 'error', 'message': msg}

    def handle_update_password(self, req, ip):
        u, err = self._require_auth(req)
        if err:
            return err
        ok, msg = self.db.update_password(int(req.get('id', 0)), u['id'], u['role'], req)
        return {'status': 'success' if ok else 'error', 'message': msg}

    def handle_mark_used(self, req, ip):
        u, err = self._require_auth(req)
        if err:
            return err
        self.db.mark_password_used(int(req.get('id', 0)), u['id'])
        return {'status': 'success'}

    def handle_mark_leaked(self, req, ip):
        u, err = self._require_auth(req)
        if err:
            return err
        ok = self.db.set_leaked(int(req.get('id', 0)), u['id'], u['role'], bool(req.get('leaked')))
        if ok and req.get('leaked'):
            self.db.create_notification(u['id'], 'Утечка пароля',
                                        'Пароль отмечен как найденный в утечке. Пора его заменить.', 'warning')
        return {'status': 'success' if ok else 'error'}

    def handle_get_all_passwords_admin(self, req, ip):
        u, err = self._require_admin(req)
        if err:
            return err
        return {'status': 'success', 'data': self.db.get_all_passwords_admin(req.get('filter_type', 'all'))}

    def handle_delete_password(self, req, ip):
        u, err = self._require_auth(req)
        if err:
            return err
        ok, msg = self.db.delete_password(int(req.get('id', 0)), u['id'], u['role'])
        return {'status': 'success' if ok else 'error', 'message': msg}

    def handle_restore_password(self, req, ip):
        u, err = self._require_auth(req)
        if err:
            return err
        ok, msg = self.db.restore_password(int(req.get('id', 0)), u['id'], u['role'])
        return {'status': 'success' if ok else 'error', 'message': msg}

    def handle_purge_password(self, req, ip):
        u, err = self._require_auth(req)
        if err:
            return err
        ok, msg = self.db.purge_password(int(req.get('id', 0)), u['id'], u['role'])
        return {'status': 'success' if ok else 'error', 'message': msg}

    def handle_get_trash(self, req, ip):
        u, err = self._require_auth(req)
        if err:
            return err
        return {'status': 'success', 'data': self.db.get_trash(u['id'], u['role'])}

    def handle_toggle_pin(self, req, ip):
        u, err = self._require_auth(req)
        if err:
            return err
        ok, msg, state = self.db.toggle_pin(int(req.get('id', 0)), u['id'], u['role'])
        return {'status': 'success' if ok else 'error', 'message': msg, 'is_pinned': state}

    def handle_get_history(self, req, ip):
        u, err = self._require_auth(req)
        if err:
            return err
        data = self.db.get_history(int(req.get('id', 0)), u['id'], u['role'])
        if data is None:
            return {'status': 'error', 'message': 'Нет доступа'}
        return {'status': 'success', 'data': data}

    def handle_import_passwords(self, req, ip):
        u, err = self._require_auth(req)
        if err:
            return err
        ok, msg, count = self.db.import_passwords(req.get('passwords', []), u['id'])
        return {'status': 'success' if ok else 'error', 'message': msg, 'count': count}

    def handle_export_passwords(self, req, ip):
        u, err = self._require_auth(req)
        if err:
            return err
        filter_type = req.get('filter_type', 'all')
        if filter_type not in ('all', 'leaks', 'old'):
            filter_type = 'all'
        return {'status': 'success', 'data': self.db.export_passwords(u['id'], u['role'], filter_type)}

    def handle_create_share(self, req, ip):
        u, err = self._require_auth(req)
        if err:
            return err
        if not license.has_feature('sharing'):
            return {'status': 'error', 'message': 'Шаринг доступен только в Standard и выше.'}
        try:
            hours = int(req.get('hours', 24) or 24)
            max_views = int(req.get('max_views', 0) or 0)
        except (TypeError, ValueError):
            return {'status': 'error', 'message': 'Некорректные параметры ссылки'}
        ok, msg, token = self.db.create_share(
            int(req.get('id', 0)), u['id'], u['role'], hours=hours,
            password=str(req.get('password', '') or '')[:200],
            max_views=max_views, one_time=bool(req.get('one_time')))
        if not ok:
            return {'status': 'error', 'message': msg}
        self.db.create_notification(u['id'], 'Общая ссылка создана',
                                    f"Ссылка для пароля #{int(req.get('id', 0))} активна.", 'info')
        return {'status': 'success', 'token': token}

    def handle_get_share_meta(self, req, ip):
        token = str(req.get('token', '') or '')[:200]
        meta = self.db.get_share_meta(token)
        if not meta:
            return {'status': 'error', 'message': 'Ссылка не найдена'}
        public = {'password_required': bool(meta['password_required']), 'valid': bool(meta['valid']),
                  'service_name': meta.get('service_name', ''), 'expires_at': meta.get('expires_at')}
        return {'status': 'success', 'data': public}

    def handle_get_shared(self, req, ip):
        if not license.has_feature('sharing'):
            return {'status': 'error', 'message': 'Функция шаринга недоступна.'}
        token = str(req.get('token', '') or '')[:200]
        ok, data = self.db.use_share(token, password=str(req.get('password', '') or '')[:200],
                                     ip=ip, user_agent=str(req.get('user_agent', '') or '')[:300])
        if not ok:
            meta = self.db.get_share_meta(token)
            if meta and meta.get('password_required'):
                return {'status': 'error', 'message': 'Требуется пароль ссылки', 'code': 'SHARE_PASSWORD_REQUIRED'}
            return {'status': 'error', 'message': 'Ссылка недействительна или использована'}
        return {'status': 'success', 'data': data}

    def handle_get_shares(self, req, ip):
        u, err = self._require_auth(req)
        if err:
            return err
        if not license.has_feature('sharing'):
            return {'status': 'error', 'message': 'Шаринг доступен только в Standard и выше.'}
        return {'status': 'success', 'data': self.db.get_shares(u['id'], u['role'])}

    def handle_revoke_share(self, req, ip):
        u, err = self._require_auth(req)
        if err:
            return err
        if not license.has_feature('sharing'):
            return {'status': 'error', 'message': 'Шаринг доступен только в Standard и выше.'}
        try:
            share_id = int(req.get('id', 0))
        except (TypeError, ValueError):
            return {'status': 'error', 'message': 'Некорректный ID'}
        ok = self.db.revoke_share(share_id, u['id'], u['role'])
        if ok:
            self.db.create_notification(u['id'], 'Общая ссылка отозвана', f"ID ссылки: {share_id}", 'warning')
        return {'status': 'success' if ok else 'error', 'message': 'Ссылка отозвана' if ok else 'Нет прав'}

    def handle_get_share_access(self, req, ip):
        u, err = self._require_auth(req)
        if err:
            return err
        if not license.has_feature('sharing'):
            return {'status': 'error', 'message': 'Шаринг доступен только в Standard и выше.'}
        try:
            share_id = int(req.get('id', 0))
        except (TypeError, ValueError):
            return {'status': 'error', 'message': 'Некорректный ID'}
        return {'status': 'success',
                'data': self.db.get_share_access(share_id, u['id'], u['role'])}

    def handle_get_users(self, req, ip):
        u, err = self._require_admin(req)
        if err:
            return err
        return {'status': 'success', 'data': self.db.get_all_users()}

    def handle_get_user_details(self, req, ip):
        u, err = self._require_admin(req)
        if err:
            return err
        data = self.db.get_user_details(int(req.get('id', 0)))
        return {'status': 'success', 'data': data} if data else {'status': 'error', 'message': 'Не найден'}

    def handle_update_user(self, req, ip):
        u, err = self._require_admin(req)
        if err:
            return err
        try:
            user_id = int(req.get('id', 0))
            is_active = int(req.get('is_active', 1))
        except (TypeError, ValueError):
            return {'status': 'error', 'message': 'Некорректные данные'}
        if is_active not in (0, 1):
            return {'status': 'error', 'message': 'Некорректные данные'}
        ok, msg = self.db.update_user(user_id, req.get('names', ''), req.get('role', 'user'),
                                      is_active, u['id'])
        return {'status': 'success' if ok else 'error', 'message': msg}

    def handle_delete_user(self, req, ip):
        u, err = self._require_admin(req)
        if err:
            return err
        target_id = int(req.get('id', 0))
        ok, msg = self.db.delete_user(target_id, u['id'], u['role'])
        if ok:
            self._invalidate_user_sessions(target_id)
        return {'status': 'success' if ok else 'error', 'message': msg}

    def handle_transfer_passwords(self, req, ip):
        u, err = self._require_auth(req)
        if err:
            return err
        if u['role'] != 'admin':
            return {'status': 'error', 'message': 'Только админ'}
        ok, msg = self.db.transfer_passwords(int(req.get('from_id', 0)), int(req.get('to_id', 0)), u['id'])
        return {'status': 'success' if ok else 'error', 'message': msg}

    def handle_import_users(self, req, ip):
        u, err = self._require_admin(req)
        if err:
            return err
        current_users = len(self.db.get_all_users())
        users_to_import = req.get('users', [])
        if not isinstance(users_to_import, list) or len(users_to_import) > 1000:
            return {'status': 'error', 'message': 'Некорректный список пользователей'}
        if current_users + len(users_to_import) > license.max_users():
            return {'status': 'error', 'message': f"Импорт превысит лимит тарифа ({license.max_users()} чел.)."}
        ok, msg = self.db.import_users(users_to_import, u['id'])
        return {'status': 'success' if ok else 'error', 'message': msg}

    def handle_add_user(self, req, ip):
        u, err = self._require_admin(req)
        if err:
            return err
        current_users = len(self.db.get_all_users())
        ok, msg = license.check_user_limit(current_users)
        if not ok:
            return {'status': 'error', 'message': msg}
        ok, msg = self.db.add_user(req.get('username', '').strip(), req.get('password', ''),
                                   req.get('names', ''), req.get('role', 'user'), u['id'])
        return {'status': 'success' if ok else 'error', 'message': msg}

    def handle_change_own_password(self, req, ip):
        u, err = self._require_auth(req)
        if err:
            return err
        ok, msg = self.db.change_own_password(u['id'], req.get('old_password'), req.get('new_password'))
        if ok:
            sid = req.get('session_id')
            with self._lock:
                if sid and sid in self.sessions:
                    self.sessions[sid]['user']['must_change_password'] = False
            if sid:
                self._invalidate_user_sessions(u['id'], keep_session_id=sid)
        return {'status': 'success' if ok else 'error', 'message': msg}

    def handle_reset_user_password(self, req, ip):
        u, err = self._require_admin(req)
        if err:
            return err
        target_id = int(req.get('user_id', 0))
        ok, msg = self.db.reset_user_password(target_id, req.get('new_password'), u['id'], u['role'])
        if ok:
            self._invalidate_user_sessions(target_id)
        return {'status': 'success' if ok else 'error', 'message': msg}

    def handle_get_public_settings(self, req, ip):
        return {'status': 'success', 'data': self.db.get_public_settings()}

    def handle_save_branding(self, req, ip):
        u, err = self._require_auth(req)
        if err:
            return err
        if not license.has_feature('branding'):
            return {'status': 'error', 'message': 'Смена брендинга доступна только в Standard.'}
        if u['role'] != 'admin':
            return {'status': 'error', 'message': 'Только администратор может менять брендинг'}
        branding_data = {k: v for k, v in req.items() if k not in ('action', 'session_id')}
        ok, msg = self.db.save_branding(branding_data, u['id'])
        return {'status': 'success' if ok else 'error', 'message': msg}

    def handle_get_settings(self, req, ip):
        u, err = self._require_admin(req)
        if err:
            return err
        s = self.db.get_all_settings()
        return {'status': 'success', 'data': {'min_pwd_len': s.get('min_pwd_len', '8'), 'max_pwd_age_days': s.get('max_pwd_age_days', '90')}}

    def handle_save_settings(self, req, ip):
        u, err = self._require_admin(req)
        if err:
            return err
        try:
            min_len = int(req.get('min_pwd_len', 8))
            max_age = int(req.get('max_pwd_age_days', 90))
        except:
            return {'status': 'error', 'message': 'Некорректные значения'}
        if not (4 <= min_len <= 128):
            return {'status': 'error', 'message': 'Длина пароля: 4–128'}
        if not (30 <= max_age <= 365):
            return {'status': 'error', 'message': 'Срок жизни: 30–365 дней'}
        self.db.set_setting('min_pwd_len', min_len)
        self.db.set_setting('max_pwd_age_days', max_age)
        return {'status': 'success', 'message': 'Настройки сохранены'}

    def handle_get_bans(self, req, ip):
        u, err = self._require_admin(req)
        if err:
            return err
        return {'status': 'success', 'data': self.db.get_banned_ips()}

    def handle_unban_ip(self, req, ip):
        u, err = self._require_admin(req)
        if err:
            return err
        self.db.unban_ip(req.get('ip', ''))
        return {'status': 'success', 'message': 'IP разбанен'}

    def handle_get_vaults(self, req, ip):
        u, err = self._require_admin(req)
        if err:
            return err
        return {'status': 'success', 'data': self.db.get_vaults()}

    def handle_create_vault(self, req, ip):
        u, err = self._require_admin(req)
        if err:
            return err
        self.db.create_vault(_text(req, 'name', 'Новая папка') or 'Новая папка', u['id'])
        return {'status': 'success', 'message': 'Создано'}

    def handle_get_vault_details(self, req, ip):
        u, err = self._require_admin(req)
        if err:
            return err
        return {'status': 'success', 'data': self.db.get_vault_details(int(req.get('id', 0)))}

    def handle_update_vault(self, req, ip):
        u, err = self._require_admin(req)
        if err:
            return err
        members, passwords = req.get('members', []), req.get('passwords', [])
        if not isinstance(members, list) or not isinstance(passwords, list):
            return {'status': 'error', 'message': 'Некорректные данные'}
        ok, msg = self.db.update_vault(int(req.get('id', 0)), members, passwords)
        return {'status': 'success' if ok else 'error', 'message': msg}

    def handle_get_stats(self, req, ip):
        u, err = self._require_admin(req)
        if err:
            return err
        return {'status': 'success', 'data': self.db.get_stats()}

    def handle_get_logs(self, req, ip):
        u, err = self._require_admin(req)
        if err:
            return err
        filters = {k: req.get(k) for k in
                   ('user_id', 'ip', 'date_from', 'date_to', 'limit') if k in req}
        # Поле action занято именем команды, поэтому фильтр передаётся отдельно.
        if 'action_filter' in req:
            filters['action'] = req.get('action_filter')
        return {'status': 'success', 'data': self.db.get_logs(filters)}

    # ---------- Уведомления ----------

    def handle_get_notifications(self, req, ip):
        u, err = self._require_auth(req)
        if err:
            return err
        limit = req.get('limit', 50)
        try:
            limit = int(limit)
        except (TypeError, ValueError):
            limit = 50
        return {'status': 'success',
                'data': {'items': self.db.get_notifications(u['id'], limit),
                         'unread': self.db.get_unread_count(u['id'])}}

    def handle_mark_notification_read(self, req, ip):
        u, err = self._require_auth(req)
        if err:
            return err
        try:
            notification_id = int(req.get('id', 0))
        except (TypeError, ValueError):
            return {'status': 'error', 'message': 'Некорректный ID'}
        ok = self.db.mark_notification_read(notification_id, u['id'])
        return {'status': 'success' if ok else 'error'}

    def handle_mark_all_notifications_read(self, req, ip):
        u, err = self._require_auth(req)
        if err:
            return err
        count = self.db.mark_all_notifications_read(u['id'])
        return {'status': 'success', 'count': count}

    # ---------- Центр безопасности ----------

    def handle_security_report(self, req, ip):
        u, err = self._require_auth(req)
        if err:
            return err
        return {'status': 'success', 'data': self.db.get_security_report(u['id'], u['role'])}

    # ---------- Резервные копии ----------

    def _require_backup(self, req):
        u, err = self._require_admin(req)
        if err:
            return None, err
        if not license.has_feature('backup'):
            return None, {'status': 'error', 'message': 'Резервные копии доступны только в Standard и выше.'}
        return u, None

    def handle_list_backups(self, req, ip):
        _u, err = self._require_backup(req)
        if err:
            return err
        return {'status': 'success', 'data': self.db.list_backups()}

    def handle_create_backup(self, req, ip):
        u, err = self._require_backup(req)
        if err:
            return err
        path = self.db.make_backup()
        self.db.create_notification(u['id'], 'Резервная копия создана', os.path.basename(path), 'success')
        return {'status': 'success', 'message': 'Копия создана', 'data': {'name': os.path.basename(path)}}

    def handle_restore_backup(self, req, ip):
        u, err = self._require_backup(req)
        if err:
            return err
        if u['role'] != 'admin':
            return {'status': 'error', 'message': 'Восстановление базы доступно только главному администратору'}
        name = str(req.get('name', '') or '')[:200]
        ok, msg = self.db.restore_backup(name)
        if ok:
            self._invalidate_user_sessions(None)
            self.db.create_notification(u['id'], 'База восстановлена', msg, 'warning')
        return {'status': 'success' if ok else 'error', 'message': msg}

    # ---------- API-токены ----------

    def handle_create_api_token(self, req, ip):
        u, err = self._require_auth(req)
        if err:
            return err
        try:
            days = int(req.get('days', 30))
        except (TypeError, ValueError):
            return {'status': 'error', 'message': 'Некорректный срок действия токена'}
        if days < 0 or days > 365:
            return {'status': 'error', 'message': 'Срок действия токена: 0 (бессрочно) или от 1 до 365 дней'}
        ok, raw = self.db.create_api_token(u['id'], _text(req, 'name', 'CLI') or 'CLI', days)
        if ok:
            self.db.create_notification(u['id'], 'API-токен создан',
                                        f"Название: {_text(req, 'name', 'CLI')}", 'warning')
        return {'status': 'success', 'token': raw} if ok else {'status': 'error', 'message': 'Не удалось создать токен'}

    def handle_list_api_tokens(self, req, ip):
        u, err = self._require_auth(req)
        if err:
            return err
        return {'status': 'success', 'data': self.db.list_api_tokens(u['id'])}

    def handle_revoke_api_token(self, req, ip):
        u, err = self._require_auth(req)
        if err:
            return err
        try:
            token_id = int(req.get('id', 0))
        except (TypeError, ValueError):
            return {'status': 'error', 'message': 'Некорректный ID'}
        ok = self.db.revoke_api_token(token_id, u['id'])
        if ok:
            # Сессии, выданные этим токеном, больше не действительны.
            with self._lock:
                for sid in [k for k, v in self.sessions.items()
                            if v.get('api_token_hash') and v['user']['id'] == u['id']]:
                    self.sessions.pop(sid, None)
        return {'status': 'success' if ok else 'error', 'message': 'Токен отозван' if ok else 'Нет прав'}

    # ---------- TOTP ----------

    def handle_totp_status(self, req, ip):
        u, err = self._require_auth(req)
        if err:
            return err
        return {'status': 'success', 'data': self.db.totp_status(u['id'])}

    def handle_totp_setup(self, req, ip):
        u, err = self._require_auth(req)
        if err:
            return err
        # При уже включённой 2FA ротация требует текущий фактор — иначе
        # достаточно украденной сессии, чтобы сбросить защиту.
        status = self.db.totp_status(u['id'])
        if status.get('enabled'):
            current = str(req.get('current_code', '') or '')[:40]
            ok, _kind = self.db.verify_second_factor(u['id'], current)
            if not ok:
                return {'status': 'error', 'message': 'Введите текущий код 2FA'}
        secret, uri = self.db.start_totp_setup(u['id'])
        return {'status': 'success', 'data': {'secret': secret, 'uri': uri}}

    def handle_totp_enable(self, req, ip):
        u, err = self._require_auth(req)
        if err:
            return err
        ok, msg, codes = self.db.enable_totp(
            u['id'], str(req.get('code', '') or '')[:40],
            str(req.get('current_code', '') or '')[:40])
        if ok:
            self.db.create_notification(u['id'], '2FA включена',
                                        'Сохраните коды восстановления в безопасном месте.', 'warning')
        return {'status': 'success' if ok else 'error', 'message': msg, 'codes': codes}

    def handle_totp_disable(self, req, ip):
        u, err = self._require_auth(req)
        if err:
            return err
        code = str(req.get('code', '') or '')[:40]
        ok, kind = self.db.verify_second_factor(u['id'], code)
        if not ok:
            return {'status': 'error', 'message': 'Неверный код 2FA'}
        self.db.disable_totp(u['id'])
        self.db.create_notification(u['id'], '2FA отключена', 'Двухфакторная защита отключена.', 'warning')
        return {'status': 'success', 'message': '2FA отключена'}

    def handle_save_password_order(self, req, ip):
        u, err = self._require_auth(req)
        if err:
            return err
        order = req.get('order', [])
        if not isinstance(order, list):
            return {'status': 'error', 'message': 'Неверный формат данных'}
        ok, msg = self.db.update_password_order(u['id'], u['role'], order)
        return {'status': 'success' if ok else 'error', 'message': msg}


if __name__ == '__main__':
    srv = FixedServer()  # ✅ База инициализируется здесь, пароль выводится сразу
    try:
        srv.start()
    except KeyboardInterrupt:
        srv.running = False