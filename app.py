import os
import socket
import json
import struct
import secrets
import csv
import io
import time
import traceback
import re
from datetime import timedelta
from urllib.parse import urlencode, urlsplit, parse_qsl

from flask import (Flask, render_template, request, jsonify, session, redirect, send_file, send_from_directory,
                   Response, flash, g)
from flask_wtf.csrf import CSRFProtect, CSRFError
from werkzeug.middleware.proxy_fix import ProxyFix
import qrcode
import license
import sso
from translations import get_text

app = Flask(__name__)
_DATA_DIR = os.environ.get('DATA_DIR') or os.path.dirname(os.path.abspath(__file__))
os.makedirs(_DATA_DIR, exist_ok=True)
_SECRET_FILE = os.environ.get('FLASK_SECRET_FILE') or os.path.join(_DATA_DIR, '.flask_secret')


def _get_flask_secret():
    env = os.environ.get('FLASK_SECRET')
    if env:
        return env
    if os.path.exists(_SECRET_FILE):
        with open(_SECRET_FILE, 'r') as f:
            return f.read().strip()
    s = secrets.token_hex(32)
    try:
        fd = os.open(_SECRET_FILE, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, 'w') as f:
            f.write(s)
    except FileExistsError:
        with open(_SECRET_FILE, 'r') as f:
            return f.read().strip()
    return s


app.secret_key = _get_flask_secret()
app.permanent_session_lifetime = timedelta(minutes=30)

# За обратным прокси (nginx/Traefik) IP и схему берём из X-Forwarded-*.
# Включать только когда приложение доступно ИСКЛЮЧИТЕЛЬНО через доверенный прокси.
try:
    _trusted_proxy_count = int(os.environ.get('TRUSTED_PROXY_COUNT', '0'))
except (TypeError, ValueError):
    _trusted_proxy_count = 0
if _trusted_proxy_count > 0:
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=_trusted_proxy_count,
                            x_proto=_trusted_proxy_count, x_host=_trusted_proxy_count,
                            x_port=_trusted_proxy_count)

app.config.update(
    WTF_CSRF_TIME_LIMIT=None,
    WTF_CSRF_SSL_STRICT=False,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    SESSION_COOKIE_SECURE=os.environ.get('HTTPS', '0') == '1',
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=30),
    MAX_CONTENT_LENGTH=12 * 1024 * 1024,
)
csrf = CSRFProtect(app)

SERVER_HOST = os.environ.get('SERVER_HOST', '127.0.0.1')
SERVER_PORT = int(os.environ.get('SERVER_PORT', 5000))
# Общий секрет с бэкендом: нужен, только когда app.py подключается не с loopback.
INTERNAL_API_SECRET = os.environ.get('INTERNAL_API_SECRET', '')
SOCKET_TIMEOUT = 8
MAX_RESPONSE_BYTES = 10 * 1024 * 1024
HEADER_SIZE = 4
TLS_CA = os.environ.get('TLS_CA')


@app.before_request
def set_language():
    lang = request.args.get('lang')
    if lang in ('ru', 'en'):
        session['lang'] = lang
        parts = urlsplit(request.full_path)
        qs = [(k, v) for k, v in parse_qsl(parts.query) if k != 'lang']
        target = parts.path + ('?' + urlencode(qs) if qs else '')
        response = app.make_response(redirect(target))
        response.set_cookie('lang', lang, max_age=31536000, httponly=True, samesite='Lax')
        return response
    if 'lang' not in session:
        cookie_lang = request.cookies.get('lang')
        if cookie_lang in ('ru', 'en'):
            session['lang'] = cookie_lang
        else:
            session['lang'] = 'ru'
    if session.get('user'):
        session.modified = True


_ALLOWED_API_WHEN_MUST_CHANGE = {
    '/api/change_own_password',
    '/api/ping',
    '/api/public_settings',
}


@app.before_request
def enforce_must_change_password():
    if request.path.startswith('/static'):
        return None
    if request.path in ('/login', '/logout', '/', '/dashboard'):
        return None
    if request.path.startswith('/share/') or request.path.startswith('/print/'):
        return None
    user = session.get('user')
    if user and user.get('must_change_password'):
        if request.path.startswith('/api/'):
            if request.path in _ALLOWED_API_WHEN_MUST_CHANGE:
                return None
            return jsonify({'status': 'error', 'message': 'Необходимо сменить пароль!',
                            'code': 'MUST_CHANGE_PWD'}), 403
        return redirect('/dashboard')
    return None


def _api_token_from_request():
    header = request.headers.get('Authorization', '')
    if header.lower().startswith('bearer '):
        return header[7:].strip()
    return request.headers.get('X-API-Token', '').strip()


# Браузерные запросы защищены CSRF-токеном. Внешние вызовы с API-токеном
# не имеют сессии и не могут получить CSRF-токен — для них проверка не нужна:
# сам токен является секретом и проверяется в authenticate_api_token().
_original_csrf_protect = csrf.protect


def _csrf_protect(*args, **kwargs):
    if request.path.startswith('/api/') and _api_token_from_request():
        g.csrf_valid = True
        return None
    return _original_csrf_protect(*args, **kwargs)


csrf.protect = _csrf_protect


@app.before_request
def authenticate_api_token():
    """API-токены работают без браузерной сессии: меняем токен на сессию бэкенда."""
    if not request.path.startswith('/api/'):
        return None
    token = _api_token_from_request()
    if not token:
        return None
    res = FixedClient().send_request({'action': 'api_token_auth', 'token': token})
    if res.get('status') != 'success':
        return jsonify({'status': 'error', 'message': res.get('message', 'Недействительный API-токен')}), 401
    g.api_session_id = res['session_id']
    g.api_user = res['user']
    return None


@app.context_processor
def inject_globals():
    lang = session.get('lang', 'ru')
    rates = {'RUB': 1.0, 'USD': 0.0105, 'EUR': 0.0095}
    return {'t': lambda key: get_text(lang, key), 'current_lang': lang, 'rates': rates}


class FixedClient:
    def __init__(self, host=SERVER_HOST, port=SERVER_PORT):
        self.host, self.port = host, port

    def send_request(self, request_data, session_id_override=None):
        sock = None
        try:
            # Служебные поля задаёт сервер приложения, клиент не может их подменить.
            if session_id_override is not None:
                request_data['session_id'] = session_id_override
            elif 'session_id' in session:
                request_data['session_id'] = session['session_id']
            else:
                request_data.pop('session_id', None)
            if INTERNAL_API_SECRET:
                request_data['internal_secret'] = INTERNAL_API_SECRET
            try:
                if request.remote_addr:
                    request_data['client_ip'] = request.remote_addr
                else:
                    request_data.pop('client_ip', None)
                request_data['user_agent'] = (request.headers.get('User-Agent', '') or '')[:300]
            except RuntimeError:
                request_data.pop('client_ip', None)
                request_data.pop('user_agent', None)
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(SOCKET_TIMEOUT)
            if TLS_CA:
                import ssl
                ctx = ssl.create_default_context(cafile=TLS_CA)
                sock = ctx.wrap_socket(sock, server_hostname=self.host)
            sock.connect((self.host, self.port))
            json_str = json.dumps(request_data, ensure_ascii=False, separators=(',', ':'))
            payload = json_str.encode('utf-8')
            sock.sendall(struct.pack('>I', len(payload)) + payload)
            header = self._recv_exact(sock, HEADER_SIZE)
            if header is None:
                return {'status': 'error', 'message': 'Сервер закрыл соединение'}
            length = struct.unpack('>I', header)[0]
            if length <= 0 or length > MAX_RESPONSE_BYTES:
                return {'status': 'error', 'message': 'Некорректная длина ответа'}
            body = self._recv_exact(sock, length)
            if body is None:
                return {'status': 'error', 'message': 'Неполный ответ'}
            if not body:
                return {'status': 'error', 'message': 'Пустой ответ'}
            res = json.loads(body.decode('utf-8'))
            if isinstance(res, dict) and res.get('message') == 'Сессия истекла':
                res['_session_expired'] = True
            return res
        except socket.timeout:
            return {'status': 'error', 'message': 'Превышено время ожидания'}
        except ConnectionRefusedError:
            return {'status': 'error', 'message': 'Backend не запущен'}
        except Exception:
            traceback.print_exc()
            return {'status': 'error', 'message': 'Сетевая ошибка'}
        finally:
            if sock:
                try:
                    sock.close()
                except:
                    pass

    @staticmethod
    def _recv_exact(sock, n):
        buf = b''
        while len(buf) < n:
            chunk = sock.recv(n - len(buf))
            if not chunk:
                return None
            buf += chunk
        return buf


def _check_session_expired(res):
    if isinstance(res, dict) and res.get('_session_expired'):
        session.clear()
        return True
    return False


_branding_cache = {'data': None, 'ts': 0}
_BRANDING_TTL = 60


def _hex_rgb(value):
    digits = str(value or '').lstrip('#')
    if len(digits) != 6:
        return '79, 70, 229'
    try:
        return ', '.join(str(int(digits[i:i + 2], 16)) for i in (0, 2, 4))
    except ValueError:
        return '79, 70, 229'


def _default_theme():
    return {'brand': '#4f46e5', 'brand2': '#8b5cf6', 'company': 'NK Secure', 'logo_text': 'NK', 'logo_url': '',
            'radius_card': '16', 'radius_modal': '24', 'font': 'Outfit', 'theme_default': 'system', 'custom_css': '',
            'brand_rgb': '79, 70, 229', 'brand2_rgb': '124, 58, 237'}


def _safe_hex(value, default):
    value = str(value or '').strip()
    return value if re.fullmatch(r'#[0-9a-fA-F]{6}', value) else default


def _safe_number(value, default, low, high):
    try:
        number = int(str(value).strip())
    except (TypeError, ValueError):
        return default
    return str(number) if low <= number <= high else default


def _safe_css(value):
    return str(value or '')[:20000].replace('<', '').replace('>', '')


def _get_theme():
    now = time.time()
    if _branding_cache['data'] and (now - _branding_cache['ts']) < _BRANDING_TTL:
        return _branding_cache['data']
    res = FixedClient().send_request({'action': 'get_public_settings'})
    if res.get('status') == 'success':
        data = res.get('data', {})
        theme = _default_theme()
        font = str(data.get('font') or 'Outfit')
        logo_url = str(data.get('logo_url') or '')
        if not re.fullmatch(r'[A-Za-z0-9 ,\-]+', font):
            font = 'Outfit'
        if logo_url and not re.match(r'^https?://', logo_url, re.I):
            logo_url = ''
        theme.update({
            'brand': _safe_hex(data.get('brand'), theme['brand']),
            'brand2': _safe_hex(data.get('brand2'), theme['brand2']),
            'company': str(data.get('company') or theme['company'])[:200],
            'logo_text': str(data.get('logo_text') or '')[:200],
            'logo_url': logo_url[:500],
            'radius_card': _safe_number(data.get('radius_card'), '16', 0, 200),
            'radius_modal': _safe_number(data.get('radius_modal'), '24', 0, 200),
            'font': font[:200],
            'theme_default': data.get('theme_default') if data.get('theme_default') in ('system', 'light', 'dark') else 'system',
            'custom_css': _safe_css(data.get('custom_css')),
        })
        theme['brand_rgb'] = _hex_rgb(theme['brand'])
        theme['brand2_rgb'] = _hex_rgb(theme['brand2'])
        _branding_cache['data'] = theme
        _branding_cache['ts'] = now
        return theme
    _branding_cache['ts'] = now
    return _branding_cache['data'] or _default_theme()


@app.context_processor
def inject_theme():
    lang = session.get('lang', 'ru')
    edition_label = license.edition_label()
    if lang != 'ru' and ' (до ' in edition_label:
        edition, _, _tail = edition_label.partition(' (до ')
        edition_label = f"{edition} (up to {license.max_users()} users)"
    return {
        'theme': _get_theme(),
        'sso': sso.public_info(),
        'license': {
            'edition': license.snapshot().get('edition', 'free'),
            'label': edition_label,
            'has_branding': license.has_feature('branding'),
            'features': license.feature_flags(),
            'max_users': license.max_users(),
            'is_free': license.is_free(),
            'is_grace': license.is_grace(),
            'days_left': license.days_left(),
            'grace_days_left': license.grace_days_left(),
            'expires_at': license.snapshot().get('expires_at'),
            'validation': license.validation_status()
        }
    }


@app.route('/robots.txt')
def robots_txt():
    # Приватное приложение: поисковым системам нечего здесь индексировать.
    return Response('User-agent: *\nDisallow: /\n', mimetype='text/plain',
                    headers={'Cache-Control': 'no-store'})


@app.route('/manifest.json')
def dynamic_manifest():
    theme = _get_theme()
    manifest = {'name': theme['company'], 'short_name': theme['company'][:12], 'start_url': '/dashboard',
                'display': 'standalone', 'background_color': '#f8fafc', 'theme_color': theme['brand'],
                'icons': [{'src': '/static/icon-192.png', 'sizes': '192x192', 'type': 'image/png'},
                          {'src': '/static/icon-512.png', 'sizes': '512x512', 'type': 'image/png'}]}
    return Response(json.dumps(manifest, ensure_ascii=False), mimetype='application/manifest+json',
                    headers={'Cache-Control': 'no-store'})


@app.errorhandler(CSRFError)
def handle_csrf_error(e):
    if request.path.startswith('/api/'):
        return jsonify({'status': 'error', 'message': 'CSRF-токен недействителен'}), 400
    return render_template('error.html', error='Ошибка безопасности', error_code=400), 400


@app.errorhandler(Exception)
def handle_exception(e):
    if hasattr(e, 'code'):
        return e
    traceback.print_exc()
    if request.path.startswith('/api/'):
        return jsonify({'status': 'error', 'message': 'Внутренняя ошибка'}), 500
    return render_template('error.html', error='Внутренняя ошибка', error_code=500), 500


@app.route('/static/<path:filename>')
def static_files(filename):
    return send_from_directory('static', filename)


@app.route('/')
def index():
    return redirect('/login')


def _check_origin():
    """Проверка Origin/Referer для login (CSRF-защита)."""
    origin = request.headers.get('Origin') or request.headers.get('Referer') or ''
    if not origin:
        # Некоторые браузеры не шлют Referer — разрешаем только GET
        return request.method == 'GET'
    try:
        o = urlsplit(origin)
        h = urlsplit(request.host_url)
        return (o.scheme, o.netloc) == (h.scheme, h.netloc)
    except Exception:
        return False


@app.route('/login', methods=['GET', 'POST'])
@csrf.exempt
def login():
    pending = session.get('pending_2fa')
    if request.method == 'POST':
        if not _check_origin():
            flash('Ошибка безопасности: неверный источник запроса', 'danger')
            return render_template('login.html'), 403

        code = request.form.get('totp_code', '').strip()
        if pending and code:
            res = FixedClient().send_request({'action': 'verify_totp',
                                              'user_id': pending.get('user_id'), 'code': code,
                                              'login_token': pending.get('login_token', '')})
            if res.get('status') == 'success':
                session.clear()
                session['user'] = res['user']
                session['session_id'] = res['session_id']
                session.permanent = True
                return redirect('/dashboard')
            flash(f'Ошибка 2FA: {res.get("message")}', 'danger')
            return render_template('login.html', totp_required=True, pending_username=pending.get('username'))

        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        res = FixedClient().send_request({'action': 'login', 'username': username, 'password': password})
        if res.get('status') == 'success':
            session.clear()
            session['user'] = res['user']
            session['session_id'] = res['session_id']
            session.permanent = True
            return redirect('/dashboard')
        if res.get('status') == 'totp_required':
            session.clear()
            session['pending_2fa'] = {
                'user_id': res.get('user_id'),
                'username': res.get('username') or username,
                'login_token': res.get('login_token', ''),
            }
            return render_template('login.html', totp_required=True,
                                   pending_username=res.get('username') or username)
        flash(f'Ошибка входа: {res.get("message")}', 'danger')
    return render_template('login.html', totp_required=bool(pending),
                           pending_username=(pending or {}).get('username'))


def _finish_external_login(res):
    """Общая обработка результата входа через LDAP/OIDC."""
    if res.get('status') == 'success':
        session.clear()
        session['user'] = res['user']
        session['session_id'] = res['session_id']
        session.permanent = True
        return redirect('/dashboard')
    if res.get('status') == 'totp_required':
        session.clear()
        session['pending_2fa'] = {'user_id': res.get('user_id'),
                                  'username': res.get('username') or '',
                                  'login_token': res.get('login_token', '')}
        return render_template('login.html', totp_required=True,
                               pending_username=session['pending_2fa']['username'])
    flash(f'Ошибка входа: {res.get("message", "неизвестная ошибка")}', 'danger')
    return render_template('login.html'), 403


@app.route('/login/ldap', methods=['POST'])
@csrf.exempt
def ldap_login():
    if not _check_origin():
        flash('Ошибка безопасности: неверный источник запроса', 'danger')
        return render_template('login.html'), 403
    cfg = sso.config()
    if not cfg or cfg['mode'] != 'ldap':
        return render_template('error.html', error='LDAP не настроен', error_code=404), 404
    ok, identity = sso.ldap_login(request.form.get('username', '').strip(),
                                  request.form.get('password', ''), cfg)
    if not ok:
        flash(identity.get('message', 'Ошибка LDAP'), 'danger')
        return render_template('login.html'), 403
    res = FixedClient().send_request({'action': 'sso_login', 'provider': 'ldap', 'identity': identity})
    return _finish_external_login(res)


@app.route('/login/oidc')
def oidc_login():
    cfg = sso.config()
    if not cfg or cfg['mode'] != 'oidc':
        return render_template('error.html', error='OIDC не настроен', error_code=404), 404
    state = secrets.token_urlsafe(24)
    verifier = secrets.token_urlsafe(40)
    session['oidc_state'] = state
    session['oidc_verifier'] = verifier
    try:
        target = sso.oidc_authorization_url(state, verifier, cfg)
    except RuntimeError as exc:
        flash(str(exc), 'danger')
        return redirect('/login')
    return redirect(target)


@app.route('/login/oidc/callback')
def oidc_callback():
    cfg = sso.config()
    if not cfg or cfg['mode'] != 'oidc':
        return render_template('error.html', error='OIDC не настроен', error_code=404), 404
    state = request.args.get('state', '')
    expected = session.pop('oidc_state', '')
    verifier = session.pop('oidc_verifier', '')
    code = request.args.get('code', '')
    if request.args.get('error'):
        flash(f'Ошибка провайдера: {request.args.get("error")}', 'danger')
        return redirect('/login')
    ok, identity = sso.oidc_callback(code, state, expected, verifier, cfg)
    if not ok:
        flash(identity.get('message', 'Ошибка OIDC'), 'danger')
        return redirect('/login')
    res = FixedClient().send_request({'action': 'sso_login', 'provider': 'oidc', 'identity': identity})
    return _finish_external_login(res)


@app.route('/logout')
def logout():
    if 'session_id' in session:
        FixedClient().send_request({'action': 'logout', 'session_id': session['session_id']})
    session.clear()
    return redirect('/login')


@app.route('/dashboard')
def dashboard():
    if 'user' not in session:
        return redirect('/login')
    return render_template('dashboard.html', user=session['user'])


@app.route('/admin')
def admin():
    user = session.get('user')
    if not user or user.get('role') not in ('admin', 'manager'):
        return redirect('/dashboard')
    if user.get('must_change_password'):
        return redirect('/dashboard')
    return render_template('admin.html', user=user)


@app.route('/logs')
def logs_page():
    user = session.get('user')
    if not user or user.get('role') not in ('admin', 'manager'):
        return redirect('/dashboard')
    if user.get('must_change_password'):
        return redirect('/dashboard')
    return render_template('logs.html', user=user)


@app.route('/trash')
def trash_page():
    user = session.get('user')
    if not user:
        return redirect('/login')
    if user.get('must_change_password'):
        return redirect('/dashboard')
    return render_template('trash.html', user=user)


@app.route('/security')
def security_page():
    user = session.get('user')
    if not user:
        return redirect('/login')
    return render_template('security.html', user=user)


@app.route('/share/<token>')
def share_page(token):
    meta = FixedClient().send_request({'action': 'get_share_meta', 'token': token})
    if meta.get('status') == 'success' and meta.get('data', {}).get('password_required'):
        resp = app.make_response(render_template('share_view.html', requires_password=True, token=token,
                                                 service_name=meta['data'].get('service_name', '')))
        resp.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
        return resp
    res = FixedClient().send_request({'action': 'get_shared', 'token': token})
    if res.get('status') == 'success':
        resp = app.make_response(render_template('share_view.html', data=res['data']))
        resp.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
        return resp
    flash(res.get('message', 'Ссылка недействительна'), 'danger')
    return redirect('/login')


@app.route('/api/share_unlock', methods=['POST'])
def api_share_unlock():
    d = request.json or {}
    return _proxy('get_shared', {'token': d.get('token', ''), 'password': d.get('password', '')})


@app.route('/print/passwords')
def print_passwords():
    user = session.get('user')
    if not user:
        return redirect('/login')
    if user.get('must_change_password'):
        return redirect('/dashboard')
    res = FixedClient().send_request({'action': 'get_passwords'})
    if res.get('status') != 'success':
        return redirect('/dashboard')
    from datetime import datetime
    lang = session.get('lang', 'ru')
    resp = app.make_response(render_template('print_passwords.html', user=user, passwords=res.get('data', []),
                                             now=datetime.now().strftime('%d.%m.%Y %H:%M'), theme=_get_theme(),
                                             current_lang=lang, t=lambda key: get_text(lang, key)))
    resp.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
    resp.headers['Pragma'] = 'no-cache'
    return resp


_RESERVED_FIELDS = {'action', 'session_id', 'client_ip', 'user_agent'}


def _clean_payload(payload):
    if not isinstance(payload, dict):
        return {}
    return {k: v for k, v in payload.items() if k not in _RESERVED_FIELDS}


def _session_override():
    return getattr(g, 'api_session_id', None)


def _proxy(action_name, payload=None, session_id_override=None):
    data = {'action': action_name}
    if payload:
        data.update(_clean_payload(payload))
    res = FixedClient().send_request(data, session_id_override=session_id_override or _session_override())
    if _check_session_expired(res):
        return jsonify({'status': 'error', 'message': 'Сессия истекла', 'redirect': '/login'}), 401
    return jsonify(res)


@app.route('/api/public_settings')
def api_public_settings():
    theme = _get_theme()
    theme['sso'] = sso.public_info()
    resp = jsonify({'status': 'success', 'data': theme})
    resp.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
    return resp


@app.route('/api/ping')
def api_ping():
    return _proxy('ping')


@app.route('/api/passwords')
def api_get_passwords():
    return _proxy('get_passwords', {'filter_type': request.args.get('filter_type', 'all')})


@app.route('/api/add_password', methods=['POST'])
def api_add_password():
    d = request.json or {}
    return _proxy('add_password', {'service_name': d.get('service_name'), 'username': d.get('username'),
                                   'password': d.get('password'), 'url': d.get('url'), 'notes': d.get('notes'),
                                   'category': d.get('category', 'Без категории'),
                                   'expires_at': d.get('expires_at')})


@app.route('/api/update_password', methods=['POST'])
def api_update_password():
    return _proxy('update_password', request.json or {})


@app.route('/api/delete_password/<int:pid>', methods=['DELETE'])
def api_delete_password(pid):
    return _proxy('delete_password', {'id': pid})


@app.route('/api/restore_password/<int:pid>', methods=['POST'])
def api_restore_password(pid):
    return _proxy('restore_password', {'id': pid})


@app.route('/api/purge_password/<int:pid>', methods=['DELETE'])
def api_purge_password(pid):
    return _proxy('purge_password', {'id': pid})


@app.route('/api/trash')
def api_get_trash():
    return _proxy('get_trash')


@app.route('/api/toggle_pin/<int:pid>', methods=['POST'])
def api_toggle_pin(pid):
    return _proxy('toggle_pin', {'id': pid})


@app.route('/api/mark_used/<int:pid>', methods=['POST'])
def api_mark_used(pid):
    return _proxy('mark_used', {'id': pid})


@app.route('/api/mark_leaked/<int:pid>', methods=['POST'])
def api_mark_leaked(pid):
    d = request.json or {}
    return _proxy('mark_leaked', {'id': pid, 'leaked': bool(d.get('leaked'))})


@app.route('/api/get_history/<int:pid>')
def api_get_history(pid):
    return _proxy('get_history', {'id': pid})


@app.route('/api/create_share/<int:pid>', methods=['POST'])
def api_create_share(pid):
    d = request.json or {}
    return _proxy('create_share', {'id': pid, 'hours': d.get('hours', 24),
                                   'password': d.get('password', ''),
                                   'max_views': d.get('max_views', 0),
                                   'one_time': bool(d.get('one_time'))})


@app.route('/api/import_passwords', methods=['POST'])
def api_import_passwords():
    # Импорт/экспорт доступны на всех тарифах.
    d = request.json or {}
    return _proxy('import_passwords', {'passwords': d.get('passwords', [])})


@app.route('/api/export')
def api_export():
    filter_type = request.args.get('filter_type', 'all')
    if filter_type not in ('all', 'leaks', 'old'):
        filter_type = 'all'
    fmt = request.args.get('format', 'csv')
    if fmt not in ('csv', 'json'):
        fmt = 'csv'
    res = FixedClient().send_request({'action': 'export_passwords', 'filter_type': filter_type},
                                     session_id_override=_session_override())
    if _check_session_expired(res):
        # csrfFetch распознаёт такой ответ и сам перенаправляет на /login.
        return jsonify({'status': 'error', 'message': 'Сессия истекла', 'redirect': '/login'}), 401
    if res.get('status') != 'success':
        return jsonify(res), 400
    data = res.get('data', [])
    stamp = time.strftime('%Y%m%d_%H%M%S')
    if fmt == 'json':
        payload = json.dumps({'exported_at': time.strftime('%Y-%m-%dT%H:%M:%S'), 'passwords': data},
                             ensure_ascii=False, indent=2)
        return Response(payload, mimetype='application/json',
                        headers={'Content-Disposition': f'attachment; filename=passwords_{stamp}.json',
                                 'Cache-Control': 'no-store'})
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['service_name', 'username', 'password', 'url', 'notes', 'category'])
    for p in data:
        writer.writerow([p.get('service_name', ''), p.get('username', ''), p.get('password', ''),
                         p.get('url', ''), p.get('notes', ''), p.get('category', '')])
    return Response(output.getvalue(), mimetype='text/csv',
                    headers={'Content-Disposition': f'attachment; filename=passwords_{stamp}.csv',
                             'Cache-Control': 'no-store'})


@app.route('/api/stats')
def api_get_stats():
    return _proxy('get_stats')


@app.route('/api/users')
def api_get_users():
    return _proxy('get_users')


@app.route('/api/user_details/<int:uid>')
def api_get_user_details(uid):
    return _proxy('get_user_details', {'id': uid})


@app.route('/api/update_user', methods=['POST'])
def api_update_user():
    d = request.json or {}
    return _proxy('update_user', {'id': d.get('id'), 'names': d.get('names'), 'role': d.get('role'),
                                  'is_active': d.get('is_active')})


@app.route('/api/add_user', methods=['POST'])
def api_add_user():
    return _proxy('add_user', request.json or {})


@app.route('/api/import_users', methods=['POST'])
def api_import_users():
    d = request.json or {}
    return _proxy('import_users', {'users': d.get('users', [])})


@app.route('/api/transfer_passwords', methods=['POST'])
def api_transfer_passwords():
    d = request.json or {}
    return _proxy('transfer_passwords', {'from_id': d.get('from_id'), 'to_id': d.get('to_id')})


@app.route('/api/all_passwords_admin')
def api_all_passwords_admin():
    return _proxy('get_all_passwords_admin', {'filter_type': request.args.get('filter_type', 'all')})


@app.route('/api/bans')
def api_get_bans():
    return _proxy('get_bans')


@app.route('/api/unban', methods=['POST'])
def api_unban():
    d = request.json or {}
    return _proxy('unban_ip', {'ip': d.get('ip')})


def _logs_payload(args, limit=None):
    payload = {k: args.get(k) for k in
               ('user_id', 'action', 'ip', 'date_from', 'date_to')
               if args.get(k) is not None}
    if 'action' in payload:
        payload['action_filter'] = payload.pop('action')
    if limit is not None:
        payload['limit'] = limit
    return payload


@app.route('/api/logs')
def api_get_logs():
    return _proxy('get_logs', _logs_payload(request.args))


@app.route('/api/logs/export')
def api_export_logs():
    res = FixedClient().send_request({'action': 'get_logs', **_logs_payload(request.args, 10000)},
                                      session_id_override=_session_override())
    if _check_session_expired(res):
        return jsonify({'status': 'error', 'message': 'Сессия истекла', 'redirect': '/login'}), 401
    if res.get('status') != 'success':
        return jsonify(res), 400
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['created_at', 'user', 'action', 'details', 'ip'])
    for row in res.get('data', []):
        writer.writerow([row.get('created_at', ''), row.get('username', '') or 'system',
                         row.get('action', ''), row.get('details', ''), row.get('ip', '')])
    stamp = time.strftime('%Y%m%d_%H%M%S')
    return Response(output.getvalue(), mimetype='text/csv',
                    headers={'Content-Disposition': f'attachment; filename=logs_{stamp}.csv',
                             'Cache-Control': 'no-store'})


@app.route('/api/vaults')
def api_get_vaults():
    return _proxy('get_vaults')


@app.route('/api/vault_details/<int:vid>')
def api_vault_details(vid):
    return _proxy('get_vault_details', {'id': vid})


@app.route('/api/create_vault', methods=['POST'])
def api_create_vault():
    d = request.json or {}
    return _proxy('create_vault', {'name': d.get('name')})


@app.route('/api/update_vault', methods=['POST'])
def api_update_vault():
    d = request.json or {}
    return _proxy('update_vault', {'id': d.get('id'), 'members': d.get('members'),
                                   'passwords': d.get('passwords')})


@app.route('/api/settings')
def api_get_settings():
    return _proxy('get_settings')


@app.route('/api/save_settings', methods=['POST'])
def api_save_settings():
    d = request.json or {}
    return _proxy('save_settings', {'min_pwd_len': d.get('min_pwd_len'),
                                    'max_pwd_age_days': d.get('max_pwd_age_days')})


@app.route('/api/save_branding', methods=['POST'])
def api_save_branding():
    user = session.get('user')
    if not user or user.get('role') != 'admin':
        return jsonify({'status': 'error', 'message': 'Только администратор может менять брендинг'}), 403
    res = FixedClient().send_request({'action': 'save_branding', **_clean_payload(request.json or {})},
                                     session_id_override=_session_override())
    if _check_session_expired(res):
        return jsonify({'status': 'error', 'message': 'Сессия истекла', 'redirect': '/login'}), 401
    if res.get('status') == 'success':
        _branding_cache['data'] = None
        _branding_cache['ts'] = 0
    return jsonify(res)


@app.route('/api/delete_user/<int:uid>', methods=['DELETE'])
def api_delete_user(uid):
    return _proxy('delete_user', {'id': uid})


@app.route('/api/change_own_password', methods=['POST'])
def api_change_own_password():
    res = FixedClient().send_request({'action': 'change_own_password', **_clean_payload(request.json or {})},
                                     session_id_override=_session_override())
    if _check_session_expired(res):
        return jsonify({'status': 'error', 'message': 'Сессия истекла', 'redirect': '/login'}), 401
    if res.get('status') == 'success' and 'user' in session:
        session['user']['must_change_password'] = False
        session.modified = True
    return jsonify(res)


@app.route('/api/reset_user_password', methods=['POST'])
def api_reset_user_password():
    return _proxy('reset_user_password', request.json or {})


@app.route('/api/qr')
def api_qr():
    text = request.args.get('text', '')
    if not text:
        return "No text", 400
    if len(text) > 2000:
        return "Text too long", 413
    # SVG-фабрика не требует Pillow и работает в любой установке.
    from qrcode.image.svg import SvgPathImage
    img = qrcode.make(text, image_factory=SvgPathImage)
    buf = io.BytesIO()
    img.save(buf)
    buf.seek(0)
    resp = send_file(buf, mimetype='image/svg+xml')
    resp.headers['Cache-Control'] = 'no-store'
    return resp


# ---------- Уведомления ----------

@app.route('/api/notifications')
def api_notifications():
    return _proxy('get_notifications', {'limit': request.args.get('limit', 50)})


@app.route('/api/notifications/<int:nid>/read', methods=['POST'])
def api_notification_read(nid):
    return _proxy('mark_notification_read', {'id': nid})


@app.route('/api/notifications/read_all', methods=['POST'])
def api_notifications_read_all():
    return _proxy('mark_all_notifications_read')


# ---------- Центр безопасности / 2FA / токены ----------

@app.route('/api/security_report')
def api_security_report():
    return _proxy('security_report')


@app.route('/api/totp/status')
def api_totp_status():
    return _proxy('totp_status')


@app.route('/api/totp/setup', methods=['POST'])
def api_totp_setup():
    d = request.json or {}
    return _proxy('totp_setup', {'current_code': d.get('current_code', '')})


@app.route('/api/totp/enable', methods=['POST'])
def api_totp_enable():
    d = request.json or {}
    return _proxy('totp_enable', {
        'code': d.get('code', ''),
        'current_code': d.get('current_code', ''),
    })


@app.route('/api/totp/disable', methods=['POST'])
def api_totp_disable():
    d = request.json or {}
    return _proxy('totp_disable', {'code': d.get('code', '')})


@app.route('/api/api_tokens')
def api_list_tokens():
    return _proxy('list_api_tokens')


@app.route('/api/api_tokens', methods=['POST'])
def api_create_token():
    d = request.json or {}
    return _proxy('create_api_token', {'name': d.get('name', 'CLI'), 'days': d.get('days', 30)})


@app.route('/api/api_tokens/<int:tid>', methods=['DELETE'])
def api_revoke_token(tid):
    return _proxy('revoke_api_token', {'id': tid})


# ---------- Шаринг ----------

@app.route('/api/shares')
def api_get_shares():
    return _proxy('get_shares')


@app.route('/api/shares/<int:sid>', methods=['DELETE'])
def api_revoke_share(sid):
    return _proxy('revoke_share', {'id': sid})


@app.route('/api/shares/<int:sid>/access')
def api_share_access(sid):
    return _proxy('get_share_access', {'id': sid})


# ---------- Резервные копии ----------

@app.route('/api/backups')
def api_list_backups():
    return _proxy('list_backups')


@app.route('/api/backups', methods=['POST'])
def api_create_backup():
    return _proxy('create_backup')


@app.route('/api/backups/restore', methods=['POST'])
def api_restore_backup():
    d = request.json or {}
    return _proxy('restore_backup', {'name': d.get('name', '')})


@app.errorhandler(404)
def page_not_found(e):
    return render_template('error.html', error='Не найдено', error_code=404), 404

@app.route('/api/save_order', methods=['POST'])
def api_save_order():
    d = request.json or {}
    return _proxy('save_password_order', {'order': d.get('order', [])})

if __name__ == '__main__':
    if os.environ.get('USE_WAITRESS') == '1':
        from waitress import serve
        serve(app, host='0.0.0.0', port=8000, threads=8)
    else:
        app.run(host='0.0.0.0', port=8000, debug=False, threaded=True, use_reloader=False)