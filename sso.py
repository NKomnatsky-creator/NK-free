"""Внешняя аутентификация: LDAP и OIDC (authorization code + PKCE).

Оба режима включаются переменными окружения. Модуль не хранит секреты и
не логирует пароли/токены. При отсутствии ldap3 режим LDAP просто недоступен
с понятным сообщением.
"""

import base64
import hashlib
import json
import logging
import os
import re
import secrets
import urllib.parse
import urllib.request
from typing import Optional, Tuple

log = logging.getLogger('sso')

ROLES = ('user', 'manager', 'admin')


def _env(name: str, default: str = '') -> str:
    return str(os.environ.get(name, default) or '').strip()


def _env_list(name: str) -> set:
    return {part.strip().lower() for part in _env(name).split(',') if part.strip()}


def config() -> Optional[dict]:
    mode = _env('SSO_MODE', 'off').lower()
    if mode not in ('ldap', 'oidc'):
        return None
    try:
        ldap_port = int(_env('LDAP_PORT', '389') or 389)
        if not 1 <= ldap_port <= 65535:
            ldap_port = 389
    except (TypeError, ValueError):
        ldap_port = 389
    cfg = {
        'mode': mode,
        'label': _env('SSO_LABEL', 'Корпоративный вход'),
        'admin_groups': _env_list('SSO_ADMIN_GROUPS'),
        'manager_groups': _env_list('SSO_MANAGER_GROUPS'),
        'default_role': _env('SSO_DEFAULT_ROLE', 'user').lower(),
    }
    if cfg['default_role'] not in ROLES:
        cfg['default_role'] = 'user'
    if mode == 'ldap':
        cfg.update({
            'server': _env('LDAP_SERVER'),
            'port': ldap_port,
            'use_tls': _env('LDAP_USE_TLS', '0') == '1',
            'start_tls': _env('LDAP_START_TLS', '0') == '1',
            'allow_insecure': _env('LDAP_ALLOW_INSECURE', '0') == '1',
            'bind_dn': _env('LDAP_BIND_DN'),
            'bind_password': _env('LDAP_BIND_PASSWORD'),
            'base_dn': _env('LDAP_BASE_DN'),
            'user_filter': _env('LDAP_USER_FILTER', '(uid={login})'),
            'user_dn_template': _env('LDAP_USER_DN_TEMPLATE'),
            'attr_username': _env('LDAP_ATTR_USERNAME', 'uid'),
            'attr_email': _env('LDAP_ATTR_EMAIL', 'mail'),
            'attr_name': _env('LDAP_ATTR_NAME', 'displayName'),
            'attr_sub': _env('LDAP_ATTR_SUB', 'objectGUID'),
            'group_filter': _env('LDAP_GROUP_FILTER'),
            'group_attr': _env('LDAP_GROUP_ATTR', 'memberOf'),
        })
    else:
        cfg.update({
            'issuer': _env('OIDC_ISSUER').rstrip('/'),
            'client_id': _env('OIDC_CLIENT_ID'),
            'client_secret': _env('OIDC_CLIENT_SECRET'),
            'redirect_uri': _env('OIDC_REDIRECT_URI'),
            'scopes': _env('OIDC_SCOPES', 'openid profile email'),
            'group_claim': _env('OIDC_GROUP_CLAIM', 'groups'),
        })
    return cfg


def is_enabled() -> bool:
    return config() is not None


def public_info() -> dict:
    cfg = config()
    if not cfg:
        return {'enabled': False, 'mode': None, 'label': ''}
    return {'enabled': True, 'mode': cfg['mode'], 'label': cfg['label']}


def _group_names(value) -> set:
    """Нормализует имя группы; DN LDAP приводится к CN/OU.

    Равенство, а не подстрока: группа `not-admin` не должна давать права `admin`.
    """
    text = str(value or '').strip().lower()
    if not text:
        return set()
    names = {text}
    for part in re.split(r'[;,]', text):
        if '=' in part:
            key, _, val = part.partition('=')
            if key.strip() in ('cn', 'ou'):
                names.add(val.strip())
    names.discard('')
    return names


def role_for(groups, cfg: dict) -> str:
    values = set()
    for group in (groups or []):
        values.update(_group_names(group))
    for role, names in (('admin', cfg.get('admin_groups', set())),
                        ('manager', cfg.get('manager_groups', set()))):
        for expected in names:
            if _group_names(expected) & values:
                return role
    return cfg.get('default_role', 'user')


def _ldap_connection(cfg: dict):
    try:
        from ldap3 import Server, Connection, Tls
        import ssl
    except ImportError:
        raise RuntimeError('Для LDAP установите пакет ldap3: pip install ldap3')

    use_ssl = cfg['use_tls'] or cfg['port'] == 636
    if use_ssl or cfg['start_tls']:
        tls = Tls(validate=ssl.CERT_REQUIRED)
    else:
        if not cfg['allow_insecure']:
            raise RuntimeError('LDAP без TLS запрещён. Включите LDAP_USE_TLS/LDAP_START_TLS '
                               'или LDAP_ALLOW_INSECURE=1 для доверенной сети.')
        tls = None
    server = Server(cfg['server'], port=cfg['port'], use_ssl=use_ssl, tls=tls,
                    connect_timeout=8)
    conn = Connection(server, user=cfg['bind_dn'] or None,
                      password=cfg['bind_password'] or None, auto_bind=True,
                      receive_timeout=8)
    if cfg['start_tls'] and not use_ssl:
        if not conn.start_tls():
            raise RuntimeError('Не удалось включить StartTLS')
    return conn


def ldap_login(username: str, password: str, cfg: Optional[dict] = None) -> Tuple[bool, dict]:
    cfg = cfg or config() or {}
    if not cfg.get('server') or not cfg.get('base_dn'):
        return False, {'message': 'LDAP не настроен'}
    if not username or not password:
        return False, {'message': 'Неверный логин или пароль'}
    try:
        conn = _ldap_connection(cfg)
        from ldap3.utils.conv import escape_filter_chars
        safe_login = escape_filter_chars(username)
        filter_ = cfg['user_filter'].replace('{login}', safe_login)
        conn.search(cfg['base_dn'], filter_, attributes=['dn', cfg['attr_username'],
                                                        cfg['attr_email'], cfg['attr_name'],
                                                        cfg['attr_sub'], cfg['group_attr']])
        if not conn.entries:
            return False, {'message': 'Неверный логин или пароль'}
        entry = conn.entries[0]
        user_dn = entry.entry_dn
        if not conn.rebind(user=user_dn, password=password):
            return False, {'message': 'Неверный логин или пароль'}

        groups = []
        if cfg.get('group_filter'):
            gfilter = (cfg['group_filter'].replace('{user_dn}', escape_filter_chars(user_dn))
                       .replace('{login}', safe_login))
            conn.search(cfg['base_dn'], gfilter, attributes=['dn', 'cn'])
            groups = [str(e.entry_dn) for e in conn.entries]
        else:
            try:
                groups = list(entry[cfg['group_attr']].values)
            except Exception:
                groups = []

        def attr(name, default=''):
            try:
                value = entry[name].value
                return str(value) if value is not None else default
            except Exception:
                return default

        sub = attr(cfg['attr_sub']) or user_dn
        return True, {
            'provider': 'ldap',
            'sub': sub,
            'username': attr(cfg['attr_username'], username) or username,
            'email': attr(cfg['attr_email']),
            'name': attr(cfg['attr_name'], username),
            'role': role_for(groups, cfg),
        }
    except RuntimeError as exc:
        return False, {'message': str(exc)}
    except Exception:
        log.exception('Ошибка LDAP-аутентификации')
        return False, {'message': 'Ошибка подключения к LDAP'}


def _http_json(url: str, data=None, headers=None, timeout=10):
    payload = None
    hdrs = dict(headers or {})
    if data is not None:
        payload = urllib.parse.urlencode(data).encode('utf-8')
        hdrs['Content-Type'] = 'application/x-www-form-urlencoded'
    req = urllib.request.Request(url, data=payload, headers=hdrs)
    with urllib.request.urlopen(req, timeout=timeout) as response:
        return json.loads(response.read().decode('utf-8'))


def oidc_metadata(cfg: Optional[dict] = None) -> dict:
    cfg = cfg or config() or {}
    issuer = cfg.get('issuer')
    if not issuer:
        raise RuntimeError('OIDC не настроен: задайте OIDC_ISSUER')
    cache = _metadata_cache.setdefault(issuer, {})
    if not cache:
        cache.update(_http_json(issuer + '/.well-known/openid-configuration'))
    return cache


_metadata_cache = {}


def oidc_authorization_url(state: str, code_verifier: str, cfg: Optional[dict] = None) -> str:
    cfg = cfg or config() or {}
    if not cfg.get('client_id') or not cfg.get('redirect_uri'):
        raise RuntimeError('OIDC не настроен: задайте OIDC_CLIENT_ID и OIDC_REDIRECT_URI')
    meta = oidc_metadata(cfg)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(code_verifier.encode()).digest()).decode().rstrip('=')
    params = {
        'response_type': 'code',
        'client_id': cfg['client_id'],
        'redirect_uri': cfg['redirect_uri'],
        'scope': cfg['scopes'],
        'state': state,
        'nonce': secrets.token_urlsafe(16),
        'code_challenge': challenge,
        'code_challenge_method': 'S256',
    }
    return meta['authorization_endpoint'] + '?' + urllib.parse.urlencode(params)


def oidc_callback(code: str, state: str, expected_state: str,
                  code_verifier: str, cfg: Optional[dict] = None) -> Tuple[bool, dict]:
    cfg = cfg or config() or {}
    if not code or not state or not secrets.compare_digest(state, expected_state):
        return False, {'message': 'Недействительное состояние OIDC-запроса'}
    try:
        meta = oidc_metadata(cfg)
        token = _http_json(meta['token_endpoint'], {
            'grant_type': 'authorization_code',
            'code': code,
            'redirect_uri': cfg['redirect_uri'],
            'client_id': cfg['client_id'],
            'client_secret': cfg['client_secret'],
            'code_verifier': code_verifier,
        })
        access_token = token.get('access_token')
        if not access_token:
            return False, {'message': 'Провайдер не выдал токен доступа'}
        userinfo = _http_json(meta['userinfo_endpoint'], headers={
            'Authorization': 'Bearer ' + access_token})
        username = str(userinfo.get('preferred_username') or userinfo.get('email') or userinfo.get('sub') or '')
        subject = str(userinfo.get('sub') or '')
        if not subject or not username:
            return False, {'message': 'Провайдер не вернул данные пользователя'}
        groups = userinfo.get(cfg['group_claim'], []) or []
        if isinstance(groups, str):
            groups = [groups]
        return True, {
            'provider': 'oidc',
            'sub': subject,
            'username': username[:100],
            'email': str(userinfo.get('email') or ''),
            'name': str(userinfo.get('name') or username),
            'role': role_for(groups, cfg),
        }
    except Exception:
        log.exception('Ошибка OIDC-аутентификации')
        return False, {'message': 'Ошибка подключения к провайдеру OIDC'}
