"""Free-заглушка интерфейса лицензирования.

Подменяет enterprise-модуль license.py при экспорте публичной free-сборки.
НЕ делает сетевых запросов, НЕ читает лицензионные файлы, НЕ содержит проверки
подписи и адресов лицензионного сервера. Реализует ровно тот контракт,
 который используют app.py, server.py и шаблоны.
"""

EDITION = 'free'
MAX_USERS = 5
CORE_FEATURES = frozenset({'import', 'export', 'security_center', 'notifications'})
ALL_FEATURES = ('import', 'export', 'security_center', 'notifications',
                'branding', 'backup', 'sharing')


class LicenseServerError(Exception):
    """Оставлен для совместимости сигнатур; во free никогда не вызывается."""


def _refresh_if_needed():
    return None


def snapshot() -> dict:
    return {
        'edition': EDITION,
        'label': 'Free',
        'max_users': MAX_USERS,
        'features': sorted(CORE_FEATURES),
        'is_grace': False,
        'grace_days_left': None,
        'expires_at': None,
    }


def has_feature(name: str) -> bool:
    return name in CORE_FEATURES


def feature_flags() -> dict:
    return {name: has_feature(name) for name in ALL_FEATURES}


def is_free() -> bool:
    return True


def is_grace() -> bool:
    return False


def grace_days_left():
    return None


def days_left():
    return None


def max_users() -> int:
    return MAX_USERS


def edition_label() -> str:
    return f"Free (до {MAX_USERS} чел.)"


def check_user_limit(current_count: int):
    if current_count >= MAX_USERS:
        return False, f"Достигнут лимит тарифа Free ({MAX_USERS} чел.)."
    return True, None


def validation_status() -> dict:
    return {
        'status': 'free',
        'mode': 'free',
        'edition': EDITION,
        'valid': True,
        'reason': '',
        'at': None,
        'at_iso': None,
        'age_seconds': None,
        'ttl': 0,
        'offline_grace': 0,
    }


def reload_license() -> dict:
    return snapshot()


def activate_license(code):
    return {'status': 'error', 'message': 'Free-сборка не поддерживает активацию лицензии.'}


def server_url_info() -> dict:
    return {
        'url': '',
        'urls': [],
        'default': '',
        'source': 'free',
        'config_file': '',
        'validation': validation_status(),
    }


def installation_info() -> dict:
    return {'installation_id': '', 'edition': EDITION}


def parse_server_urls(data):
    return []


def set_server_url(urls):
    return None


def reset_server_url():
    return None


def test_server_url(candidate):
    return {'status': 'error', 'message': 'Free-сборка не использует лицензионный сервер.'}


def probe_server_url(candidate):
    return {'reachable': False, 'status': 'unsupported'}
