// === JS журнала событий ===

let logsInitialized = false;
function initLogsPage() {
    if (logsInitialized) return;
    logsInitialized = true;
    loadLogUsers();
    loadLogs();
}

document.addEventListener('DOMContentLoaded', initLogsPage);
if (document.readyState === 'complete' || document.readyState === 'interactive') {
    initLogsPage();
}

function translateAction(action) {
    const lang = window.__CURRENT_LANG__ || 'ru';
    if (lang === 'ru') return action;

    const map = {
        'Вход': 'Login',
        'Выход': 'Logout',
        'Неудачный вход': 'Failed Login',
        'Изменение брендинга': 'Branding changed',
        'Добавление пароля': 'Password added',
        'Изменение пароля': 'Password changed',
        'Удаление пароля (в корзину)': 'Password deleted (trash)',
        'Восстановление пароля': 'Password restored',
        'Окончательное удаление пароля': 'Password purged',
        'Закрепление пароля': 'Password pinned',
        'Открепление пароля': 'Password unpinned',
        'Создание пользователя': 'User created',
        'Удаление пользователя': 'User deleted',
        'Редактирование пользователя': 'User updated',
        'Импорт пользователей': 'Users imported',
        'Импорт паролей': 'Passwords imported',
        'Передача паролей': 'Passwords transferred',
        'Смена своего пароля': 'Own password changed',
        'Сброс пароля пользователя': 'User password reset',
        'Создание общей папки': 'Shared folder created',
        'Создание общей ссылки': 'Share link created',
        'Использование общей ссылки': 'Share link used',
        'IP Заблокирован': 'IP banned',
        'Вход (2FA)': 'Login (2FA)',
        'Запрос 2FA': '2FA requested',
        'Включение 2FA': '2FA enabled',
        'Включение/ротация 2FA': '2FA enabled / rotated',
        'Отключение 2FA': '2FA disabled',
        'Вход через SSO': 'SSO login',
        'Смена сервера лицензий': 'License server changed',
        'Создание API-токена': 'API token created',
        'Изменение порядка паролей': 'Password order changed',
        'Общая ссылка создана': 'Share link created',
        'Общая ссылка отозвана': 'Share link revoked',
        'Отзыв общей ссылки': 'Share link revoked',
        'Резервная копия создана': 'Backup created',
        'База восстановлена': 'Database restored',
        'Утечка пароля': 'Password leak',
    };
    return map[action] || action;
}

// Детали журнала хранятся в БД на русском языке — переводим известные шаблоны,
// сохраняя пользовательские значения (имена, IP, идентификаторы) без изменений.
function translateDetails(details) {
    const text = String(details || '');
    if ((window.__CURRENT_LANG__ || 'ru') === 'ru') return text;
    return text
        .replace(/(,\s*)логин:\s*/gi, '$1login: ')
        .replace(/(\d+\s+)неверных попыток/gi, '$1failed attempts')
        .replace(/Провайдер:\s*/gi, 'Provider: ')
        .replace(/,\s*пользователь:\s*/gi, ', user: ')
        .replace(/Пользователь:\s*/gi, 'User: ')
        .replace(/Добавлен\s+/g, 'Added ')
        .replace(/Добавлено:\s*/g, 'Added: ')
        .replace(/Удален\s+/g, 'Deleted ')
        .replace(/с ролью\s+/g, 'with role ')
        .replace(/Сервис:\s*/gi, 'Service: ')
        .replace(/Обновлено:\s*/g, 'Updated: ')
        .replace(/ID пароля:\s*/gi, 'Password ID: ')
        .replace(/^\s*От\s+(\d+)\s+к\s+(\d+)\s*$/i, 'From $1 to $2');
}

function loadLogs() {
    const tbody = document.getElementById('logs-list');
    if (tbody) {
        tbody.innerHTML = `<tr><td colspan="5" class="text-center py-5"><div class="spinner-border text-primary"></div></td></tr>`;
    }

    // ✅ Добавлен таймаут на случай, если сервер "завис"
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 10000);

    const params = new URLSearchParams();
    const f = (id, key) => {
        const el = document.getElementById(id);
        if (el && el.value) params.set(key, el.value);
    };
    f('logUserFilter', 'user_id');
    f('logActionFilter', 'action');
    f('logIpFilter', 'ip');
    f('logDateFrom', 'date_from');
    f('logDateTo', 'date_to');
    const qs = params.toString();

    csrfFetch('/api/logs' + (qs ? '?' + qs : ''), { signal: controller.signal })
        .then(r => r.json())
        .then(res => {
            clearTimeout(timeoutId);
            if (typeof handleMustChange === 'function' && handleMustChange(res)) return;
            if (!tbody) return;

            if (!res || res.status !== 'success') {
                tbody.innerHTML = `<tr><td colspan="5">${emptyStateHtml('exclamation-triangle-fill', res && res.message || window.__T__?.load_error || 'Ошибка загрузки данных', '', true)}</td></tr>`;
                return;
            }

            const data = res.data || [];
            if (!data.length) {
                tbody.innerHTML = `<tr><td colspan="5">${emptyStateHtml('list-ul', window.__T__?.no_logs || 'Нет записей', '', true)}</td></tr>`;
                return;
            }

            tbody.innerHTML = data.map(l => `
                <tr>
                    <td data-label="${escapeAttr(window.__T__?.time || 'Время')}" class="text-muted small">${escapeHtml(l.created_at || '')}</td>
                    <td data-label="${escapeAttr(window.__T__?.user || 'Пользователь')}" class="fw-bold">${escapeHtml(l.username || '—')}</td>
                    <td data-label="${escapeAttr(window.__T__?.action || 'Действие')}">
                        <span class="badge badge-action bg-primary bg-opacity-10 text-primary">${escapeHtml(translateAction(l.action || ''))}</span>
                    </td>
                    <td data-label="${escapeAttr(window.__T__?.details || 'Детали')}" class="text-muted small text-truncate-custom">${escapeHtml(translateDetails(l.details))}</td>
                    <td data-label="IP"><code>${escapeHtml(l.ip || '—')}</code></td>
                </tr>
            `).join('');
        })
        .catch(err => {
            clearTimeout(timeoutId);
            if (err.name === 'AbortError') {
                if (tbody) tbody.innerHTML = `<tr><td colspan="5">${emptyStateHtml('clock-history', window.__T__?.timeout_error || 'Превышено время ожидания ответа', '', true)}</td></tr>`;
                return;
            }
            if (err && err.message === 'redirect') return;
            if (tbody) {
                tbody.innerHTML = `<tr><td colspan="5">${emptyStateHtml('wifi-off', (window.__T__?.network_error || 'Ошибка сети') + ': ' + (err.message || ''), '', true)}</td></tr>`;
            }
        });
}

function loadLogUsers() {
    const select = document.getElementById('logUserFilter');
    if (!select) return;
    csrfFetch('/api/users')
        .then(r => r.json())
        .then(res => {
            if (!res || res.status !== 'success') return;
            const current = select.value;
            select.innerHTML = `<option value="">${escapeHtml(window.__T__?.all_users || 'Все пользователи')}</option>` +
                (res.data || []).map(u => `<option value="${u.id}">${escapeHtml(u.username)}</option>`).join('');
            select.value = current;
        })
        .catch(() => {});
}

function resetLogFilters() {
    ['logUserFilter', 'logActionFilter', 'logIpFilter', 'logDateFrom', 'logDateTo'].forEach(id => {
        const el = document.getElementById(id);
        if (el) el.value = '';
    });
    loadLogs();
}

function exportLogs() {
    const params = new URLSearchParams();
    const f = (id, key) => {
        const el = document.getElementById(id);
        if (el && el.value) params.set(key, el.value);
    };
    f('logUserFilter', 'user_id');
    f('logActionFilter', 'action');
    f('logIpFilter', 'ip');
    f('logDateFrom', 'date_from');
    f('logDateTo', 'date_to');
    const qs = params.toString();
    csrfFetch('/api/logs/export' + (qs ? '?' + qs : ''))
        .then(async r => {
            const type = r.headers.get('Content-Type') || '';
            if (!r.ok || !/text\/csv|application\/csv|application\/octet-stream/i.test(type)) {
                let res = null;
                try { res = await r.json(); } catch (_) {}
                throw new Error((res && res.message) || r.statusText || 'Export failed');
            }
            const blob = await r.blob();
            const url = URL.createObjectURL(blob);
            const link = document.createElement('a');
            link.href = url;
            link.download = 'logs.csv';
            document.body.appendChild(link);
            link.click();
            link.remove();
            setTimeout(() => URL.revokeObjectURL(url), 1000);
        })
        .catch(err => {
            if (err && err.message !== 'redirect') showToast((window.__T__?.error || 'Ошибка') + ': ' + err.message, 'error');
        });
}

window.loadLogs = loadLogs;
window.loadLogUsers = loadLogUsers;
window.resetLogFilters = resetLogFilters;
window.exportLogs = exportLogs;