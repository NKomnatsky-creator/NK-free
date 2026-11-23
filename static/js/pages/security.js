// === Центр безопасности ===
let securityInitialized = false;
let totpEnabled = false;

function initSecurityPage() {
    if (securityInitialized) return;
    securityInitialized = true;
    loadAll();
}
document.addEventListener('DOMContentLoaded', initSecurityPage);
if (document.readyState === 'complete' || document.readyState === 'interactive') initSecurityPage();

function tr(key, fallback) {
    return (window.__T__ && window.__T__[key]) || fallback || key;
}

function apiJson(url, options) {
    return csrfFetch(url, options).then(r => r.json());
}
function apiPost(url, body) {
    return apiJson(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body || {})
    });
}
function apiDelete(url) {
    return apiJson(url, { method: 'DELETE' });
}
function checkRes(res) {
    if (!res) throw new Error(tr('server_error', 'Сервер не отвечает'));
    if (typeof handleMustChange === 'function' && handleMustChange(res)) return false;
    if (res.status !== 'success') {
        showToast(res.message || tr('error', 'Ошибка'), 'error');
        return false;
    }
    return true;
}
function showSecError(message) {
    const box = document.getElementById('sec-error');
    if (!box) return;
    if (!message) { box.classList.add('d-none'); box.textContent = ''; return; }
    box.textContent = message;
    box.classList.remove('d-none');
}

function loadAll() {
    showSecError('');
    loadReport();
    loadNotifications();
    loadShares();
    loadTokens();
    loadTotpStatus();
}

function switchSecurityTab(id, btn) {
    document.querySelectorAll('.sec-tab').forEach(el => el.style.display = 'none');
    const target = document.getElementById(id);
    if (target) target.style.display = '';
    document.querySelectorAll('[data-sec-tab]').forEach(el => {
        const active = el === btn;
        el.classList.toggle('active', active);
        el.setAttribute('aria-selected', active ? 'true' : 'false');
        el.tabIndex = active ? 0 : -1;
    });
    if (btn) btn.focus({ preventScroll: true });
}

function handleSecurityTabKey(event, btn) {
    const keys = { ArrowRight: 1, ArrowLeft: -1, Home: -1e6, End: 1e6 };
    if (!(event.key in keys)) return;
    event.preventDefault();
    const tabs = [...document.querySelectorAll('[data-sec-tab]')];
    const current = tabs.indexOf(btn);
    if (current < 0 || !tabs.length) return;
    let next;
    if (event.key === 'Home') next = 0;
    else if (event.key === 'End') next = tabs.length - 1;
    else next = (current + keys[event.key] + tabs.length) % tabs.length;
    const tab = tabs[next];
    switchSecurityTab(tab.dataset.secTab, tab);
}

const ISSUE_LABELS = {
    weak: ['Слабый пароль', 'Weak password'],
    duplicate: ['Повторяющийся пароль', 'Duplicate password'],
    leaked: ['Найден в утечке', 'Found in a breach'],
    old: ['Давно не менялся', 'Not changed for a long time'],
    expired: ['Срок действия истёк', 'Expired'],
    no_url: ['Нет ссылки на сайт', 'No website URL']
};
const SEVERITY_LABELS = {
    high: ['Высокая', 'High'], medium: ['Средняя', 'Medium'], low: ['Низкая', 'Low']
};
function localized(pair) {
    const ru = (window.__CURRENT_LANG__ || 'ru') === 'ru';
    return pair ? (ru ? pair[0] : pair[1]) : '';
}

function loadReport() {
    const tbody = document.getElementById('security-issues');
    apiJson('/api/security_report')
        .then(res => {
            if (!checkRes(res)) return;
            const s = res.data.summary || {};
            const set = (id, val) => { const el = document.getElementById(id); if (el) el.textContent = val ?? '0'; };
            set('sec-total', s.total); set('sec-issues', s.issues);
            set('sec-healthy', s.healthy); set('sec-leaked', s.leaked);
            const upd = document.getElementById('security-updated');
            if (upd) upd.textContent = tr('loaded_at', 'Загружено') + ': ' + formatDate(new Date(), { dateStyle: 'short', timeStyle: 'short' });
            if (!tbody) return;
            const issues = res.data.issues || [];
            if (!issues.length) {
                tbody.innerHTML = `<tr><td colspan="4" class="p-0">${emptyStateHtml('check-circle', tr('all_good', 'Всё отлично!'), '', true)}</td></tr>`;
                return;
            }
            tbody.innerHTML = issues.map(i => `
                <tr>
                    <td class="fw-bold">${escapeHtml(i.service_name || '—')}</td>
                    <td class="issue-tag">${escapeHtml(localized(ISSUE_LABELS[i.issue]) || i.issue)}</td>
                    <td class="severity-${escapeAttr(i.severity || 'low')}">${escapeHtml(localized(SEVERITY_LABELS[i.severity]) || i.severity)}</td>
                    <td class="text-end"><a class="btn btn-sm btn-outline-primary" href="/dashboard"><i class="bi bi-pencil"></i></a></td>
                </tr>`).join('');
        })
        .catch(err => {
            if (err && err.message === 'redirect') return;
            if (tbody) tbody.innerHTML = `<tr><td colspan="4" class="text-center text-danger py-4">${escapeHtml(err.message || tr('network_error', 'Ошибка сети'))}</td></tr>`;
        });
}

function loadNotifications() {
    const box = document.getElementById('notifications-list');
    apiJson('/api/notifications?limit=50')
        .then(res => {
            if (!checkRes(res)) return;
            const items = (res.data && res.data.items) || [];
            const unread = (res.data && res.data.unread) || 0;
            const badge = document.getElementById('unreadBadge');
            if (badge) { badge.textContent = unread; badge.style.display = unread ? '' : 'none'; }
            if (!box) return;
            if (!items.length) {
                box.innerHTML = `<div class="text-center text-muted py-4">${escapeHtml(tr('no_notifications', 'Уведомлений нет'))}</div>`;
                return;
            }
            box.innerHTML = items.map(n => `
                <div class="notification-item ${n.is_read ? '' : 'unread'}">
                    <div class="notif-icon"><i class="bi bi-${n.type === 'warning' ? 'exclamation-triangle' : n.type === 'success' ? 'check-circle' : 'info-circle'}"></i></div>
                    <div class="flex-grow-1">
                        <div class="notif-title">${escapeHtml(n.title || '')}</div>
                        <div class="notif-message">${escapeHtml(n.message || '')}</div>
                        <div class="notif-time">${escapeHtml(n.created_at || '')}</div>
                    </div>
                    ${n.is_read ? '' : `<button class="btn btn-sm btn-outline-primary" onclick="markNotificationRead(${n.id})">${escapeHtml(tr('mark_read', 'Прочитано'))}</button>`}
                </div>`).join('');
        })
        .catch(err => {
            if (err && err.message === 'redirect') return;
            showSecError(err.message || tr('network_error', 'Ошибка сети'));
        });
}

function markNotificationRead(id) {
    apiPost(`/api/notifications/${id}/read`)
        .then(res => { if (checkRes(res)) loadNotifications(); })
        .catch(() => showToast(tr('network_error', 'Ошибка сети'), 'error'));
}
function markAllRead() {
    apiPost('/api/notifications/read_all')
        .then(res => {
            if (checkRes(res)) {
                showToast(tr('saved', 'Сохранено'), 'success');
                loadNotifications();
            }
        })
        .catch(() => showToast(tr('network_error', 'Ошибка сети'), 'error'));
}

function loadShares() {
    const tbody = document.getElementById('shares-list');
    if (!tbody) return;
    if (window.__FEATURES__ && window.__FEATURES__.sharing === false) {
        tbody.innerHTML = `<tr><td colspan="5" class="p-0">${emptyStateHtml('lock-fill', tr('sharing_paid', 'Общие ссылки доступны в Standard и выше.'), '', true)}</td></tr>`;
        return;
    }
    apiJson('/api/shares')
        .then(res => {
            if (!checkRes(res)) return;
            const items = res.data || [];
            if (!items.length) {
                tbody.innerHTML = `<tr><td colspan="5" class="p-0">${emptyStateHtml('link-45deg', tr('no_shares', 'Общих ссылок нет'), '', true)}</td></tr>`;
                return;
            }
            tbody.innerHTML = items.map(s => {
                const revoked = !!s.revoked_at;
                const status = revoked
                    ? `<span class="badge bg-secondary">${escapeHtml(tr('revoked', 'Отозвана'))}</span>`
                    : (s.valid === false
                        ? `<span class="badge bg-warning text-dark">${escapeHtml(tr('inactive', 'Неактивна'))}</span>`
                        : `<span class="badge bg-success">${escapeHtml(tr('active', 'Активна'))}</span>`);
                return `<tr>
                    <td class="fw-bold">${escapeHtml(s.service_name || '—')}</td>
                    <td class="small">${escapeHtml(s.expires_at || '')}</td>
                    <td>${escapeHtml(s.views || 0)}${s.max_views ? ' / ' + escapeHtml(s.max_views) : ''}</td>
                    <td>${status}</td>
                    <td class="text-end text-nowrap">
                        <button class="btn btn-sm btn-outline-secondary" onclick="showShareAccess(${s.id})" title="${escapeAttr(tr('access_log', 'Журнал доступа'))}"><i class="bi bi-list-ul"></i></button>
                        ${revoked ? '' : `<button class="btn btn-sm btn-outline-danger" onclick="revokeShare(${s.id})" title="${escapeAttr(tr('revoke', 'Отозвать'))}"><i class="bi bi-x-circle"></i></button>`}
                    </td>
                </tr>`;
            }).join('');
        })
        .catch(err => {
            if (err && err.message === 'redirect') return;
            tbody.innerHTML = `<tr><td colspan="5" class="text-center text-danger py-4">${escapeHtml(err.message || tr('network_error', 'Ошибка сети'))}</td></tr>`;
        });
}

function revokeShare(id) {
    apiDelete(`/api/shares/${id}`)
        .then(res => { if (checkRes(res)) { showToast(tr('saved', 'Сохранено'), 'success'); loadShares(); } })
        .catch(() => showToast(tr('network_error', 'Ошибка сети'), 'error'));
}

function showShareAccess(id) {
    const body = document.getElementById('share-access-body');
    if (body) body.textContent = tr('loading', 'Загрузка...');
    const modal = bootstrap.Modal.getOrCreateInstance(document.getElementById('shareAccessModal'));
    modal.show();
    apiJson(`/api/shares/${id}/access`)
        .then(res => {
            if (!checkRes(res)) return;
            if (!body) return;
            const rows = res.data || [];
            if (!rows.length) { body.textContent = tr('no_logs', 'Нет записей'); return; }
            body.innerHTML = `<div class="table-responsive"><table class="table table-sm mb-0"><thead><tr><th>IP</th><th>User-Agent</th><th>${escapeHtml(tr('status', 'Статус'))}</th><th>${escapeHtml(tr('time', 'Время'))}</th></tr></thead><tbody>` +
                rows.map(r => `<tr><td><code>${escapeHtml(r.ip || '—')}</code></td><td class="small text-muted text-break">${escapeHtml(r.user_agent || '')}</td><td>${r.success ? 'OK' : 'FAIL'}</td><td class="small text-nowrap">${escapeHtml(r.created_at || '')}</td></tr>`).join('') +
                `</tbody></table></div>`;
        })
        .catch(err => { if (body) body.textContent = err.message || tr('network_error', 'Ошибка сети'); });
}

function loadTotpStatus() {
    const box = document.getElementById('totp-status-box');
    apiJson('/api/totp/status')
        .then(res => {
            if (!checkRes(res)) return;
            if (!box) return;
            const enabled = !!(res.data && res.data.enabled);
            totpEnabled = enabled;
            box.innerHTML = enabled
                ? `<span class="badge bg-success"><i class="bi bi-shield-check me-1"></i>${escapeHtml(tr('totp_enabled', '2FA включена'))}</span>`
                : `<span class="badge bg-secondary"><i class="bi bi-shield me-1"></i>${escapeHtml(tr('totp_disabled', '2FA отключена'))}</span>`;
            document.getElementById('totp-current-wrap')?.classList.toggle('d-none', !enabled);
            const label = document.getElementById('totp-setup-label');
            if (label) label.textContent = enabled ? tr('rotate_2fa', 'Ротировать 2FA') : tr('setup_2fa', 'Настроить 2FA');
        })
        .catch(() => { if (box) box.textContent = tr('network_error', 'Ошибка сети'); });
}

function startTotpSetup() {
    const current = (document.getElementById('totp-current-code') || {}).value || '';
    if (totpEnabled && !current) {
        showToast(tr('current_code', 'Текущий код 2FA'), 'warning');
        document.getElementById('totp-current-code')?.focus();
        return;
    }
    apiPost('/api/totp/setup', { current_code: current })
        .then(res => {
            if (!checkRes(res)) return;
            const box = document.getElementById('totp-setup');
            if (!box) return;
            box.classList.remove('d-none');
            const secret = res.data.secret || '';
            document.getElementById('totp-secret').value = secret;
            document.getElementById('totp-qr').src = '/api/qr?text=' + encodeURIComponent(res.data.uri || '');
            document.getElementById('totp-enable-code').focus();
        })
        .catch(() => showToast(tr('network_error', 'Ошибка сети'), 'error'));
}

function enableTotp() {
    const code = (document.getElementById('totp-enable-code') || {}).value || '';
    const current = (document.getElementById('totp-current-code') || {}).value || '';
    apiPost('/api/totp/enable', { code: code, current_code: current })
        .then(res => {
            if (!checkRes(res)) return;
            const codes = res.codes || [];
            const box = document.getElementById('recovery-codes');
            if (box && codes.length) {
                box.classList.remove('d-none');
                document.getElementById('recovery-codes-list').innerHTML = codes
                    .map(c => `<span class="badge bg-light text-dark border me-2 mb-2">${escapeHtml(c)}</span>`).join('');
            }
            showToast(res.message || tr('success', 'Успешно'), 'success');
            loadTotpStatus();
        })
        .catch(() => showToast(tr('network_error', 'Ошибка сети'), 'error'));
}

function disableTotp() {
    const code = (document.getElementById('totp-disable-code') || {}).value || '';
    if (!code) { showToast(tr('fill_required', 'Заполните поле'), 'warning'); return; }
    apiPost('/api/totp/disable', { code: code })
        .then(res => { if (checkRes(res)) { showToast(res.message || tr('success', 'Успешно'), 'success'); loadTotpStatus(); } })
        .catch(() => showToast(tr('network_error', 'Ошибка сети'), 'error'));
}

function loadTokens() {
    const tbody = document.getElementById('tokens-list');
    apiJson('/api/api_tokens')
        .then(res => {
            if (!checkRes(res)) return;
            if (!tbody) return;
            const items = res.data || [];
            if (!items.length) {
                tbody.innerHTML = `<tr><td colspan="5" class="p-0">${emptyStateHtml('key', tr('no_tokens', 'Токенов нет'), '', true)}</td></tr>`;
                return;
            }
            tbody.innerHTML = items.map(t => `
                <tr>
                    <td class="fw-bold">${escapeHtml(t.name || 'CLI')}</td>
                    <td class="small">${escapeHtml(t.created_at || '')}</td>
                    <td class="small">${escapeHtml(t.last_used_at || '—')}</td>
                    <td class="small">${escapeHtml(t.expires_at || tr('never', 'никогда'))}</td>
                    <td class="text-end">${t.is_active
                        ? `<button class="btn btn-sm btn-outline-danger" onclick="revokeToken(${t.id})"><i class="bi bi-x-circle"></i></button>`
                        : `<span class="badge bg-secondary">${escapeHtml(tr('revoked', 'Отозван'))}</span>`}</td>
                </tr>`).join('');
        })
        .catch(err => {
            if (err && err.message === 'redirect') return;
            if (tbody) tbody.innerHTML = `<tr><td colspan="5" class="text-center text-danger py-4">${escapeHtml(err.message || tr('network_error', 'Ошибка сети'))}</td></tr>`;
        });
}

function createToken() {
    const name = (document.getElementById('token-name') || {}).value || 'CLI';
    const days = (document.getElementById('token-days') || {}).value || 30;
    apiPost('/api/api_tokens', { name: name, days: Number(days) })
        .then(res => {
            if (!checkRes(res)) return;
            const box = document.getElementById('new-token-box');
            if (box && res.token) {
                box.classList.remove('d-none');
                document.getElementById('new-token-value').textContent = res.token;
            }
            showToast(tr('token_created', 'Токен создан'), 'success');
            loadTokens();
        })
        .catch(() => showToast(tr('network_error', 'Ошибка сети'), 'error'));
}

function revokeToken(id) {
    apiDelete(`/api/api_tokens/${id}`)
        .then(res => { if (checkRes(res)) { showToast(tr('saved', 'Сохранено'), 'success'); loadTokens(); } })
        .catch(() => showToast(tr('network_error', 'Ошибка сети'), 'error'));
}

Object.assign(window, {
    loadAll, loadReport, loadNotifications, loadShares, loadTokens, loadTotpStatus,
    switchSecurityTab, markNotificationRead, markAllRead, revokeShare, showShareAccess,
    startTotpSetup, enableTotp, disableTotp, createToken, revokeToken
});
