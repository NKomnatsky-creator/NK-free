let usersList = [];
let adminPasswords = [];
let vaultsList = [];
let userModalInstance, detailsModalInstance, importUsersModalInstance, vaultModalInstance, vaultAccessModalInstance, viewPwdAdminModalInstance, resetPwdModalInstance;

const CURRENT_USER = window.__USER__ ? window.__USER__.username : '';

/* --- Универсальная сортировка и пагинация таблиц ---------------------- */
const ADMIN_TABLE_PAGE_SIZE = 8;
const adminTables = {
    'admin-pwd-list': { rows: [], page: 1, sortKey: '', sortDir: 1, cols: 6,
        pager: 'admin-pwd-pager', empty: 'no_passwords', render: adminPwdRow },
    'bans-list': { rows: [], page: 1, sortKey: '', sortDir: 1, cols: 4,
        pager: 'bans-pager', empty: 'no_banned_ips', render: banRow },
    'backups-list': { rows: [], page: 1, sortKey: '', sortDir: 1, cols: 3,
        pager: 'backups-pager', empty: 'no_backups', render: backupRow }
};

function compareAdminValues(a, b) {
    if (a === b) return 0;
    if (a === null || a === undefined || a === '') return 1;
    if (b === null || b === undefined || b === '') return -1;
    const na = Number(a), nb = Number(b);
    if (!Number.isNaN(na) && !Number.isNaN(nb) && a !== '' && b !== '') return na - nb;
    return String(a).localeCompare(String(b), currentLocale(), { numeric: true, sensitivity: 'base' });
}

function renderTablePager(cfg, id) {
    const el = document.getElementById(cfg.pager);
    if (!el) return;
    const pages = Math.max(1, Math.ceil(cfg.rows.length / ADMIN_TABLE_PAGE_SIZE));
    const prev = window.__T__?.page_prev || 'Назад';
    const next = window.__T__?.page_next || 'Далее';
    const label = (window.__T__?.page_of || 'Стр. {p} из {t}')
        .replace('{p}', cfg.page).replace('{t}', pages);
    el.innerHTML = `
        <button type="button" data-page="prev" aria-label="${escapeAttr(prev)}" ${cfg.page <= 1 ? 'disabled' : ''}>‹ ${escapeHtml(prev)}</button>
        <span>${escapeHtml(label)}</span>
        <button type="button" data-page="next" aria-label="${escapeAttr(next)}" ${cfg.page >= pages ? 'disabled' : ''}>${escapeHtml(next)} ›</button>
    `;
    el.querySelectorAll('button[data-page]').forEach(btn => {
        btn.addEventListener('click', () => {
            cfg.page += btn.dataset.page === 'next' ? 1 : -1;
            renderAdminTable(id);
        });
    });
}

function renderAdminTable(id) {
    const cfg = adminTables[id];
    const tbody = document.getElementById(id);
    if (!cfg || !tbody) return;
    const rows = cfg.rows.slice();
    if (cfg.sortKey) {
        rows.sort((a, b) => compareAdminValues(a[cfg.sortKey], b[cfg.sortKey]) * cfg.sortDir);
    }
    const pages = Math.max(1, Math.ceil(rows.length / ADMIN_TABLE_PAGE_SIZE));
    if (cfg.page > pages) cfg.page = pages;
    if (cfg.page < 1) cfg.page = 1;

    if (!rows.length) {
        const text = window.__T__?.[cfg.empty] || cfg.empty;
        tbody.innerHTML = `<tr><td colspan="${cfg.cols}" class="p-0">${emptyStateHtml('inbox', text, '', true)}</td></tr>`;
    } else {
        const start = (cfg.page - 1) * ADMIN_TABLE_PAGE_SIZE;
        tbody.innerHTML = rows.slice(start, start + ADMIN_TABLE_PAGE_SIZE).map(cfg.render).join('');
    }
    renderTablePager(cfg, id);
}

function setAdminTableRows(id, rows) {
    const cfg = adminTables[id];
    if (!cfg) return;
    cfg.rows = rows || [];
    cfg.page = 1;
    renderAdminTable(id);
}

function sortAdminTable(th) {
    const tbody = th.closest('.table-responsive')?.querySelector('tbody');
    if (!tbody) return;
    const cfg = adminTables[tbody.id];
    if (!cfg) return;
    const key = th.dataset.sort;
    cfg.sortDir = cfg.sortKey === key ? -cfg.sortDir : 1;
    cfg.sortKey = key;
    cfg.page = 1;
    th.parentElement.querySelectorAll('th[data-sort]').forEach(other => {
        other.setAttribute('aria-sort', other === th
            ? (cfg.sortDir === 1 ? 'ascending' : 'descending') : 'none');
    });
    renderAdminTable(tbody.id);
}

document.addEventListener('click', (e) => {
    const th = e.target.closest('th[data-sort]');
    if (th) sortAdminTable(th);
});

document.addEventListener('keydown', (e) => {
    if (e.key !== 'Enter' && e.key !== ' ') return;
    const th = e.target.closest('th[data-sort]');
    if (!th) return;
    e.preventDefault();
    sortAdminTable(th);
});

const BRANDING_DEFAULTS = {
    brand: '#6366f1',
    brand2: '#8b5cf6',
    company: 'NK Secure',
    logo_text: 'NK',
    logo_url: '',
    radius_card: '16',
    radius_modal: '24',
    font: 'Outfit',
    theme_default: 'system',
    custom_css: '',
};

function saveActiveTab(tabId) { try { localStorage.setItem('admin_active_tab', tabId); } catch(e) {} }

function restoreActiveTab() {
    let savedTab = null;
    try { savedTab = localStorage.getItem('admin_active_tab'); } catch(e) {}
    let targetTabId = savedTab || 'tab-users';
    // ✅ fallback, если вкладки нет (например, branding при Free-лицензии)
    if (!document.getElementById(targetTabId)) targetTabId = 'tab-users';
    const targetContent = document.getElementById(targetTabId);
    if (!targetContent) return;
    document.querySelectorAll('.admin-nav-item').forEach(i => i.classList.remove('active'));
    document.querySelectorAll('.tab-content').forEach(t => t.classList.remove('active'));
    const navItem = document.querySelector(`.admin-nav-item[data-tab="${targetTabId}"]`);
    if (navItem) navItem.classList.add('active');
    targetContent.classList.add('active');
}

let isAdminInitialized = false;
function initAdminPage() {
    if (isAdminInitialized) return;
    if (typeof bootstrap === 'undefined') {
        setTimeout(initAdminPage, 100);
        return;
    }
    isAdminInitialized = true;
    userModalInstance = new bootstrap.Modal(document.getElementById('userModal'));
    detailsModalInstance = new bootstrap.Modal(document.getElementById('detailsModal'));
    importUsersModalInstance = new bootstrap.Modal(document.getElementById('importUsersModal'));
    vaultModalInstance = new bootstrap.Modal(document.getElementById('vaultModal'));
    vaultAccessModalInstance = new bootstrap.Modal(document.getElementById('vaultAccessModal'));
    viewPwdAdminModalInstance = new bootstrap.Modal(document.getElementById('viewPwdAdminModal'));
    resetPwdModalInstance = new bootstrap.Modal(document.getElementById('resetPwdModal'));

    restoreActiveTab();
    loadStats();
    loadUsers();
    loadAdminPasswords();
    loadVaults();
    loadBans();
    loadBackups();
    loadSettings();
    if (document.getElementById('brand_brand_color')) loadBranding();
}

document.addEventListener('DOMContentLoaded', initAdminPage);
if (document.readyState === 'complete' || document.readyState === 'interactive') {
    initAdminPage();
}

let pwdSearchTimer;
document.addEventListener('DOMContentLoaded', () => {
    const el = document.getElementById('pwdSearch');
    if (el) el.addEventListener('input', () => {
        clearTimeout(pwdSearchTimer);
        pwdSearchTimer = setTimeout(loadAdminPasswords, 180);
    });

    const roleMenu = document.getElementById('userRoleMenu');
    const roleBtnLabel = document.getElementById('userRoleLabel');
    const hiddenRoleInput = document.getElementById('userRole');

    if (roleMenu && roleBtnLabel && hiddenRoleInput) {
        roleMenu.addEventListener('click', (e) => {
            const item = e.target.closest('.dropdown-item');
            if (!item) return;
            e.preventDefault();
            hiddenRoleInput.value = item.dataset.value;
            roleBtnLabel.textContent = item.textContent;
        });
    }
});

function switchTab(tabId, el) {
    document.querySelectorAll('.admin-nav-item').forEach(i => i.classList.remove('active'));
    document.querySelectorAll('.tab-content').forEach(t => t.classList.remove('active'));
    if(el) el.classList.add('active');
    const tabContent = document.getElementById(tabId);
    if(tabContent) tabContent.classList.add('active');
    saveActiveTab(tabId);
}

function loadStats() {
    csrfFetch('/api/stats').then(r => r.json()).then(data => {
        if (data.status === 'success') {
            document.getElementById('stat-users').textContent = data.data.users_count;
            document.getElementById('stat-passwords').textContent = data.data.passwords_count;
            document.getElementById('stat-leaks').textContent = data.data.leaks;
            document.getElementById('stat-db').textContent = data.data.db_size_kb + ' KB';
        }
    });
}

function loadUsers() {
    csrfFetch('/api/users').then(r => r.json()).then(data => {
        if (data.status === 'success') { usersList = data.data; filterUsers(); }
    });
}

function localizeUserName(names) {
    const legacy = {'Администратор': 'role_admin', 'Менеджер': 'role_manager', 'Сотрудник': 'role_user'};
    const key = legacy[names];
    return key && window.__T__?.[key] ? window.__T__[key] : (names || '—');
}

function localizeRole(role) {
    const keys = {admin: 'role_admin', manager: 'role_manager', user: 'role_user'};
    const key = keys[role];
    return key && window.__T__?.[key] ? window.__T__[key] : (role || '');
}

function filterUsers() {
    const q = document.getElementById('userSearch').value.toLowerCase();
    const role = document.getElementById('userRoleFilter').value;
    const list = document.getElementById('users-list');
    const filtered = usersList.filter(u =>
        (u.username.toLowerCase().includes(q) || (u.names||'').toLowerCase().includes(q)) &&
        (!role || u.role === role)
    );
    document.getElementById('users-loading').style.display = 'none';
    if (!filtered.length) {
        list.innerHTML = emptyStateHtml('people', q ? (window.__T__?.nothing_found || 'Ничего не найдено') : (window.__T__?.no_users || 'Пользователей нет'), '', true);
        return;
    }
    list.innerHTML = filtered.map(u => `
        <div class="user-card p-3 d-flex flex-column flex-md-row justify-content-between align-items-md-center gap-3 flex-wrap">
            <div class="d-flex align-items-center gap-3 w-100">
                <div class="rounded-circle bg-base d-flex align-items-center justify-content-center" style="width:48px;height:48px;flex-shrink:0;"><i class="bi bi-person fs-5 text-muted"></i></div>
                <div class="flex-grow-1 min-w-0">
                    <h3 class="fs-6 mb-1 fw-bold d-flex align-items-center gap-2 flex-wrap">
                        ${escapeHtml(u.username)}
                        ${u.role === 'admin' ? `<span class="status-chip status-chip--danger">${window.__T__.role_admin}</span>` : u.role === 'manager' ? `<span class="status-chip status-chip--warning">${window.__T__.role_manager}</span>` : `<span class="status-chip status-chip--active">${window.__T__.role_user}</span>`}
                        ${!u.is_active ? `<span class="status-chip status-chip--muted">${window.__T__.blocked}</span>` : ''}
                    </h3>
                    <div class="text-muted small text-truncate">${escapeHtml(localizeUserName(u.names))}</div>
                </div>
            </div>
            <div class="d-flex gap-2 w-100 w-md-auto justify-content-end mt-2 mt-md-0">
                <button class="action-btn" onclick="showUserDetails(${u.id})" title="${window.__T__?.details || 'Details'}"><i class="bi bi-info-circle"></i></button>
                <button class="action-btn" onclick="editUser(${u.id})" title="${window.__T__.edit}"><i class="bi bi-pencil"></i></button>
                ${u.username !== CURRENT_USER ? `<button class="action-btn text-danger" onclick="deleteUser(${u.id})"><i class="bi bi-trash"></i></button>` : ''}
            </div>
        </div>
    `).join('');
}

function showUserDetails(id) {
    csrfFetch(`/api/user_details/${id}`).then(r => r.json()).then(res => {
        if(res.status !== 'success') return;
        const d = res.data;
        document.getElementById('detailsBody').innerHTML = `
            <h4 class="fw-bold mb-1">${escapeHtml(d.user.username)}</h4>
            <p class="text-muted small mb-4">${escapeHtml(localizeUserName(d.user.names))} • ${escapeHtml(localizeRole(d.user.role))}</p>
            <div class="row g-3 mb-4">
                <div class="col-6"><div class="p-3 bg-base rounded text-center"><div class="fs-4 fw-bold">${d.passwords_count}</div><small>${window.__T__.passwords}</small></div></div>
                <div class="col-6"><div class="p-3 bg-base rounded text-center"><div class="fs-4 fw-bold ${d.fails_24h > 0 ? 'text-danger' : ''}">${d.fails_24h}</div><small>${window.__T__.failed_attempts || 'Ошибок входа'}</small></div></div>
            </div>
            <h6 class="fw-bold mb-3">${window.__T__.recent_actions || 'Последние действия'}</h6>
            <div class="timeline">
                ${d.logs.map(l => `<div class="timeline-item"><div class="small text-muted">${escapeHtml(l.created_at)}</div><div class="fw-bold">${escapeHtml(l.action)}</div><div class="small">${escapeHtml(l.details)}</div></div>`).join('') || `<p class="text-muted">${window.__T__.no_logs || 'Нет логов'}</p>`}
            </div>
        `;
        detailsModalInstance.show();
    });
}

function loadAdminPasswords() {
    const filter = document.getElementById('pwdFilter').value;
    csrfFetch(`/api/all_passwords_admin?filter_type=${filter}`).then(r => r.json()).then(res => {
        if (handleMustChange(res)) return;
        if(res.status === 'success') {
            adminPasswords = res.data;
            const q = document.getElementById('pwdSearch').value.toLowerCase();
            const filtered = adminPasswords.filter(p =>
                (p.service_name || '').toLowerCase().includes(q) ||
                (p.username || '').toLowerCase().includes(q) ||
                (p.created_by_name || '').toLowerCase().includes(q)
            );
            setAdminTableRows('admin-pwd-list', filtered);
        }
    });
}

function adminPwdRow(p) {
    return `
        <tr>
            <td data-label="${window.__T__.service}" class="fw-bold">${escapeHtml(p.service_name)}</td>
            <td data-label="${window.__T__.owner}">${escapeHtml(p.created_by_name || p.created_by || '')}</td>
            <td data-label="${window.__T__.login}">${escapeHtml(p.username)}</td>
            <td data-label="${window.__T__.category}"><span class="status-chip status-chip--muted">${escapeHtml(p.category)}</span></td>
            <td data-label="${window.__T__.updated}" class="text-muted small">${escapeHtml(formatDate((p.last_modified_at || '').split(' ')[0], { dateStyle: 'medium' }))}</td>
            <td>
                <button class="btn btn-sm btn-outline-secondary w-100 w-md-auto"
                        data-pwd="${escapeAttr(p.password || '')}"
                        data-service="${escapeAttr(p.service_name || '')}"
                        onclick="viewAdminPwd(this)">
                    <i class="bi bi-eye me-1"></i> ${window.__T__.show || 'Показать'}
                </button>
            </td>
        </tr>
    `;
}

function viewAdminPwd(btn) {
    document.getElementById('vpService').textContent = btn.dataset.service || '';
    document.getElementById('vpPassword').value = btn.dataset.pwd || '';
    viewPwdAdminModalInstance.show();
}

function loadBans() {
    csrfFetch('/api/bans').then(r => r.json()).then(res => {
        if(res.status === 'success') {
            setAdminTableRows('bans-list', res.data);
        }
    });
}

function banRow(b) {
    return `
        <tr>
            <td data-label="IP" class="fw-bold"><code>${escapeHtml(b.ip)}</code></td>
            <td data-label="${window.__T__.attempts}">${formatNumber(b.attempts)}</td>
            <td data-label="${window.__T__.banned_until}" class="text-muted small">${escapeHtml(formatDate(b.banned_until, { dateStyle: 'medium', timeStyle: 'short' }))}</td>
            <td><button class="btn btn-sm btn-success w-100" data-ip="${escapeAttr(b.ip)}" onclick="unban(this.dataset.ip)">${window.__T__.unban}</button></td>
        </tr>
    `;
}

function unban(ip) {
    csrfFetch('/api/unban', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ip})})
    .then(r=>r.json()).then(res => { if(res.status==='success') { showToast(window.__T__.success, 'success'); loadBans(); } });
}

function backupRow(b) {
    return `
        <tr>
            <td class="fw-bold small"><code>${escapeHtml(b.name || '')}</code></td>
            <td class="text-muted small">${escapeHtml(formatDate(b.created_at, { dateStyle: 'medium', timeStyle: 'short' }))} · ${escapeHtml(formatNumber(b.size_kb || 0))} KB</td>
            <td class="text-end"><button class="btn btn-sm btn-outline-danger" data-name="${escapeAttr(b.name || '')}" onclick="restoreBackup(this.dataset.name)"><i class="bi bi-arrow-counterclockwise me-1"></i>${escapeHtml(window.__T__.restore_backup || 'Восстановить')}</button></td>
        </tr>`;
}

function setBackupMessage(text, icon) {
    const tbody = document.getElementById('backups-list');
    const pager = document.getElementById('backups-pager');
    if (pager) pager.innerHTML = '';
    if (tbody) tbody.innerHTML = `<tr><td colspan="3" class="p-0">${emptyStateHtml(icon || 'archive', text, '', true)}</td></tr>`;
}

function loadBackups() {
    if (!document.getElementById('backups-list')) return;
    if (window.__FEATURES__ && window.__FEATURES__.backup === false) {
        setBackupMessage(window.__T__.backup_paid || 'Резервные копии доступны в Standard и выше.', 'lock-fill');
        return;
    }
    csrfFetch('/api/backups')
        .then(r => r.json())
        .then(res => {
            if (!res || res.status !== 'success') {
                setBackupMessage((res && res.message) || window.__T__.error || 'Ошибка', 'exclamation-triangle-fill');
                return;
            }
            setAdminTableRows('backups-list', res.data || []);
        })
        .catch(err => {
            if (err && err.message === 'redirect') return;
            setBackupMessage(err.message || window.__T__.network_error || 'Ошибка сети', 'wifi-off');
        });
}

function createBackup() {
    const btn = document.querySelector('[onclick="createBackup()"]');
    const original = btn ? btn.innerHTML : '';
    if (btn) { btn.disabled = true; btn.innerHTML = '<span class="spinner-border spinner-border-sm me-1"></span>...'; }
    csrfFetch('/api/backups', { method: 'POST' })
        .then(r => r.json())
        .then(res => {
            if (!res || res.status !== 'success') throw new Error((res && res.message) || window.__T__.error || 'Ошибка');
            showToast(res.message || window.__T__.success || 'Успешно', 'success');
            loadBackups();
        })
        .catch(err => {
            if (err && err.message !== 'redirect') showToast(window.__T__.error + ': ' + err.message, 'error');
        })
        .finally(() => { if (btn) { btn.disabled = false; btn.innerHTML = original; } });
}

function restoreBackup(name) {
    if (!confirm(window.__T__.restore_backup_confirm || 'Восстановить базу из этой копии?')) return;
    csrfFetch('/api/backups/restore', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name: name })
    })
        .then(r => r.json())
        .then(res => {
            if (!res || res.status !== 'success') throw new Error((res && res.message) || window.__T__.error || 'Ошибка');
            showToast(res.message || window.__T__.success || 'Успешно', 'success');
        })
        .catch(err => {
            if (err && err.message !== 'redirect') showToast(window.__T__.error + ': ' + err.message, 'error');
        });
}

function loadSettings() {
    csrfFetch('/api/settings').then(r => r.json()).then(res => {
        if(res.status === 'success') {
            document.getElementById('setMinLen').value = res.data.min_pwd_len;
            document.getElementById('setMaxAge').value = res.data.max_pwd_age_days;
        }
    });
}

function saveSettings() {
    const min_pwd_len = document.getElementById('setMinLen').value;
    const max_pwd_age_days = document.getElementById('setMaxAge').value;
    csrfFetch('/api/save_settings', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({min_pwd_len, max_pwd_age_days})})
    .then(r=>r.json()).then(res => { if(res.status==='success') showToast(window.__T__.saved, 'success'); else showToast(window.__T__.error + ': ' + res.message, 'error'); });
}

function loadVaults() {
    csrfFetch('/api/vaults').then(r=>r.json()).then(res => {
        if(res.status === 'success') {
            vaultsList = res.data;
            const vaultsEl = document.getElementById('vaults-list');
            if (!vaultsList.length) {
                vaultsEl.innerHTML = `<div class="col-12">${emptyStateHtml('folder-symlink', window.__T__?.no_vaults || 'Общих хранилищ нет')}</div>`;
                return;
            }
            vaultsEl.innerHTML = vaultsList.map(v => `
                <div class="col-12 col-md-6 col-xl-4">
                    <div class="vault-card p-3 h-100">
                        <div class="d-flex justify-content-between mb-2">
                            <h5 class="fw-bold mb-0 text-truncate"><i class="bi bi-folder-fill text-warning me-2"></i>${escapeHtml(v.name)}</h5>
                            <button class="action-btn flex-shrink-0" onclick="openVaultAccess(${v.id})"><i class="bi bi-gear"></i></button>
                        </div>
                        <div class="text-muted small mb-2">${window.__T__.created_by || 'Создал'}: ${escapeHtml(v.creator)}</div>
                        <div class="d-flex gap-3 small flex-wrap">
                            <span class="badge bg-base text-muted border"><i class="bi bi-people"></i> ${v.members_count} ${window.__T__.users || 'чел.'}</span>
                            <span class="badge bg-base text-muted border"><i class="bi bi-key"></i> ${v.pwd_count} ${window.__T__.passwords || 'пар.'}</span>
                        </div>
                    </div>
                </div>
            `).join('');
        }
    });
}

function openCreateVaultModal() { document.getElementById('vaultName').value = ''; vaultModalInstance.show(); }

function createVault() {
    const name = document.getElementById('vaultName').value;
    if(!name) return;
    csrfFetch('/api/create_vault', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({name})})
    .then(r=>r.json()).then(res => { if(res.status==='success') { vaultModalInstance.hide(); loadVaults(); } });
}

function openVaultAccess(id) {
    document.getElementById('accessVaultId').value = id;
    csrfFetch(`/api/vault_details/${id}`).then(r=>r.json()).then(res => {
        if(res.status !== 'success') return;
        const members = res.data.members;
        const pwds = res.data.passwords;
        document.getElementById('access-users-list').innerHTML = usersList.map(u => `
            <div class="form-check mb-2">
                <input class="form-check-input" type="checkbox" value="${u.id}" id="vm_${u.id}" ${members.includes(u.id)?'checked':''}>
                <label class="form-check-label" for="vm_${u.id}">${escapeHtml(u.username)}</label>
            </div>
        `).join('');
        csrfFetch('/api/all_passwords_admin').then(r=>r.json()).then(pres => {
            if(pres.status === 'success') {
                document.getElementById('access-pwds-list').innerHTML = pres.data.map(p => `
                    <div class="form-check mb-2">
                        <input class="form-check-input" type="checkbox" value="${p.id}" id="vp_${p.id}" ${pwds.includes(p.id)?'checked':''}>
                        <label class="form-check-label" for="vp_${p.id}">${escapeHtml(p.service_name)} (${escapeHtml(p.created_by_name || '')})</label>
                    </div>
                `).join('');
            }
        });
        vaultAccessModalInstance.show();
    });
}

function saveVaultAccess() {
    const id = document.getElementById('accessVaultId').value;
    const members = [...document.querySelectorAll('#access-users-list input:checked')].map(el => parseInt(el.value));
    const passwords = [...document.querySelectorAll('#access-pwds-list input:checked')].map(el => parseInt(el.value));
    csrfFetch('/api/update_vault', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({id, members, passwords})})
    .then(r=>r.json()).then(res => { if(res.status==='success') { vaultAccessModalInstance.hide(); showToast(window.__T__.saved, 'success'); loadVaults(); } });
}

function editUser(id) {
    const u = usersList.find(x => x.id === id); if(!u) return;
    document.getElementById('editUserId').value = u.id;
    document.getElementById('userName').value = u.username;
    document.getElementById('userName').disabled = true;
    document.getElementById('userNames').value = u.names;

    const hiddenRoleInput = document.getElementById('userRole');
    const roleBtnLabel = document.getElementById('userRoleLabel');
    if (hiddenRoleInput && roleBtnLabel) {
        hiddenRoleInput.value = u.role;
        const menuItem = document.querySelector(`#userRoleMenu [data-value="${u.role}"]`);
        if (menuItem) roleBtnLabel.textContent = menuItem.textContent;
    }

    document.getElementById('userActive').checked = u.is_active;
    document.getElementById('pwdField').style.display = 'none';
    document.getElementById('activeField').style.display = 'block';

    document.getElementById('resetPwdBtnWrap').style.display = 'block';

    document.getElementById('userModalTitle').textContent = window.__T__.edit;
    userModalInstance.show();
}

function openUserModal() {
    document.getElementById('userForm').reset();
    document.getElementById('editUserId').value = '';
    document.getElementById('userName').disabled = false;
    document.getElementById('pwdField').style.display = 'block';
    document.getElementById('activeField').style.display = 'none';

    document.getElementById('resetPwdBtnWrap').style.display = 'none';

    const hiddenRoleInput = document.getElementById('userRole');
    const roleBtnLabel = document.getElementById('userRoleLabel');
    if (hiddenRoleInput && roleBtnLabel) {
        hiddenRoleInput.value = 'user';
        roleBtnLabel.textContent = window.__T__.role_user || 'Сотрудник';
    }

    document.getElementById('userModalTitle').textContent = window.__T__.add_user;
    userModalInstance.show();
}

function submitUser() {
    const id = document.getElementById('editUserId').value;
    const payload = {
        username: document.getElementById('userName').value,
        names: document.getElementById('userNames').value,
        role: document.getElementById('userRole').value,
    };
    if(id) {
        payload.id = id;
        payload.is_active = document.getElementById('userActive').checked ? 1 : 0;
        csrfFetch('/api/update_user', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify(payload)})
        .then(r=>r.json()).then(res => {
            if(res.status==='success') { userModalInstance.hide(); loadUsers(); }
            else showToast(window.__T__.error + ': ' + res.message, 'error');
        });
    } else {
        const pwd = document.getElementById('userPasswordInput').value;
        if (!pwd || pwd.length < 8) {
            showToast(window.__T__?.password_min_length || 'Пароль должен быть не менее 8 символов', 'error');
            return;
        }
        payload.password = pwd;
        csrfFetch('/api/add_user', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify(payload)})
        .then(r=>r.json()).then(res => {
            if(res.status==='success') { userModalInstance.hide(); loadUsers(); }
            else showToast(window.__T__.error + ': ' + res.message, 'error');
        });
    }
}

function deleteUser(id) {
    const user = usersList.find(u => u.id === id);
    const template = window.__T__?.confirm_delete_target || 'Удалить «{name}»? Это действие нельзя отменить.';
    if (!confirm(template.replace('{name}', user ? user.username : '#' + id))) return;
    csrfFetch(`/api/delete_user/${id}`, {method:'DELETE'}).then(r=>r.json()).then(res => { if(res.status==='success') loadUsers(); });
}

function openImportUsersModal() { importUsersModalInstance.show(); }

function parseCSVLine(line) {
    const out = [];
    let cur = '', inQ = false;
    for (let i = 0; i < line.length; i++) {
        const ch = line[i];
        if (ch === '"') {
            if (inQ && line[i + 1] === '"') { cur += '"'; i++; }
            else inQ = !inQ;
        } else if (ch === ',' && !inQ) {
            out.push(cur); cur = '';
        } else {
            cur += ch;
        }
    }
    out.push(cur);
    return out;
}

function importUsers() {
    const file = document.getElementById('csvUsersInput').files[0];
    if(!file) return;
    const reader = new FileReader();
    reader.onload = e => {
        const lines = e.target.result.split(/\r?\n/).filter(l => l.trim());
        const users = [];
        for(let i=1; i<lines.length; i++) {
            const row = parseCSVLine(lines[i]);
            if(row[0]) users.push({username: row[0].trim(), names: row[1]?.trim(), role: row[2]?.trim() || 'user'});
        }
        csrfFetch('/api/import_users', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({users})})
        .then(r=>r.json()).then(res => {
            importUsersModalInstance.hide();
            showToast(res.message, res.status === 'success' ? 'success' : 'error');
            loadUsers();
        });
    };
    reader.readAsText(file);
}

function loadBranding() {
    const url = '/api/public_settings?nocache=' + Math.random();
    fetch(url, { cache: 'no-store' })
        .then(r => r.json())
        .then(res => {
            const data = (res.status === 'success' && res.data) ? res.data : BRANDING_DEFAULTS;
            fillBrandingForm(data);
            updateLivePreview();
        })
        .catch(() => {
            fillBrandingForm(BRANDING_DEFAULTS);
            updateLivePreview();
        });
}

function fillBrandingForm(data) {
    const set = (id, val) => { const el = document.getElementById(id); if (el) el.value = val || ''; };
    set('brand_company_name', data.company || BRANDING_DEFAULTS.company);

    const c1 = data.brand || BRANDING_DEFAULTS.brand;
    set('brand_brand_color', c1);
    set('brand_brand_color_hex', c1);

    const c2 = data.brand2 || BRANDING_DEFAULTS.brand2;
    set('brand_brand_color_2', c2);
    set('brand_brand_color_2_hex', c2);

    set('brand_radius_card', data.radius_card || BRANDING_DEFAULTS.radius_card);
    set('brand_radius_modal', data.radius_modal || BRANDING_DEFAULTS.radius_modal);
    set('brand_font_family', data.font || BRANDING_DEFAULTS.font);
    set('brand_theme_default', data.theme_default || BRANDING_DEFAULTS.theme_default);
    set('brand_logo_text', data.logo_text || '');
    set('brand_logo_url', data.logo_url || '');
    set('brand_custom_css', data.custom_css || '');
}

function syncHex(field) {
    const hexInput = document.getElementById(`brand_${field}_hex`);
    const colorInput = document.getElementById(`brand_${field}`);
    let val = (hexInput.value || '').trim();
    if (!val.startsWith('#')) val = '#' + val;
    if (/^#[0-9a-fA-F]{6}$/.test(val)) {
        colorInput.value = val.toLowerCase();
        updateLivePreview();
    }
}

function hexToRgb(hex) {
    if (!/^#[0-9a-fA-F]{6}$/.test(hex)) return '99, 102, 241';
    const r = parseInt(hex.slice(1, 3), 16);
    const g = parseInt(hex.slice(3, 5), 16);
    const b = parseInt(hex.slice(5, 7), 16);
    return `${r}, ${g}, ${b}`;
}

function updateLivePreview() {
    const brand = document.getElementById('brand_brand_color')?.value || BRANDING_DEFAULTS.brand;
    const brand2 = document.getElementById('brand_brand_color_2')?.value || BRANDING_DEFAULTS.brand2;
    const radiusCard = document.getElementById('brand_radius_card')?.value || '16';
    const radiusModal = document.getElementById('brand_radius_modal')?.value || '24';
    const font = document.getElementById('brand_font_family')?.value || 'Outfit';
    const company = document.getElementById('brand_company_name')?.value || 'PassVault';
    const logoText = document.getElementById('brand_logo_text')?.value || '';
    const logoUrl = document.getElementById('brand_logo_url')?.value || '';

    const pv1 = document.getElementById('preview_brand_color');
    if (pv1) pv1.style.background = brand;
    const pv2 = document.getElementById('preview_brand_color_2');
    if (pv2) pv2.style.background = brand2;

    const hex1 = document.getElementById('brand_brand_color_hex');
    if (hex1) hex1.value = brand;
    const hex2 = document.getElementById('brand_brand_color_2_hex');
    if (hex2) hex2.value = brand2;

    const root = document.documentElement;
    root.style.setProperty('--brand', brand);
    root.style.setProperty('--brand-rgb', hexToRgb(brand));
    root.style.setProperty('--brand-2', brand2);
    root.style.setProperty('--brand-2-rgb', hexToRgb(brand2));
    root.style.setProperty('--brand-light', `rgba(${hexToRgb(brand)}, 0.15)`);
    root.style.setProperty('--radius-card', radiusCard + 'px');
    root.style.setProperty('--radius-modal', radiusModal + 'px');
    root.style.setProperty('--font-main', `'${font}', sans-serif`);
    document.body.style.fontFamily = `'${font}', sans-serif`;

    const logoEl = document.getElementById('preview_logo');
    if (logoEl) {
        logoEl.innerHTML = '';
        if (logoUrl) {
            const img = document.createElement('img');
            img.src = logoUrl;
            img.alt = '';
            img.onerror = function() { this.style.display = 'none'; };
            logoEl.appendChild(img);
        } else if (logoText) {
            const span = document.createElement('span');
            span.className = 'fw-bold';
            span.style.fontSize = '0.85rem';
            span.textContent = logoText;
            logoEl.appendChild(span);
        } else {
            logoEl.innerHTML = '<i class="bi bi-shield-lock-fill"></i>';
        }
    }

    const companyEl = document.getElementById('preview_company');
    if (companyEl) companyEl.textContent = company || 'PassVault';
}

function saveBranding() {
    const payload = {
        company_name: document.getElementById('brand_company_name').value.trim(),
        brand_color: document.getElementById('brand_brand_color').value,
        brand_color_2: document.getElementById('brand_brand_color_2').value,
        radius_card: document.getElementById('brand_radius_card').value,
        radius_modal: document.getElementById('brand_radius_modal').value,
        font_family: document.getElementById('brand_font_family').value,
        theme_default: document.getElementById('brand_theme_default').value,
        logo_text: document.getElementById('brand_logo_text').value.trim(),
        logo_url: document.getElementById('brand_logo_url').value.trim(),
        custom_css: (document.getElementById('brand_custom_css') || {}).value || '',
    };

    if (!payload.company_name) { showToast(window.__T__.fill_required, 'error'); return; }
    if (!/^#[0-9a-fA-F]{6}$/.test(payload.brand_color)) { showToast(window.__T__.invalid_color, 'error'); return; }
    if (!/^#[0-9a-fA-F]{6}$/.test(payload.brand_color_2)) { showToast(window.__T__.invalid_color, 'error'); return; }
    if (payload.logo_url && !/^https?:\/\//i.test(payload.logo_url)) {
        showToast(window.__T__.invalid_url, 'error'); return;
    }

    const btn = document.getElementById('saveBrandingBtn');
    btn.disabled = true;
    btn.innerHTML = '<span class="spinner-border spinner-border-sm me-1"></span>...';

    csrfFetch('/api/save_branding', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify(payload)
    }).then(r => r.json()).then(res => {
        btn.disabled = false;
        btn.innerHTML = `<i class="bi bi-check-lg me-1"></i> ${window.__T__.save}`;

        if (res.status === 'success') {
            showToast(window.__T__.saved, 'success');
            setTimeout(() => window.location.reload(), 800);
        } else {
            showToast(window.__T__.error + ': ' + res.message, 'error');
        }
    }).catch(err => {
        btn.disabled = false;
        btn.innerHTML = `<i class="bi bi-check-lg me-1"></i> ${window.__T__.save}`;
        if (err && err.message === 'redirect') return;
        showToast(window.__T__.network_error + ': ' + err.message, 'error');
    });
}

function resetBranding() {
    if (!confirm(window.__T__.confirm_reset || 'Сбросить?')) return;
    fillBrandingForm(BRANDING_DEFAULTS);
    updateLivePreview();
    showToast(window.__T__.reset_done || 'Форма сброшена.', 'info');
}

function openResetPwdModal() {
    const id = document.getElementById('editUserId').value;
    const username = document.getElementById('userName').value;

    document.getElementById('resetPwdUserId').value = id;
    document.getElementById('resetPwdUserName').textContent = username;
    document.getElementById('resetNewPassword').value = '';

    resetPwdModalInstance.show();
}

function generateRandomPwd() {
    const chars = 'abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789!@#$%^&*';
    let pwd = '';
    const arr = new Uint32Array(12);
    crypto.getRandomValues(arr);
    for (let i = 0; i < 12; i++) {
        pwd += chars.charAt(arr[i] % chars.length);
    }
    document.getElementById('resetNewPassword').value = pwd;
}

function submitResetPassword() {
    const userId = document.getElementById('resetPwdUserId').value;
    const newPwd = document.getElementById('resetNewPassword').value;

    if (!newPwd || newPwd.length < 8) {
        showToast(window.__T__?.password_min_length || 'Пароль должен быть не менее 8 символов', 'error');
        return;
    }

    const btn = document.querySelector('#resetPwdModal .btn-danger');
    const originalText = btn.textContent;
    btn.disabled = true;
    btn.innerHTML = '<span class="spinner-border spinner-border-sm me-1"></span>...';

    csrfFetch('/api/reset_user_password', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({ user_id: parseInt(userId, 10), new_password: newPwd })
    }).then(r => r.json()).then(res => {
        btn.disabled = false;
        btn.textContent = originalText;

        if (res.status === 'success') {
            resetPwdModalInstance.hide();
            showToast(window.__T__?.password_reset_ok || 'Пароль успешно сброшен', 'success');
        } else {
            showToast(res.message || window.__T__?.password_reset_failed || 'Ошибка сброса', 'error');
        }
    }).catch(err => {
        btn.disabled = false;
        btn.textContent = originalText;
        if (err && err.message === 'redirect') return;
        showToast((window.__T__?.network_error || 'Ошибка сети') + ': ' + err.message, 'error');
    });
}

function setTheme(theme) {
    let appliedTheme = theme;
    if (theme === 'system') {
        appliedTheme = window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
    }
    document.documentElement.setAttribute('data-bs-theme', appliedTheme);
    localStorage.setItem('theme', theme);
    updateThemeButtons(theme);
}

function updateThemeButtons(theme) {
    document.querySelectorAll('.theme-btn').forEach(btn => btn.classList.remove('active'));
    const activeBtn = document.getElementById(`theme-btn-${theme}`);
    if (activeBtn) activeBtn.classList.add('active');
}

function toggleGlassMode() {
    const isGlass = document.documentElement.getAttribute('data-theme-glass') === 'true';
    const newGlass = !isGlass;
    document.documentElement.setAttribute('data-theme-glass', newGlass ? 'true' : 'false');
    localStorage.setItem('theme_glass', newGlass ? 'true' : 'false');
    updateGlassBtn(newGlass);
}

function updateGlassBtn(isGlass) {
    const btn = document.getElementById('glassToggleBtn');
    if (!btn) return;
    if (isGlass) {
        btn.classList.replace('btn-outline-primary', 'btn-primary');
        btn.innerHTML = '<i class="bi bi-droplet-fill"></i> <span>Glass: ON</span>';
    } else {
        btn.classList.replace('btn-primary', 'btn-outline-primary');
        btn.innerHTML = '<i class="bi bi-droplet-half"></i> <span>Liquid Glass</span>';
    }
}

document.addEventListener('DOMContentLoaded', () => {
    const saved = localStorage.getItem('theme');
    const serverDefault = window.__THEME_DEFAULT__ || 'system';
    const current = saved || serverDefault;
    updateThemeButtons(current);

    const isGlass = localStorage.getItem('theme_glass') === 'true';
    document.documentElement.setAttribute('data-theme-glass', isGlass ? 'true' : 'false');
    updateGlassBtn(isGlass);
});

window.switchTab = switchTab;
window.openUserModal = openUserModal;
window.editUser = editUser;
window.deleteUser = deleteUser;
window.submitUser = submitUser;
window.showUserDetails = showUserDetails;
window.openImportUsersModal = openImportUsersModal;
window.importUsers = importUsers;
window.openCreateVaultModal = openCreateVaultModal;
window.createVault = createVault;
window.openVaultAccess = openVaultAccess;
window.saveVaultAccess = saveVaultAccess;
window.unban = unban;
window.loadBackups = loadBackups;
window.createBackup = createBackup;
window.restoreBackup = restoreBackup;
window.saveSettings = saveSettings;
window.loadAdminPasswords = loadAdminPasswords;
window.filterUsers = filterUsers;
window.viewAdminPwd = viewAdminPwd;
window.syncHex = syncHex;
window.updateLivePreview = updateLivePreview;
window.saveBranding = saveBranding;
window.resetBranding = resetBranding;
window.openResetPwdModal = openResetPwdModal;
window.generateRandomPwd = generateRandomPwd;
window.submitResetPassword = submitResetPassword;
window.setTheme = setTheme;
window.toggleGlassMode = toggleGlassMode;