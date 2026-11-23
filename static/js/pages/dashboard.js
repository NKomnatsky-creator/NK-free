let allPasswords = [];
let currentCategory = 'Все';
let currentOwner = '';
let currentFilterChip = null;
let addModalInstance, qrModalInstance, historyModalInstance, importModalInstance, generatorModalInstance, confirmDeleteModalInstance, shareLinkModalInstance, shareOptionsModalInstance, exportModalInstance;
let genTargetInputId = 'passwordInput';
let allPasswordsVisible = false;
let autoHideTimer = null;
let privacyMode = false;
let confettiFired = false;
let sortableInstance = null;

let cmdModalInstance = null;
let cmdResults = [];
let cmdActiveIdx = 0;

let searchTimer;
function filterPasswordsDebounced() {
    clearTimeout(searchTimer);
    searchTimer = setTimeout(filterPasswords, 150);
}

function showEl(el, display) {
    if (!el) return;
    el.classList.remove('force-hidden', 'force-flex', 'force-block');
    if (display === 'flex') el.classList.add('force-flex');
    else if (display === 'block') el.classList.add('force-block');
    else el.classList.add('force-hidden');
}

function hideEl(el) {
    if (el) { el.classList.remove('force-flex', 'force-block'); el.classList.add('force-hidden'); }
}

document.addEventListener('hide.bs.modal', function () { if (document.activeElement) document.activeElement.blur(); });

function initDashboard() {
    try {
        addModalInstance = new bootstrap.Modal(document.getElementById('addModal'));
        qrModalInstance = new bootstrap.Modal(document.getElementById('qrModal'));
        historyModalInstance = new bootstrap.Modal(document.getElementById('historyModal'));
        importModalInstance = new bootstrap.Modal(document.getElementById('importModal'));
        generatorModalInstance = new bootstrap.Modal(document.getElementById('generatorModal'));
        confirmDeleteModalInstance = new bootstrap.Modal(document.getElementById('confirmDeleteModal'));
        shareLinkModalInstance = new bootstrap.Modal(document.getElementById('shareLinkModal'));
        shareOptionsModalInstance = new bootstrap.Modal(document.getElementById('shareOptionsModal'));
        exportModalInstance = new bootstrap.Modal(document.getElementById('exportModal'));
    } catch (e) { console.error(e); }

    loadPasswords();
    bindHotkeys();

    fetch('/api/logs')
        .then(r => r.json()).then(res => {
            if (res.status === 'success' && res.data.length) {
                const lastLogin = res.data.find(l => l.action === 'Вход' || l.action === 'Login');
                const el = document.getElementById('last-login-info');
                if (el && lastLogin) {
                    const d = new Date(lastLogin.created_at);
                    const locale = window.__CURRENT_LANG__ === 'ru' ? 'ru-RU' : 'en-US';
                    const label = window.__T__.last_login || 'Last login';
                    el.textContent = `${label}: ${d.toLocaleDateString(locale)} ${d.toLocaleTimeString(locale, {hour: '2-digit', minute:'2-digit'})} · IP: ${lastLogin.ip || '—'}`;
                }
            }
        }).catch(() => {});
}

let isDashboardInitialized = false;
function safeInitDashboard() {
    if (isDashboardInitialized) return;
    if (typeof bootstrap === 'undefined') {
        setTimeout(safeInitDashboard, 100);
        return;
    }
    isDashboardInitialized = true;
    initDashboard();
}

document.addEventListener('DOMContentLoaded', safeInitDashboard);
if (document.readyState === 'complete' || document.readyState === 'interactive') {
    safeInitDashboard();
}

function bindHotkeys() {
    document.addEventListener('keydown', (e) => {
        const inInput = ['INPUT', 'TEXTAREA'].includes(document.activeElement.tagName);
        if (e.ctrlKey && e.key === 'k') { e.preventDefault(); openCommandPalette(); return; }
        if (e.key === '/' && !inInput) { e.preventDefault(); document.getElementById('searchInput').focus(); return; }
        if (e.key === 'Escape') {
            const search = document.getElementById('searchInput');
            if (document.activeElement === search && search.value) { search.value = ''; filterPasswords(); }
            else { closeSidebar(); }
            return;
        }
        if (e.ctrlKey && (e.key === 'n' || e.key === 'N') && !inInput) { e.preventDefault(); showAddModal(); return; }
        if (e.ctrlKey && (e.key === 'g' || e.key === 'G') && !inInput) { e.preventDefault(); openGenerator('passwordInput'); return; }
    });
}

function loadPasswords() {
    const loader = document.getElementById('skeleton-loading');
    const container = document.getElementById('passwords-container');
    const noPwd = document.getElementById('no-passwords');
    const errorBox = document.getElementById('error-alert');

    showEl(loader, 'flex'); hideEl(container); hideEl(noPwd); hideEl(errorBox);

    csrfFetch('/api/passwords').then(r => r.json()).then(data => {
        hideEl(loader);
        if (handleMustChange(data)) { showEl(loader, 'flex'); return; }
        if (data && data.status === 'success') {
            allPasswords = data.data || [];
            applyFavorites();
            renderCategories();
            populateOwnerFilter();
            renderFilterChips();
            renderInsights();
            filterPasswords();
        } else {
            showError((data && data.message) ? data.message : (window.__T__.error || 'Ошибка'));
        }
    }).catch(err => {
        hideEl(loader);
        if (err && err.message === 'redirect') return;
        showError((window.__T__.network_error || 'Сеть') + ': ' + err.message);
    });
}

function renderFilterChips() {
    const container = document.getElementById('filterChips');
    if (!container) return;
    const weakCount = allPasswords.filter(p => (p.password || '').length < 8).length;
    const pwdCounts = {}; allPasswords.forEach(p => pwdCounts[p.password] = (pwdCounts[p.password] || 0) + 1);
    const dupCount = Object.values(pwdCounts).filter(c => c > 1).length;
    const oldCount = allPasswords.filter(p => (Date.now() - new Date(p.last_modified_at || p.created_at)) / 86400000 > 90).length;

    const now = new Date();
    const expiringCount = allPasswords.filter(p => p.expires_at && new Date(p.expires_at) > now && (new Date(p.expires_at) - now) / 86400000 <= 7).length;
    const expiredCount = allPasswords.filter(p => p.expires_at && new Date(p.expires_at) < now).length;

    const chips = [
        { id: 'weak', label: window.__T__.filter_weak, count: weakCount, icon: 'shield-x', color: 'text-danger' },
        { id: 'dup', label: window.__T__.filter_dup, count: dupCount, icon: 'files', color: 'text-warning' },
        { id: 'old', label: window.__T__.filter_old, count: oldCount, icon: 'clock-history', color: 'text-info' },
        { id: 'expiring', label: window.__T__.filter_expiring, count: expiringCount, icon: 'calendar-x', color: 'text-warning' },
        { id: 'expired', label: window.__T__.filter_expired, count: expiredCount, icon: 'x-octagon', color: 'text-danger' }
    ];
    container.innerHTML = chips.map(c => `
        <div class="filter-chip ${currentFilterChip === c.id ? 'active' : ''}" onclick="toggleFilterChip('${c.id}')">
            <i class="bi bi-${c.icon} ${c.color}"></i> ${c.label}
            <span class="badge">${c.count}</span>
        </div>
    `).join('');
}

function toggleFilterChip(id) {
    if (currentFilterChip === id) currentFilterChip = null;
    else currentFilterChip = id;
    renderFilterChips();
    filterPasswords();
}

function populateOwnerFilter() {
    const menu = document.getElementById('ownerFilterMenu');
    const label = document.getElementById('ownerFilterLabel');
    if (!menu || !label) return;
    const owners = [...new Set(allPasswords.map(p => p.created_by_name || p.created_by).filter(Boolean))].sort();
    const allLabel = window.__T__.select_staff || 'Все сотрудники';
    menu.innerHTML = `<li><button type="button" class="dropdown-item" data-owner="">${escapeHtml(allLabel)}</button></li>` +
        owners.map(o => `<li><button type="button" class="dropdown-item" data-owner="${escapeAttr(o)}">${escapeHtml(o)}</button></li>`).join('');
    menu.querySelectorAll('[data-owner]').forEach(el => {
        el.addEventListener('click', (e) => {
            e.preventDefault();
            currentOwner = el.dataset.owner || '';
            label.textContent = currentOwner || allLabel;
            menu.querySelectorAll('[data-owner]').forEach(x => x.classList.remove('active'));
            el.classList.add('active');
            filterPasswords();
        });
    });
    if (currentOwner && !owners.includes(currentOwner)) {
        currentOwner = '';
        label.textContent = allLabel;
    } else if (!currentOwner) {
        label.textContent = allLabel;
    } else {
        label.textContent = currentOwner;
    }
}

function togglePrivacyMode() {
    privacyMode = !privacyMode;
    document.body.classList.toggle('privacy-mode', privacyMode);
    const icon = document.getElementById('privacy-icon');
    if (privacyMode) {
        icon.className = 'bi bi-incognito text-primary';
        showToast(window.__T__.privacy_on || 'Приватность ВКЛ', 'info');
    } else {
        icon.className = 'bi bi-incognito';
    }
}

function showError(msg) {
    const errorBox = document.getElementById('error-alert');
    const errorMsg = document.getElementById('error-message');
    if (errorBox && errorMsg) { errorMsg.textContent = msg; showEl(errorBox, 'block'); }
}

function getFavorites() { try { return JSON.parse(localStorage.getItem('passvault_favorites') || '[]'); } catch { return []; } }
function saveFavorites(ids) { try { localStorage.setItem('passvault_favorites', JSON.stringify(ids)); } catch(e){} }
function applyFavorites() { const favs = getFavorites(); allPasswords.forEach(p => { p.is_favorite = favs.includes(p.id); }); }
function toggleFavorite(id) {
    const favs = getFavorites(); const idx = favs.indexOf(id);
    if (idx >= 0) favs.splice(idx, 1); else favs.push(id);
    saveFavorites(favs); applyFavorites(); filterPasswords();
    showToast(idx >= 0 ? (window.__T__.removed_fav || 'Убрано') : (window.__T__.added_fav || 'Добавлено'), 'success');
}

function togglePin(id) {
    csrfFetch(`/api/toggle_pin/${id}`, { method: 'POST' }).then(r => r.json()).then(res => {
        if (handleMustChange(res)) return;
        if (res.status === 'success') {
            showToast(res.is_pinned ? (window.__T__.pinned || 'Закреплено') : (window.__T__.unpinned || 'Откреплено'), 'success');
            const p = allPasswords.find(x => x.id === id);
            if (p) { p.is_pinned = res.is_pinned; p.pinned_at = res.is_pinned ? new Date().toISOString() : null; }
            filterPasswords();
        }
        else showToast((window.__T__.error || 'Ошибка') + ': ' + res.message, 'error');
    }).catch(err => {
        if (err && err.message === 'redirect') return;
        showToast((window.__T__.network_error || 'Ошибка сети') + ': ' + err.message, 'error');
    });
}

function toggleAllPasswords() {
    allPasswordsVisible = !allPasswordsVisible;
    applyPasswordVisibility();
    if (allPasswordsVisible) {
        if (autoHideTimer) clearTimeout(autoHideTimer);
        autoHideTimer = setTimeout(() => {
            allPasswordsVisible = false;
            applyPasswordVisibility();
            showToast(window.__T__.passwords_hidden || 'Скрыто', 'info');
        }, 30000);
    } else if (autoHideTimer) { clearTimeout(autoHideTimer); }
}

function applyPasswordVisibility() {
    document.querySelectorAll('[id^="pwd-"]').forEach(el => {
        const id = parseInt(el.id.replace('pwd-', ''), 10);
        const p = allPasswords.find(x => x.id === id);
        if (p) el.textContent = allPasswordsVisible ? (p.password_error ? (window.__T__.decryption_error || '<ошибка>') : p.password) : '••••••••';
    });
    const icon = document.getElementById('toggle-all-icon');
    if (icon) icon.className = allPasswordsVisible ? 'bi bi-eye' : 'bi bi-eye-slash';
}

function openGenerator(targetInputId) {
    genTargetInputId = targetInputId || 'passwordInput';
    generatePassword();
    if (generatorModalInstance) generatorModalInstance.show();
}

function generatePassword() {
    const len = parseInt(document.getElementById('gen-length').value, 10);
    const upper = document.getElementById('gen-upper').checked, lower = document.getElementById('gen-lower').checked;
    const digits = document.getElementById('gen-digits').checked, symbols = document.getElementById('gen-symbols').checked;
    const noSimilar = document.getElementById('gen-nosimilar').checked;
    let chars = '';
    if (upper) chars += noSimilar ? 'ABCDEFGHJKLMNPQRSTUVWXYZ' : 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
    if (lower) chars += noSimilar ? 'abcdefghijkmnpqrstuvwxyz' : 'abcdefghijklmnopqrstuvwxyz';
    if (digits) chars += noSimilar ? '23456789' : '0123456789';
    if (symbols) chars += '!@#$%^&*()_+-=[]{}|;:,.<>?';
    if (!chars) chars = 'abcdefghijklmnopqrstuvwxyz';
    const arr = new Uint32Array(len); crypto.getRandomValues(arr);
    let pwd = '';
    for (let i = 0; i < len; i++) pwd += chars.charAt(arr[i] % chars.length);
    document.getElementById('gen-result').value = pwd;
    const strength = getPasswordStrength(pwd);
    const labels = { weak: '🔴', medium: '🟡', strong: '🟢' };
    document.getElementById('gen-strength').textContent = labels[strength];
}

function copyGenerated() {
    const val = document.getElementById('gen-result').value;
    navigator.clipboard.writeText(val).then(() => { showClipboardToast(); });
}

function useGenerated() {
    const val = document.getElementById('gen-result').value;
    const input = document.getElementById(genTargetInputId);
    if (input) { input.value = val; input.type = 'text'; if (typeof checkHIBP === 'function') checkHIBP(val); }
    generatorModalInstance.hide();
    showToast(window.__T__.generated || 'Сгенерировано', 'success');
}

function showClipboardToast() {
    const old = document.getElementById('clipboard-toast');
    if (old) old.remove();
    const toast = document.createElement('div');
    toast.id = 'clipboard-toast';
    toast.className = 'clipboard-toast';
    toast.innerHTML = `<i class="bi bi-clipboard-check"></i>
        <span>${window.__T__.copied || 'Скопировано'}! <span id="clip-countdown">30</span>${window.__T__?.seconds_short || 'с'}</span>
        <button onclick="clearClipboardNow()">${window.__T__.clear_now || 'Сейчас'}</button>`;
    document.body.appendChild(toast);
    let sec = 30;
    const interval = setInterval(() => {
        sec--;
        const el = document.getElementById('clip-countdown');
        if (el) el.textContent = sec;
        if (sec <= 0) {
            clearInterval(interval);
            navigator.clipboard.writeText('\u200b').catch(() => {});
            const t = document.getElementById('clipboard-toast');
            if (t) t.remove();
        }
    }, 1000);
}

function clearClipboardNow() {
    navigator.clipboard.writeText('\u200b').catch(() => {});
    const toast = document.getElementById('clipboard-toast');
    if (toast) toast.remove();
    showToast(window.__T__.clipboard_cleared || 'Очищено', 'success');
}

function showImportModal() { document.getElementById('csvFileInput').value = ''; importModalInstance.show(); }

function startImport() {
    const fileInput = document.getElementById('csvFileInput');
    if (!fileInput || !fileInput.files.length) { showToast(window.__T__.select_file || 'Выберите файл', 'error'); return; }
    const file = fileInput.files[0];
    const reader = new FileReader();

    reader.onload = function(e) {
        try {
            const text = e.target.result;
            let passwords = [];

            if (file.name.endsWith('.json')) {
                const json = JSON.parse(text);
                const items = json.items || json;
                if (Array.isArray(items)) {
                    items.forEach(item => {
                        if (item.login && item.password) {
                            passwords.push({
                                service_name: item.name || window.__T__.import || 'Импорт', username: item.login,
                                password: item.password, url: item.login_uri || '', notes: item.notes || '', category: window.__T__.import || 'Импорт'
                            });
                        }
                    });
                }
            } else {
                const lines = text.split(/\r?\n/).filter(line => line.trim() !== '');
                if (lines.length < 2) { showToast(window.__T__.file_empty || 'Файл пуст', 'error'); return; }
                const headers = lines[0].split(',').map(h => h.trim().replace(/"/g, '').toLowerCase());
                const idx = { name: headers.findIndex(h => h.includes('name') || h.includes('service') || h.includes('title')), url: headers.findIndex(h => h.includes('url') || h.includes('link')), user: headers.findIndex(h => h.includes('user') || h.includes('login')), pwd: headers.findIndex(h => h.includes('pass')), notes: headers.findIndex(h => h.includes('note') || h.includes('comment')) };
                for (let i = 1; i < lines.length; i++) {
                    const row = []; let inQuotes = false; let current = '';
                    for (let char of lines[i]) {
                        if (char === '"') inQuotes = !inQuotes;
                        else if (char === ',' && !inQuotes) { row.push(current); current = ''; }
                        else current += char;
                    }
                    row.push(current);
                    const p = {
                        service_name: idx.name !== -1 ? (row[idx.name] || '').replace(/"/g, '') : (window.__T__.import || 'Импорт'),
                        url: idx.url !== -1 ? (row[idx.url] || '').replace(/"/g, '') : '',
                        username: idx.user !== -1 ? (row[idx.user] || '').replace(/"/g, '') : '',
                        password: idx.pwd !== -1 ? (row[idx.pwd] || '').replace(/"/g, '') : '',
                        notes: idx.notes !== -1 ? (row[idx.notes] || '').replace(/"/g, '') : '',
                        category: window.__T__.import || 'Импорт'
                    };
                    if (p.password) passwords.push(p);
                }
            }

            if (!passwords.length) { showToast(window.__T__.passwords_not_found || 'Не найдены', 'error'); return; }
            importModalInstance.hide();
            showEl(document.getElementById('skeleton-loading'), 'flex');

            csrfFetch('/api/import_passwords', { method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({passwords: passwords}) })
            .then(r => r.json()).then(res => {
                hideEl(document.getElementById('skeleton-loading'));
                if (handleMustChange(res)) return;
                if (res.status === 'success') { showToast(res.message, 'success'); loadPasswords(); }
                else showToast((window.__T__.error || 'Ошибка') + ': ' + res.message, 'error');
            }).catch(err => {
                hideEl(document.getElementById('skeleton-loading'));
                if (err && err.message === 'redirect') return;
                showToast((window.__T__.network_error || 'Ошибка сети') + ': ' + err.message, 'error');
            });
        } catch (err) { console.error(err); showToast(window.__T__.parse_error || 'Ошибка парсинга', 'error'); }
    };
    reader.readAsText(file);
}

function exportPasswords() {
    if (exportModalInstance) exportModalInstance.show();
}

function performExport() {
    const btn = document.getElementById('exportBtn');
    if (!btn || btn.disabled) return;
    const originalHtml = btn.innerHTML;
    btn.disabled = true;
    btn.innerHTML = '<span class="spinner-border spinner-border-sm me-1"></span>...';

    const fmt = (document.getElementById('exportFormat') || {}).value || 'csv';
    const filter = (document.getElementById('exportFilter') || {}).value || 'all';
    csrfFetch(`/api/export?format=${encodeURIComponent(fmt)}&filter_type=${encodeURIComponent(filter)}`)
        .then(async r => {
            const type = r.headers.get('Content-Type') || '';
            const isFile = /text\/csv|application\/csv|application\/json|application\/octet-stream/i.test(type);
            if (!r.ok || !isFile) {
                let res = null;
                try { res = await r.json(); } catch (_) { res = null; }
                if (res && res.redirect) { window.location.href = res.redirect; return; }
                if (typeof handleMustChange === 'function' && handleMustChange(res)) return;
                throw new Error((res && res.message) || r.statusText || (window.__T__.error || 'Ошибка'));
            }

            const blob = await r.blob();
            const disposition = r.headers.get('Content-Disposition') || '';
            const nameMatch = disposition.match(/filename\*?=(?:UTF-8'')?([^;]+)/i);
            let filename = nameMatch ? nameMatch[1].trim().replace(/^["']|["']$/g, '')
                                     : (fmt === 'json' ? 'passwords.json' : 'passwords.csv');
            try { filename = decodeURIComponent(filename); } catch (_) {}
            const url = URL.createObjectURL(blob);
            const link = document.createElement('a');
            link.href = url;
            link.download = filename;
            document.body.appendChild(link);
            link.click();
            link.remove();
            setTimeout(() => URL.revokeObjectURL(url), 1000);
            if (exportModalInstance) exportModalInstance.hide();
            showToast(window.__T__.exported || 'Экспорт завершён', 'success');
        })
        .catch(err => {
            if (err && err.message === 'redirect') return;
            showToast((window.__T__.error || 'Ошибка') + ': ' + ((err && err.message) || 'export failed'), 'error');
        })
        .finally(() => {
            btn.disabled = false;
            btn.innerHTML = originalHtml;
        });
}

let hibpTimer = null;
const hibpAvailable = !!(window.isSecureContext && crypto.subtle);
function checkHIBP(password, passwordId = null) {
    clearTimeout(hibpTimer);
    const w = document.getElementById('hibp-warning');
    const s = document.getElementById('hibp-success');
    if (w) { w.style.display = 'none'; w.className = 'alert alert-danger py-1 px-2 mt-2 mb-0'; }
    if (s) s.style.display = 'none';

    if (!hibpAvailable) {
        if (w && password.length >= 4) {
            w.style.display = 'block';
            w.className = 'alert alert-warning py-1 px-2 mt-2 mb-0';
            w.innerHTML = `<i class="bi bi-info-circle"></i> ${window.__T__.hibp_unavailable || 'Проверка недоступна'}`;
        }
        return;
    }
    if (password.length < 4) return;

    hibpTimer = setTimeout(() => {
        crypto.subtle.digest('SHA-1', new TextEncoder().encode(password)).then(hashBuffer => {
            const hashHex = Array.from(new Uint8Array(hashBuffer)).map(b => b.toString(16).padStart(2, '0')).join('').toUpperCase();
            const suffix = hashHex.substring(5);
            fetch(`https://api.pwnedpasswords.com/range/${hashHex.substring(0, 5)}`).then(res => res.text()).then(text => {
                const leaked = new RegExp(`^${suffix}:`, 'm').test(text);
                if (leaked) {
                    if (w) {
                        w.style.display = 'block';
                        w.className = 'alert alert-danger py-1 px-2 mt-2 mb-0';
                        w.innerHTML = `<i class="bi bi-shield-x"></i> ${window.__T__.pwned || 'Пароль в утечках!'}`;
                    }
                    if (passwordId) {
                        csrfFetch(`/api/mark_leaked/${passwordId}`, {
                            method: 'POST', headers: {'Content-Type': 'application/json'},
                            body: JSON.stringify({leaked: true})
                        }).catch(() => {});
                    }
                } else {
                    if (s) s.style.display = 'block';
                    if (passwordId) {
                        csrfFetch(`/api/mark_leaked/${passwordId}`, {
                            method: 'POST', headers: {'Content-Type': 'application/json'},
                            body: JSON.stringify({leaked: false})
                        }).catch(() => {});
                    }
                }
            }).catch(() => {});
        }).catch(() => {});
    }, 500);
}

document.addEventListener('click', e => {
    const copyBtn = e.target.closest('[data-copy]');
    if (copyBtn) {
        const text = copyBtn.dataset.copy;
        const pwdId = copyBtn.dataset.pwdId;
        navigator.clipboard.writeText(text).then(() => {
            showClipboardToast();
            const originalHtml = copyBtn.innerHTML;
            copyBtn.innerHTML = '<i class="bi bi-check-lg text-success"></i>';
            setTimeout(() => copyBtn.innerHTML = originalHtml, 2000);

            if (pwdId) csrfFetch(`/api/mark_used/${pwdId}`, {method: 'POST'}).catch(() => {});
        });
        return;
    }

    const viewBtn = e.target.closest('[data-view-id]');
    if (viewBtn) { toggleView(parseInt(viewBtn.dataset.viewId, 10), viewBtn); return; }

    const editBtn = e.target.closest('[data-edit-id]');
    if (editBtn) { editPassword(parseInt(editBtn.dataset.editId, 10)); return; }

    const delBtn = e.target.closest('[data-delete-id]');
    if (delBtn) { openDeleteConfirm(parseInt(delBtn.dataset.deleteId, 10)); return; }

    const quickRefreshBtn = e.target.closest('[data-quick-refresh]');
    if (quickRefreshBtn) { quickRefreshPassword(parseInt(quickRefreshBtn.dataset.quickRefresh, 10)); return; }
});

function sharePassword(id) {
    const p = allPasswords.find(x => x.id === id); if (!p) return;
    const hidden = document.getElementById('sharePasswordId');
    if (hidden) hidden.value = id;
    if (shareOptionsModalInstance) shareOptionsModalInstance.show();
}

function confirmShare() {
    const id = parseInt((document.getElementById('sharePasswordId') || {}).value || '0', 10);
    if (!id) return;
    const payload = {
        hours: Number((document.getElementById('shareHours') || {}).value || 24),
        max_views: Number((document.getElementById('shareMaxViews') || {}).value || 0),
        password: (document.getElementById('shareLinkPassword') || {}).value || '',
        one_time: !!(document.getElementById('shareOneTime') || {}).checked
    };
    const btn = document.querySelector(`[data-share-id="${id}"]`);
    let originalHtml = '';
    if (btn) {
        originalHtml = btn.innerHTML;
        btn.innerHTML = '<span class="spinner-border spinner-border-sm"></span>';
        btn.disabled = true;
    }
    csrfFetch(`/api/create_share/${id}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
    })
        .then(r => r.json())
        .then(res => {
            if (btn) { btn.innerHTML = originalHtml; btn.disabled = false; }
            if (handleMustChange(res)) return;
            if (res.status === 'success') {
                if (shareOptionsModalInstance) shareOptionsModalInstance.hide();
                const url = `${window.location.origin}/share/${res.token}`;
                document.getElementById('shareLinkInput').value = url;
                shareLinkModalInstance.show();
            } else {
                showToast(res.message, 'error');
            }
        })
        .catch(err => {
            if (btn) { btn.innerHTML = originalHtml; btn.disabled = false; }
            if (err && err.message === 'redirect') return;
            showToast((window.__T__.network_error || 'Ошибка сети') + ': ' + err.message, 'error');
        });
}

function copyShareLink() {
    const input = document.getElementById('shareLinkInput');
    navigator.clipboard.writeText(input.value).then(() => {
        const btn = document.getElementById('copyShareBtn');
        const originalHtml = btn.innerHTML;
        btn.innerHTML = '<i class="bi bi-check-lg me-1"></i> ' + (window.__T__?.copied || 'Скопировано');
        btn.classList.replace('btn-primary', 'btn-success');
        setTimeout(() => {
            btn.innerHTML = originalHtml;
            btn.classList.replace('btn-success', 'btn-primary');
            shareLinkModalInstance.hide();
        }, 1500);
    });
}

function quickRefreshPassword(id) {
    const p = allPasswords.find(x => x.id === id); if (!p) return;
    const newPwd = Array.from(crypto.getRandomValues(new Uint8Array(16)))
        .map(b => b.toString(16).padStart(2, '0')).join('').slice(0, 16);

    csrfFetch('/api/update_password', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({ id: id, password: newPwd })
    }).then(r => r.json()).then(res => {
        if (handleMustChange(res)) return;
        if (res.status === 'success') {
            navigator.clipboard.writeText(newPwd).then(() => {
                showClipboardToast();
                showToast(window.__T__?.password_updated_copied || 'Пароль обновлён и скопирован', 'success');
            }).catch(() => {
                showToast(window.__T__?.password_updated_manual || 'Пароль обновлён. Скопируйте из карточки.', 'success');
            });
            loadPasswords();
        } else {
            showToast((window.__T__?.error || 'Ошибка') + ': ' + res.message, 'error');
        }
    }).catch(err => {
        if (err && err.message === 'redirect') return;
        showToast(window.__T__?.network_error || 'Ошибка сети', 'error');
    });
}

function getCategoryIcon(cat) {
    const c = cat.toLowerCase();
    if (c.includes('работ') || c.includes('сервер') || c.includes('бд')) return 'briefcase-fill';
    if (c.includes('соц') || c.includes('сеть')) return 'globe2';
    if (c.includes('банк') || c.includes('финанс')) return 'credit-card-2-front-fill';
    if (c.includes('игр') || c.includes('steam')) return 'controller';
    if (c.includes('почт') || c.includes('email')) return 'envelope-fill';
    return 'folder-fill';
}

function renderCategories() {
    const counts = {};
    const uncategorized = window.__T__?.uncategorized || 'Без категории';
    allPasswords.forEach(p => { const cat = p.category || uncategorized; counts[cat] = (counts[cat] || 0) + 1; });
    const maxCount = Math.max(...Object.values(counts), 1);

    const categories = ['Все', ...Object.keys(counts).sort()];
    const list = document.getElementById('category-list');
    if (!list) return;

    list.innerHTML = categories.map(c => {
        const icon = c === 'Все' ? 'grid-fill' : getCategoryIcon(c);
        const count = c === 'Все' ? allPasswords.length : counts[c];
        const percent = c === 'Все' ? 100 : (count / maxCount) * 100;

        return `
        <a class="cat-pill ${c === currentCategory ? 'active' : ''}" data-category="${escapeAttr(c)}">
            <div class="cat-bg" style="width:${percent}%;"></div>
            <i class="bi bi-${icon}" style="z-index:1;"></i>
            <span class="flex-grow-1" style="z-index:1;">${escapeHtml(c === 'Все' ? (window.__T__?.all || 'Все') : c)}</span>
            <span class="badge rounded-pill" style="background: var(--bg-base); color: var(--text-muted); border: 1px solid var(--border-color); z-index:1;">${count}</span>
        </a>`;
    }).join('');
    list.querySelectorAll('[data-category]').forEach(el => el.addEventListener('click', () => setCategory(el.dataset.category)));
}

function setCategory(cat) {
    currentCategory = cat;
    currentFilterChip = null;
    const title = document.getElementById('current-category-title');
    if (title) title.textContent = cat === 'Все' ? (window.__T__.all_passwords || 'Все пароли') : cat;
    renderCategories();
    renderFilterChips();
    filterPasswords();
    closeSidebar();
}

function renderInsights() {
    const box = document.getElementById('insights-container');
    if (!box) return;
    if (!allPasswords.length) { box.innerHTML = ''; return; }

    const insights = [];
    const now = new Date();
    const expiring = allPasswords.filter(p => p.expires_at && new Date(p.expires_at) > now && (new Date(p.expires_at) - now) / 86400000 <= 7).length;
    const expired = allPasswords.filter(p => p.expires_at && new Date(p.expires_at) < now).length;

    if (expiring > 0) insights.push({ id: 'expiring', icon: 'calendar-x', color: '#eab308', text: `<b>${expiring}</b> ${window.__T__.insight_expiring}` });
    if (expired > 0) insights.push({ id: 'expired', icon: 'x-octagon', color: '#dc2626', text: `<b>${expired}</b> ${window.__T__.insight_expired}` });

    if (!insights.length) {
        box.innerHTML = '';
        return;
    }
    box.innerHTML = insights.map(i => `<div class="alert border-0 mb-2 d-flex align-items-start gap-2" style="cursor:pointer; background: ${i.color}15; color:${i.color}; border-radius:12px;" onclick="toggleFilterChip('${i.id}')"><i class="bi bi-${i.icon} fs-5"></i><div>${i.text}</div></div>`).join('');
}

function highlight(text, query) {
    if (!query) return escapeHtml(text);
    const safe = escapeHtml(text);
    const regex = new RegExp(`(${query.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')})`, 'gi');
    return safe.replace(regex, '<mark>$1</mark>');
}

function updateEmptyTip() {
    const el = document.getElementById('empty-tip');
    if (el) el.textContent = '💡 ' + (window.__T__.tip_reuse || 'Совет');
}

function resetFilters() {
    document.getElementById('searchInput').value = '';
    currentCategory = 'Все';
    currentFilterChip = null;
    currentOwner = '';
    const label = document.getElementById('ownerFilterLabel');
    if (label) label.textContent = window.__T__.select_staff || 'Все сотрудники';
    document.getElementById('current-category-title').textContent = window.__T__.all_passwords || 'Все пароли';
    renderCategories();
    renderFilterChips();
    populateOwnerFilter();
    filterPasswords();
}

function smartSearchFilter(p, q) {
    if (!q) return true;
    const query = q.toLowerCase();

    if (query.startsWith('#')) {
        return (p.category || '').toLowerCase().includes(query.slice(1));
    }

    return (p.service_name || '').toLowerCase().includes(query) ||
           (p.username || '').toLowerCase().includes(query) ||
           (p.notes || '').toLowerCase().includes(query) ||
           (p.url || '').toLowerCase().includes(query);
}

function filterPasswords() {
    const q = (document.getElementById('searchInput').value || '').toLowerCase().trim();
    let filtered = allPasswords;

    if (currentCategory !== 'Все') filtered = filtered.filter(p => (p.category || (window.__T__?.uncategorized || 'Без категории')) === currentCategory);
    if (currentOwner) filtered = filtered.filter(p => (p.created_by_name || p.created_by) === currentOwner);

    if (currentFilterChip === 'weak') filtered = filtered.filter(p => (p.password || '').length < 8);
    else if (currentFilterChip === 'old') filtered = filtered.filter(p => (Date.now() - new Date(p.last_modified_at || p.created_at)) / 86400000 > 90);
    else if (currentFilterChip === 'dup') {
        const pwdCounts = {}; allPasswords.forEach(p => pwdCounts[p.password] = (pwdCounts[p.password] || 0) + 1);
        filtered = filtered.filter(p => pwdCounts[p.password] > 1);
    }
    else if (currentFilterChip === 'expiring') {
        const now = new Date();
        filtered = filtered.filter(p => p.expires_at && new Date(p.expires_at) > now && (new Date(p.expires_at) - now) / 86400000 <= 7);
    }
    else if (currentFilterChip === 'expired') {
        const now = new Date();
        filtered = filtered.filter(p => p.expires_at && new Date(p.expires_at) < now);
    }

    if (q) filtered = filtered.filter(p => smartSearchFilter(p, q));

    filtered.sort((a, b) => {
        const orderA = a.sort_order || 0;
        const orderB = b.sort_order || 0;
        if (orderA !== orderB) return orderA - orderB;

        if (a.is_pinned && !b.is_pinned) return -1;
        if (!a.is_pinned && b.is_pinned) return 1;
        if (a.is_favorite && !b.is_favorite) return -1;
        if (!a.is_favorite && b.is_favorite) return 1;
        return 0;
    });

    window._highlightQuery = q;
    const container = document.getElementById('passwords-container');
    const noPwd = document.getElementById('no-passwords');

    if (filtered.length) {
        // FLIP: карточки перемещаются через transform (compositor),
        // а не через пересчёт layout — стабильные кадры на 120 Гц.
        if (window.NKMotion && window.NKMotion.flip) {
            window.NKMotion.flip(container, () => renderPasswords(filtered),
                                 { selector: ':scope > .vault-item' });
        } else {
            renderPasswords(filtered);
        }
        showEl(container, 'flex');
        hideEl(noPwd);
    } else {
        hideEl(container);
        const isFiltering = q || currentFilterChip || currentCategory !== 'Все' || currentOwner;
        const titleEl = document.getElementById('empty-title');
        const descEl = document.getElementById('empty-desc');
        const actionEl = document.getElementById('empty-action');
        const importHint = document.getElementById('empty-import-hint');
        const iconEl = document.getElementById('empty-icon');

        if (isFiltering) {
            titleEl.textContent = window.__T__.nothing_found || 'Ничего не найдено';
            descEl.textContent = q
        ? (window.__T__?.search_no_results || 'По запросу «{q}» ничего нет.').replace('{q}', q)
        : (window.__T__.no_filter_results || 'Пусто.');
            actionEl.innerHTML = `<i class="bi bi-x-lg me-1"></i> ${window.__T__.reset_filters || 'Сбросить'}`;
            actionEl.onclick = resetFilters;
            if (importHint) importHint.style.display = 'none';
            if (iconEl) iconEl.className = 'bi bi-search';
        } else {
            titleEl.textContent = window.__T__.empty_safe_title || 'Сейф пока пуст';
            descEl.textContent = window.__T__.empty_safe_desc || 'Добавьте пароль';
            actionEl.innerHTML = `<i class="bi bi-plus-lg me-1"></i> ${window.__T__.new_password || 'Добавить'}`;
            actionEl.onclick = showAddModal;
            if (importHint) importHint.style.display = 'block';
            if (iconEl) iconEl.className = 'bi bi-safe';
            updateEmptyTip();
        }
        showEl(noPwd, 'block');
    }
}

function getFavicon(url) {
    try { return url ? `https://www.google.com/s2/favicons?domain=${new URL(url).hostname}&sz=64` : null; }
    catch { return null; }
}

function getPasswordStrength(pwd) {
    let score = 0;
    if (pwd.length >= 8) score++; if (pwd.length >= 12) score++;
    if (/[A-Z]/.test(pwd)) score++; if (/[0-9]/.test(pwd)) score++; if (/[^A-Za-z0-9]/.test(pwd)) score++;
    if (score <= 2) return 'weak'; if (score <= 4) return 'medium'; return 'strong';
}

function renderPasswords(list) {
    const container = document.getElementById('passwords-container');
    container.innerHTML = '';
    const hq = window._highlightQuery || '';
    const isAdmin = !!(window.__USER__ && ['admin', 'manager'].includes(window.__USER__.role));

    list.forEach((p) => {
        const div = document.createElement('div');
        div.className = 'vault-item';
        div.dataset.id = p.id;

        const faviconUrl = getFavicon(p.url);
        const letter = (p.service_name || '?').charAt(0).toUpperCase();
        const hue = (letter.charCodeAt(0) * 37) % 360;
        const letterIcon = `<span class="fw-bold fs-5" style="color:hsl(${hue} 70% 50%)">${escapeHtml(letter)}</span>`;
        const iconHtml = faviconUrl ? `<img src="${escapeAttr(faviconUrl)}" onerror="this.style.display='none'">` : letterIcon;
        const openLabel = window.__T__?.open_link || 'Открыть';
        const iconWrapper = p.url ? `<a href="${escapeAttr(p.url)}" target="_blank" rel="noopener noreferrer" class="service-icon mb-2" title="${escapeAttr(openLabel)} ${escapeAttr(p.url)}">${iconHtml}</a>` : `<div class="service-icon mb-2">${iconHtml}</div>`;

        const strength = getPasswordStrength(p.password || '');
        const dotClass = strength === 'weak' ? 'strength-weak' : strength === 'medium' ? 'strength-medium' : 'strength-strong';
        const strengthTone = strength === 'weak' ? 'danger' : strength === 'medium' ? 'warning' : 'active';
        const strengthLabel = window.__T__?.['strength_' + strength] || strength;
        const lastMod = new Date(p.last_modified_at || p.created_at);
        const daysOld = Math.floor((new Date() - lastMod) / 86400000);

        const ageTitle = (window.__T__?.password_unchanged || 'Пароль не менялся {days} дн.')
            .replace('{days}', daysOld);
        const daysShort = window.__T__?.days_short || 'дн.';
        let ageBadge = '';
        if (daysOld > 180) ageBadge = `<span class="status-chip status-chip--danger" title="${escapeAttr(ageTitle)}"><i class="bi bi-exclamation-triangle"></i> ${daysOld}${escapeHtml(daysShort)}</span>`;
        else if (daysOld > 90) ageBadge = `<span class="status-chip status-chip--warning" title="${escapeAttr(ageTitle)}">${daysOld}${escapeHtml(daysShort)}</span>`;

        let expiresBadge = '';
        if (p.expires_at) {
            const expDate = new Date(p.expires_at);
            const daysLeft = Math.ceil((expDate - new Date()) / 86400000);
            if (daysLeft < 0) expiresBadge = `<span class="status-chip status-chip--danger">${window.__T__.badge_expired || 'Просрочен'}</span>`;
            else if (daysLeft <= 7) expiresBadge = `<span class="status-chip status-chip--warning">${window.__T__.badge_expires_in || 'Истекает через'} ${daysLeft} ${window.__T__.days_short || 'дн.'}</span>`;
        }

        const favIcon = p.is_favorite ? 'star-fill' : 'star';
        const favClass = p.is_favorite ? 'text-warning' : '';
        const favTitle = p.is_favorite ? (window.__T__.remove_fav || 'Убрать из избранного') : (window.__T__.add_fav || 'В избранное');
        const pinIcon = p.is_pinned ? 'pin-angle-fill' : 'pin-angle';
        const pinClass = p.is_pinned ? 'text-primary' : '';
        const pinTitle = p.is_pinned ? (window.__T__.unpin || 'Открепить') : (window.__T__.pin || 'Закрепить');

        const ownerBadge = isAdmin ? `<span class="status-chip status-chip--info hide-in-privacy" title="${escapeAttr(window.__T__?.owner || 'Владелец')}"><i class="bi bi-person-fill"></i> ${escapeHtml(p.created_by_name || p.created_by || '')}</span>` : '';
        const categoryName = p.category || (window.__T__?.uncategorized || 'Без категории');
        const catKey = String(categoryName).toLowerCase();
        const catIcon = /почт|mail|email/.test(catKey) ? 'envelope'
            : /банк|bank|finance|финанс/.test(catKey) ? 'bank'
            : /работ|work|job/.test(catKey) ? 'briefcase'
            : /соц|social/.test(catKey) ? 'people' : 'tag';
        const catBadge = `<span class="status-chip status-chip--muted hide-in-privacy"><i class="bi bi-${catIcon}"></i> ${escapeHtml(categoryName)}</span>`;

        div.innerHTML = `
            <div class="d-flex justify-content-between align-items-start mb-3">
                <div class="d-flex gap-3 align-items-center text-truncate">
                    ${iconWrapper}
                    <div class="text-truncate">
                        <div class="item-value text-truncate d-flex align-items-center gap-1 hide-in-privacy fs-6">
                            ${p.is_pinned ? '<i class="bi bi-pin-angle-fill text-primary" style="font-size:0.8rem;"></i>' : ''}
                            ${p.is_favorite ? '<i class="bi bi-star-fill text-warning" style="font-size:0.8rem;"></i>' : ''}
                            ${highlight(p.service_name, hq)}
                        </div>
                        <div class="d-flex align-items-center flex-wrap gap-1 mt-1">
                            ${catBadge}
                            ${ownerBadge}
                            ${ageBadge}
                            ${expiresBadge}
                        </div>
                    </div>
                </div>
                <div class="dropdown flex-shrink-0" onclick="event.stopPropagation()">
                    <button class="action-btn" type="button" data-bs-toggle="dropdown" aria-expanded="false"><i class="bi bi-three-dots-vertical"></i></button>
                    <ul class="dropdown-menu dropdown-menu-end dropdown-menu-custom">
                        <li><button class="dropdown-item-custom ${pinClass}" type="button" onclick="togglePin(${p.id})"><i class="bi bi-${pinIcon}"></i> ${pinTitle}</button></li>
                        <li><button class="dropdown-item-custom ${favClass}" type="button" onclick="toggleFavorite(${p.id})"><i class="bi bi-${favIcon}"></i> ${favTitle}</button></li>
                        <li><button class="dropdown-item-custom" type="button" data-share-id="${p.id}" onclick="sharePassword(${p.id})"><i class="bi bi-share"></i> ${window.__T__.share || 'Поделиться'}</button></li>
                        ${p.url ? `<li><button class="dropdown-item-custom" type="button" onclick="showQR(${p.id})"><i class="bi bi-qr-code"></i> ${window.__T__?.qr_code || 'QR-код'}</button></li>` : ''}
                        <li><button class="dropdown-item-custom" type="button" onclick="showHistory(${p.id})"><i class="bi bi-clock-history"></i> ${window.__T__.history || 'История'}</button></li>
                    </ul>
                </div>
            </div>

            <div class="mb-3 item-field">
                <div class="item-label">${window.__T__.login || 'Логин'}</div>
                <div class="item-value d-flex align-items-center gap-2 text-truncate">
                    <span class="text-truncate hide-in-privacy">${highlight(p.username || '', hq)}</span>
                    <button class="action-btn p-1" data-copy="${escapeAttr(p.username || '')}" title="${escapeAttr(window.__T__?.copy_login || 'Копировать логин')}" onclick="event.stopPropagation()">
                        <i class="bi bi-person-plus" style="font-size:0.8rem;"></i>
                    </button>
                </div>
            </div>

            <div class="mb-3 item-field">
                <div class="item-label">${window.__T__.password || 'Пароль'}</div>
                <div class="item-value d-flex align-items-center gap-2">
                    <div class="strength-dot ${dotClass}" title="${escapeAttr(strengthLabel)}"></div>
                    <span class="strength-label status-chip status-chip--${strengthTone}" title="${escapeAttr(strengthLabel)}">${escapeHtml(strengthLabel)}</span>
                    <span id="pwd-${p.id}" class="text-truncate flex-grow-1" style="font-family: monospace; letter-spacing: 1px;">••••••••</span>
                    <button class="action-btn p-1" data-view-id="${p.id}" title="${escapeAttr(window.__T__?.show || 'Показать')}"><i class="bi bi-eye"></i></button>
                </div>
            </div>

            <div class="d-flex align-items-center gap-1 actions-wrap mt-auto pt-3 border-top" style="border-color: var(--border-color) !important;">
                <button class="action-btn" data-copy="${escapeAttr(p.password || '')}" data-pwd-id="${p.id}" title="${escapeAttr(window.__T__?.copy_password || 'Копировать пароль')}"><i class="bi bi-copy"></i></button>
                <button class="action-btn" data-quick-refresh="${p.id}" title="${escapeAttr(window.__T__?.generate_new || 'Сгенерировать новый')}"><i class="bi bi-arrow-repeat"></i></button>
                <button class="action-btn" data-edit-id="${p.id}" title="${window.__T__.edit}"><i class="bi bi-pencil"></i></button>
                <button class="action-btn text-danger ms-auto" data-delete-id="${p.id}" title="${window.__T__.delete}"><i class="bi bi-trash"></i></button>
            </div>
        `;
        container.appendChild(div);
    });

    if (allPasswordsVisible) applyPasswordVisibility();
    initSortable();
}

function initSortable() {
    const container = document.getElementById('passwords-container');
    if (!container || typeof Sortable === 'undefined') return;

    if (sortableInstance) sortableInstance.destroy();

    sortableInstance = new Sortable(container, {
        animation: 250,
        ghostClass: "sortable-ghost",
        dragClass: "sortable-drag",
        handle: ".vault-item",
        filter: ".action-btn, .dropdown-menu, button, input",
        preventOnFilter: false,
        onEnd: function (evt) {
            const order = Array.from(container.children).map(el => parseInt(el.dataset.id, 10)).filter(id => !isNaN(id));

            csrfFetch('/api/save_order', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({ order: order })
            }).then(r => r.json()).then(res => {
                if (res.status === 'success') {
                    order.forEach((id, index) => {
                        const p = allPasswords.find(x => x.id === id);
                        if (p) p.sort_order = index;
                    });
                    showToast(window.__T__?.order_saved || 'Порядок сохранён', 'info');
                } else {
                    showToast((window.__T__?.order_save_failed || 'Ошибка сохранения порядка') + ': ' + res.message, 'error');
                }
            }).catch(err => {
                if (err && err.message === 'redirect') return;
                showToast(window.__T__?.network_error || 'Ошибка сети', 'error');
            });
        }
    });
}

function togglePasswordVisibility(inputId, button) {
    const input = document.getElementById(inputId); const icon = button.querySelector('i');
    input.type = input.type === 'password' ? 'text' : 'password';
    icon.className = input.type === 'password' ? 'bi bi-eye' : 'bi bi-eye-slash';
}

function toggleView(id, btn) {
    const p = allPasswords.find(x => x.id === id); if (!p) return;
    const el = document.getElementById(`pwd-${id}`); if (!el) return;
    const icon = btn.querySelector('i');
    if (el.textContent === '••••••••') {
        el.textContent = p.password_error ? (window.__T__.decryption_error || '<ошибка>') : p.password;
        icon.className = 'bi bi-eye-slash';
    } else {
        el.textContent = '••••••••';
        icon.className = 'bi bi-eye';
    }
}

function showAddModal() {
    if (typeof hibpTimer !== 'undefined') clearTimeout(hibpTimer);
    document.getElementById('addForm').reset();
    document.getElementById('editId').value = '';
    document.getElementById('passwordInput').type = 'password';
    document.getElementById('hibp-warning').style.display = 'none';
    document.getElementById('hibp-success').style.display = 'none';
    document.querySelector('#addModal .modal-title').textContent = window.__T__.new_password || 'Новый';
    document.getElementById('saveBtn').textContent = window.__T__.save || 'Сохранить';
    const uncategorizedLabel = window.__T__?.uncategorized || 'Без категории';
    const cats = [...new Set(allPasswords.map(p => p.category || uncategorizedLabel))];
    document.getElementById('category-list-data').innerHTML = cats.map(c => `<option value="${escapeAttr(c)}">`).join('');
    if (addModalInstance) addModalInstance.show();
    closeSidebar();
}

function editPassword(id) {
    if (typeof hibpTimer !== 'undefined') clearTimeout(hibpTimer);
    const p = allPasswords.find(x => x.id === id); if (!p) return;
    const form = document.getElementById('addForm');
    document.getElementById('editId').value = p.id;
    form.service_name.value = p.service_name || '';
    form.category.value = p.category || (window.__T__?.uncategorized || 'Без категории');
    form.username.value = p.username || '';
    form.url.value = p.url || '';
    form.notes.value = p.notes || '';
    form.password.value = p.password || '';
    form.expires_at.value = p.expires_at ? p.expires_at.split(' ')[0] : '';
    document.getElementById('passwordInput').type = 'text';
    checkHIBP(p.password || '', p.id);
    document.querySelector('#addModal .modal-title').textContent = window.__T__.edit || 'Редактировать';
    document.getElementById('saveBtn').textContent = window.__T__.save || 'Сохранить';
    if (addModalInstance) addModalInstance.show();
}

function submitForm() {
    const form = document.getElementById('addForm');
    const data = Object.fromEntries(new FormData(form).entries());
    if (!data.service_name.trim() || !data.username.trim() || !data.password) { showToast(window.__T__.fill_required || 'Заполните поля', 'error'); return; }
    if (!data.category) data.category = window.__T__?.uncategorized || 'Без категории';
    const editId = document.getElementById('editId').value;

    const url = editId ? '/api/update_password' : '/api/add_password';
    const payload = editId ? { ...data, id: parseInt(editId, 10) } : data;

    const btn = document.getElementById('saveBtn');
    btn.disabled = true;
    btn.innerHTML = '<span class="spinner-border spinner-border-sm me-1"></span>...';

    csrfFetch(url, { method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(payload) })
    .then(r => r.json()).then(res => {
        btn.disabled = false;
        btn.textContent = window.__T__.save || 'Сохранить';
        if (handleMustChange(res)) return;
        if (res.status === 'success') {
            if (addModalInstance) addModalInstance.hide();
            showToast(editId ? window.__T__.updated || 'Обновлено' : window.__T__.saved || 'Сохранено', 'success');
            loadPasswords();
        } else showToast((window.__T__.error || 'Ошибка') + ': ' + res.message, 'error');
    }).catch(err => {
        btn.disabled = false;
        btn.textContent = window.__T__.save || 'Сохранить';
        if (err && err.message === 'redirect') return;
        showToast((window.__T__.network_error || 'Ошибка сети') + ': ' + err.message, 'error');
    });
}

function openDeleteConfirm(id) {
    const p = allPasswords.find(x => x.id === id); if (!p) return;
    const deleteText = window.__T__?.delete_record_desc || 'Запись «{name}» будет перемещена в корзину.';
    document.getElementById('confirmDeleteText').textContent =
        deleteText.replace('{name}', p.service_name);

    const btn = document.getElementById('confirmDeleteBtn');
    const newBtn = btn.cloneNode(true);
    btn.parentNode.replaceChild(newBtn, btn);

    newBtn.addEventListener('click', () => {
        confirmDeleteModalInstance.hide();
        deletePassword(id);
    });

    confirmDeleteModalInstance.show();
}

function deletePassword(id) {
    const p = allPasswords.find(x => x.id === id); if (!p) return;

    const card = document.querySelector(`.vault-item[data-id="${id}"]`);
    if (card) {
        card.classList.add('deleting');
        setTimeout(() => { allPasswords = allPasswords.filter(x => x.id !== id); renderCategories(); filterPasswords(); }, 300);
    } else {
        allPasswords = allPasswords.filter(x => x.id !== id); renderCategories(); filterPasswords();
    }

    csrfFetch(`/api/delete_password/${id}`, {method: 'DELETE'}).then(r => r.json()).then(res => {
        if (handleMustChange(res)) return;
        if (res.status === 'success') {
            showToast(window.__T__.deleted_toast || 'В корзине', 'success', window.__T__.undo || 'Отменить', () => {
                csrfFetch(`/api/restore_password/${id}`, { method: 'POST' }).then(r => r.json()).then(r => {
                    if (r.status === 'success') { showToast(window.__T__.restored, 'success'); loadPasswords(); }
                    else showToast((window.__T__.error || 'Ошибка') + ': ' + r.message, 'error');
                });
            });
        } else {
            showToast((window.__T__.error || 'Ошибка') + ': ' + res.message, 'error');
        }
    }).catch(err => {
        if (err && err.message === 'redirect') return;
        showToast((window.__T__.network_error || 'Ошибка сети') + ': ' + err.message, 'error');
    })
      .finally(() => loadPasswords());
}

function showQR(id) {
    const p = allPasswords.find(x => x.id === id); if (!p || !p.url) { showToast(window.__T__.no_link || 'Нет ссылки', 'warning'); return; }
    document.getElementById('qrImage').src = `/api/qr?text=${encodeURIComponent(p.url)}`;
    if (qrModalInstance) qrModalInstance.show();
}

function showHistory(passwordId) {
    const list = document.getElementById('historyList');
    list.innerHTML = '<div class="text-center py-3"><div class="spinner-border text-primary"></div></div>';
    historyModalInstance.show();
    csrfFetch(`/api/get_history/${passwordId}`).then(r => r.json()).then(data => {
        if (data.status !== 'success') { list.innerHTML = `<p class="text-danger">${escapeHtml(data.message)}</p>`; return; }
        if (!data.data.length) { list.innerHTML = `<p class="text-muted text-center">${window.__T__.history_empty || 'История пуста'}</p>`; return; }
        const labels = { service_name: window.__T__.service, username: window.__T__.login, password: window.__T__.password, url: window.__T__.url, notes: window.__T__.notes, category: window.__T__.category, expires_at: 'Срок действия' };
        list.innerHTML = '<div class="timeline">' + data.data.map(h => {
            const diffs = Object.entries(h.diff || {}).map(([k, v]) => `<div class="small mb-1"><span class="fw-bold">${labels[k] || k}:</span> <span class="text-danger text-decoration-line-through">${escapeHtml(String(v.from ?? '').slice(0, 60))}</span><i class="bi bi-arrow-right mx-1"></i><span class="text-success">${escapeHtml(String(v.to ?? '').slice(0, 60))}</span></div>`).join('');
            return `<div class="timeline-item">
                <div class="timeline-date">${escapeHtml(h.changed_at)}</div>
                <div class="timeline-content">
                    <div class="d-flex justify-content-between align-items-center mb-2">
                        <span class="fw-bold">${escapeHtml(h.changed_by)}</span>
                        <span class="badge ${h.change_type === 'password' ? 'bg-warning text-dark' : 'bg-secondary'}">${h.change_type === 'password' ? (window.__T__.pwd_change || 'Смена пароля') : (window.__T__.fields_change || 'Изменение полей')}</span>
                    </div>
                    ${diffs || '<div class="text-muted small">—</div>'}
                </div>
            </div>`;
        }).join('') + '</div>';
    }).catch(err => {
        if (err && err.message === 'redirect') return;
        list.innerHTML = `<p class="text-danger">${window.__T__.error}: ${escapeHtml(err.message)}</p>`;
    });
}

function openCommandPalette() {
    if (window._mustChange) { showChangePasswordModal(true); return; }
    if (!cmdModalInstance) cmdModalInstance = new bootstrap.Modal(document.getElementById('cmdPaletteModal'));
    const input = document.getElementById('cmdInput'); input.value = '';
    cmdResults = allPasswords.slice(0, 10); cmdActiveIdx = 0; renderCmdResults();
    cmdModalInstance.show(); setTimeout(() => input.focus(), 150);
}

document.addEventListener('input', e => { if (e.target.id === 'cmdInput') filterCommandPalette(e.target.value); });
document.addEventListener('keydown', e => {
    const modal = document.getElementById('cmdPaletteModal');
    if (!modal || !modal.classList.contains('show')) return;
    if (e.key === 'ArrowDown') { e.preventDefault(); cmdActiveIdx = Math.min(cmdActiveIdx + 1, cmdResults.length - 1); renderCmdResults(); }
    else if (e.key === 'ArrowUp') { e.preventDefault(); cmdActiveIdx = Math.max(cmdActiveIdx - 1, 0); renderCmdResults(); }
    else if (e.key === 'Enter') {
        e.preventDefault();
        const item = cmdResults[cmdActiveIdx];
        if (item) {
            if (item.isCommand) item.action();
            else if (e.ctrlKey) pickCommandPassword(item.id);
            else pickCommand(item.id);
        }
    }
});

const CMD_ACTIONS = [
    { title: window.__T__?.new_password || 'Новый', icon: 'plus-circle', action: () => { cmdModalInstance.hide(); showAddModal(); } },
    { title: window.__T__?.trash || 'Корзина', icon: 'trash', action: () => { window.location.href='/trash'; } },
    { title: window.__T__?.change_pwd || 'Сменить пароль', icon: 'key', action: () => { cmdModalInstance.hide(); showChangePasswordModal(false); } },
    { title: window.__T__?.privacy_mode || 'Приватность', icon: 'incognito', action: () => { cmdModalInstance.hide(); togglePrivacyMode(); } }
];

if (window.__USER__ && ['admin', 'manager'].includes(window.__USER__.role)) {
    CMD_ACTIONS.push({ title: window.__T__?.admin_panel || 'Админка', icon: 'gear', action: () => { window.location.href='/admin'; } });
    CMD_ACTIONS.push({ title: window.__T__?.logs || 'Логи', icon: 'list-ul', action: () => { window.location.href='/logs'; } });
}

function filterCommandPalette(q) {
    const query = (q || '').toLowerCase().trim();
    if (query.startsWith('>')) {
        const cmdQuery = query.slice(1).trim();
        cmdResults = CMD_ACTIONS.filter(c => c.title.toLowerCase().includes(cmdQuery)).map(c => ({ ...c, isCommand: true }));
    } else {
        if (!query) cmdResults = allPasswords.slice(0, 10);
        else cmdResults = allPasswords.filter(p => (p.service_name || '').toLowerCase().includes(query) || (p.username || '').toLowerCase().includes(query) || (p.url || '').toLowerCase().includes(query)).slice(0, 20);
    }
    cmdActiveIdx = 0; renderCmdResults();
}

function renderCmdResults() {
    const box = document.getElementById('cmdResults');
    if (!cmdResults.length) { box.innerHTML = `<p class="text-muted text-center py-3 mb-0">${window.__T__.nothing_found || 'Ничего не найдено'}</p>`; return; }
    box.innerHTML = cmdResults.map((p, i) => {
        if (p.isCommand) {
            return `<div class="d-flex align-items-center gap-3 p-2 rounded-3 cmd-result-item ${i === cmdActiveIdx ? 'active' : ''}" style="cursor:pointer;" onclick="cmdResults[${i}].action()">
                <div class="rounded-circle d-flex align-items-center justify-content-center" style="width:36px;height:36px;background:var(--bg-base);"><i class="bi bi-${p.icon} text-primary"></i></div>
                <div class="fw-bold">${escapeHtml(p.title)}</div>
            </div>`;
        }
        return `<div class="d-flex align-items-center gap-3 p-2 rounded-3 cmd-result-item ${i === cmdActiveIdx ? 'active' : ''}" style="cursor:pointer;" onclick="pickCommand(${p.id})">
            <div class="service-icon" style="width:36px;height:36px;border-radius:10px;"><span class="fw-bold" style="color:var(--brand);">${escapeHtml((p.service_name||'?').charAt(0))}</span></div>
            <div class="flex-grow-1"><div class="fw-bold">${escapeHtml(p.service_name)}</div><div class="small text-muted">${escapeHtml(p.username || '—')}</div></div>
            <i class="bi bi-copy text-muted"></i>
        </div>`;
    }).join('');
}

function pickCommand(id) {
    const p = allPasswords.find(x => x.id === id); if (!p) return;
    navigator.clipboard.writeText(p.username || '').then(() => { showClipboardToast(); showToast(window.__T__.login_copied || 'Скопировано', 'success'); });
    if (cmdModalInstance) cmdModalInstance.hide();
    csrfFetch(`/api/mark_used/${id}`, {method: 'POST'}).catch(() => {});
}

function pickCommandPassword(id) {
    const p = allPasswords.find(x => x.id === id); if (!p) return;
    navigator.clipboard.writeText(p.password || '').then(() => { showClipboardToast(); showToast(window.__T__.password_copied || 'Скопировано', 'success'); });
    if (cmdModalInstance) cmdModalInstance.hide();
    csrfFetch(`/api/mark_used/${id}`, {method: 'POST'}).catch(() => {});
}

setTimeout(() => {
    const loader = document.getElementById('skeleton-loading');
    if (loader && !loader.classList.contains('force-hidden')) { hideEl(loader); showError(window.__T__.server_error || 'Сервер не отвечает.'); }
}, 12000);

window.showAddModal = showAddModal;
window.editPassword = editPassword;
window.deletePassword = deletePassword;
window.toggleFavorite = toggleFavorite;
window.togglePin = togglePin;
window.sharePassword = sharePassword;
window.copyShareLink = copyShareLink;
window.showQR = showQR;
window.showHistory = showHistory;
window.toggleFilterChip = toggleFilterChip;
window.togglePrivacyMode = togglePrivacyMode;
window.toggleAllPasswords = toggleAllPasswords;
window.openGenerator = openGenerator;
window.copyGenerated = copyGenerated;
window.useGenerated = useGenerated;
window.clearClipboardNow = clearClipboardNow;
window.showImportModal = showImportModal;
window.startImport = startImport;
window.submitForm = submitForm;
window.togglePasswordVisibility = togglePasswordVisibility;
window.openCommandPalette = openCommandPalette;
window.pickCommand = pickCommand;
window.pickCommandPassword = pickCommandPassword;
window.resetFilters = resetFilters;
window.loadPasswords = loadPasswords;
window.generatePassword = generatePassword;
window.toggleView = toggleView;
window.filterPasswordsDebounced = filterPasswordsDebounced;
window.openDeleteConfirm = openDeleteConfirm;
window.exportPasswords = exportPasswords;
window.performExport = performExport;
window.confirmShare = confirmShare;
