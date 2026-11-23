let trashItems = [];
let purgeModalInstance = null;

document.addEventListener('DOMContentLoaded', () => {
    const modalEl = document.getElementById('purgeConfirmModal');
    if (modalEl && typeof bootstrap !== 'undefined') {
        purgeModalInstance = new bootstrap.Modal(modalEl);
    }
    loadTrash();
});

function loadTrash() {
    const list = document.getElementById('trash-list');
    const empty = document.getElementById('trash-empty');
    const purgeBtn = document.getElementById('purge-all-btn');
    
    if (list) list.innerHTML = '<div class="text-center py-5"><div class="spinner-border text-primary"></div></div>';
    if (empty) empty.style.display = 'none';

    csrfFetch('/api/trash').then(r => r.json()).then(res => {
        if (res.status !== 'success') {
            if (list) list.innerHTML = '';
            showToast(res.message || window.__T__?.load_failed || 'Ошибка загрузки', 'error');
            return;
        }
        
        trashItems = res.data || [];
        
        if (trashItems.length === 0) {
            if (list) list.innerHTML = '';
            if (empty) empty.style.display = 'flex';
            if (purgeBtn) purgeBtn.style.display = 'none';
            return;
        }

        if (purgeBtn) purgeBtn.style.display = 'block';
        if (empty) empty.style.display = 'none';

        if (list) {
            list.innerHTML = trashItems.map(p => `
                <div class="glass-card p-3 d-flex flex-column flex-md-row align-items-md-center justify-content-between gap-3">
                    <div class="d-flex align-items-center gap-3">
                        <div class="service-icon bg-base">
                            <i class="bi bi-file-earmark-lock text-muted fs-5"></i>
                        </div>
                        <div>
                            <div class="fw-bold">${escapeHtml(p.service_name)}</div>
                            <div class="text-muted small">${escapeHtml(p.username || '—')}</div>
                        </div>
                    </div>
                    <div class="d-flex align-items-center gap-2">
                        <button class="btn btn-sm btn-outline-success rounded-pill px-3" onclick="restoreItem(${p.id})">
                            <i class="bi bi-arrow-counterclockwise me-1"></i> ${window.__T__?.restore || 'Восстановить'}
                        </button>
                        <button class="btn btn-sm btn-outline-danger rounded-pill px-3" data-purge-id="${p.id}" data-purge-name="${escapeAttr(p.service_name)}">
                            <i class="bi bi-trash me-1"></i> ${window.__T__?.purge || 'Удалить'}
                        </button>
                    </div>
                </div>
            `).join('');
            list.querySelectorAll('[data-purge-id]').forEach(btn => {
                btn.addEventListener('click', () => window.openPurgeConfirm(Number(btn.dataset.purgeId), btn.dataset.purgeName));
            });
        }
    }).catch(err => {
        if (err && err.message === 'redirect') return;
        if (list) list.innerHTML = '';
        showToast(window.__T__?.network_error || 'Ошибка сети', 'error');
    });
}

function restoreItem(id) {
    csrfFetch(`/api/restore_password/${id}`, { method: 'POST' })
        .then(r => r.json())
        .then(res => {
            if (res.status === 'success') {
                showToast(window.__T__?.restored || 'Восстановлено', 'success');
                loadTrash();
            } else {
                showToast(res.message || (window.__T__?.error || 'Ошибка'), 'error');
            }
        }).catch(() => showToast(window.__T__?.network_error || 'Ошибка сети', 'error'));
}

// ✅ Открытие красивой модалки вместо confirm()
window.openPurgeConfirm = function(id, name) {
    if (!purgeModalInstance) return;
    const textEl = document.getElementById('purgeConfirmText');
    if (textEl) textEl.textContent = `${window.__T__?.purge_record_prompt || 'Запись'} "${name}" ${window.__T__?.purge_will_deleted || 'будет удалена безвозвратно.'}`;
    
    const btn = document.getElementById('confirmPurgeBtn');
    const newBtn = btn.cloneNode(true);
    btn.parentNode.replaceChild(newBtn, btn);
    
    newBtn.addEventListener('click', () => {
        purgeModalInstance.hide();
        purgeItem(id);
    });
    
    purgeModalInstance.show();
};

window.openPurgeAllConfirm = function() {
    if (!purgeModalInstance) return;
    const textEl = document.getElementById('purgeConfirmText');
    if (textEl) textEl.textContent = window.__T__?.confirm_purge_all || 'ВСЕ записи из корзины будут удалены безвозвратно.';
    
    const btn = document.getElementById('confirmPurgeBtn');
    const newBtn = btn.cloneNode(true);
    btn.parentNode.replaceChild(newBtn, btn);
    
    newBtn.addEventListener('click', () => {
        purgeModalInstance.hide();
        purgeAll();
    });
    
    purgeModalInstance.show();
};

function purgeItem(id) {
    csrfFetch(`/api/purge_password/${id}`, { method: 'DELETE' })
        .then(r => r.json())
        .then(res => {
            if (res.status === 'success') {
                showToast(window.__T__?.purged || 'Удалено навсегда', 'success');
                loadTrash();
            } else {
                showToast(res.message || (window.__T__?.error || 'Ошибка'), 'error');
            }
        }).catch(() => showToast(window.__T__?.network_error || 'Ошибка сети', 'error'));
}

function purgeAll() {
    const promises = trashItems.map(p => csrfFetch(`/api/purge_password/${p.id}`, { method: 'DELETE' }).then(r => r.json()));
    Promise.all(promises).then(() => {
        showToast(window.__T__?.trash_cleared || 'Корзина очищена', 'success');
        loadTrash();
    }).catch(() => showToast(window.__T__?.purge_failed || 'Ошибка при очистке', 'error'));
}