let sharedPwdCopied = false;

function toggleSharedPwd(btn) {
    const input = document.getElementById('sharedPwdInput');
    const icon = btn.querySelector('i');
    if (input.type === 'password') {
        input.type = 'text';
        icon.className = 'bi bi-eye-slash';
    } else {
        input.type = 'password';
        icon.className = 'bi bi-eye';
    }
}

function copySharedPwd() {
    const input = document.getElementById('sharedPwdInput');
    navigator.clipboard.writeText(input.value).then(() => {
        sharedPwdCopied = true;
        showToast(window.__T__.copied || 'Скопировано', 'success');
    }).catch(() => {
        showToast(window.__T__.error || 'Ошибка', 'error');
    });
}

function unlockShare() {
    const pwd = (document.getElementById('sharePasswordInput') || {}).value || '';
    const token = (document.getElementById('shareToken') || {}).value || '';
    const err = document.getElementById('shareUnlockError');
    if (err) err.classList.add('d-none');
    csrfFetch('/api/share_unlock', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ token: token, password: pwd })
    })
        .then(r => r.json())
        .then(res => {
            if (!res || res.status !== 'success') {
                const message = (res && res.message) || window.__T__.error || 'Ошибка';
                if (err) { err.textContent = message; err.classList.remove('d-none'); }
                return;
            }
            const data = res.data || {};
            const service = document.getElementById('shareService');
            if (service) service.textContent = data.service_name || '';
            const login = document.getElementById('shareLogin');
            if (login) login.textContent = data.username || '';
            const input = document.getElementById('sharedPwdInput');
            if (input) input.value = data.password || '';
            const unlockBox = document.getElementById('shareUnlockBox');
            const resultBox = document.getElementById('shareResultBox');
            if (unlockBox) unlockBox.classList.add('d-none');
            if (resultBox) resultBox.classList.remove('d-none');
        })
        .catch(e => {
            if (e && e.message === 'redirect') return;
            if (err) {
                err.textContent = (window.__T__.network_error || 'Ошибка сети') + ': ' + (e.message || '');
                err.classList.remove('d-none');
            }
        });
}

window.addEventListener('beforeunload', (e) => {
    const input = document.getElementById('sharedPwdInput');
    if (!sharedPwdCopied && input && input.value) {
        e.preventDefault();
        e.returnValue = window.__T__.share_confirm || 'Пароль не скопирован! Ссылка сгорит. Уверены?';
        return e.returnValue;
    }
});

window.toggleSharedPwd = toggleSharedPwd;
window.copySharedPwd = copySharedPwd;
window.unlockShare = unlockShare;