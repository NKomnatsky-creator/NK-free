let changePwdModalInstance = null;
let forceChange = false;
let _bootstrapRetries = 0;

window.showChangePasswordModal = function(force = false) {
    if (typeof bootstrap === 'undefined') {
        if (_bootstrapRetries++ > 50) {
            showToast(window.__T__?.bootstrap_not_loaded || 'Bootstrap не загрузился', 'error');
            return;
        }
        setTimeout(() => window.showChangePasswordModal(force), 100);
        return;
    }
    _bootstrapRetries = 0;
    forceChange = force;

    const form = document.getElementById('changePwdForm');
    if (form) form.reset();
    const bar = document.getElementById('pwd-strength-bar');
    if (bar) {
        bar.style.width = '0%';
        bar.style.background = '';
    }
    const text = document.getElementById('pwd-strength-text');
    if (text) text.textContent = '';

    // Сброс состояния галочки
    const confirmGroup = document.getElementById('confirmPwdGroup');
    if (confirmGroup) {
        confirmGroup.classList.remove('match-ok', 'match-error', 'shake');
        const icon = confirmGroup.querySelector('i');
        if (icon) icon.className = 'bi bi-check-circle';
    }

    // Скрываем предупреждение Caps Lock
    document.querySelectorAll('.caps-lock-warning').forEach(el => el.classList.remove('show'));

    if (typeof window.hibpTimer !== 'undefined') clearTimeout(window.hibpTimer);

    if (force) {
        document.getElementById('closePwdModalBtn').style.display = 'none';
        document.getElementById('cancelPwdBtn').style.display = 'none';
        const logoutBtn = document.getElementById('logoutPwdBtn');
        if (logoutBtn) logoutBtn.style.display = 'block';
    } else {
        document.getElementById('closePwdModalBtn').style.display = 'block';
        document.getElementById('cancelPwdBtn').style.display = 'block';
        const logoutBtn = document.getElementById('logoutPwdBtn');
        if (logoutBtn) logoutBtn.style.display = 'none';
    }

    if (!changePwdModalInstance) {
        changePwdModalInstance = new bootstrap.Modal(document.getElementById('changePwdModal'));
    }
    changePwdModalInstance.show();
};

// ✅ Функция для показа/скрытия пароля в инпуте
window.togglePwdVisibility = function(inputId, btn) {
    const input = document.getElementById(inputId);
    const icon = btn.querySelector('i');
    if (input.type === 'password') {
        input.type = 'text';
        icon.className = 'bi bi-eye-slash';
    } else {
        input.type = 'password';
        icon.className = 'bi bi-eye';
    }
};

// ✅ Проверка совпадения паролей
window.checkPasswordMatch = function() {
    const newPwd = document.getElementById('newPasswordInput').value;
    const confirmPwd = document.getElementById('confirmPasswordInput').value;
    const group = document.getElementById('confirmPwdGroup');
    const icon = group.querySelector('i');

    if (!confirmPwd) {
        group.classList.remove('match-ok', 'match-error', 'shake');
        icon.className = 'bi bi-check-circle';
        return;
    }

    if (newPwd === confirmPwd) {
        group.classList.remove('match-error', 'shake');
        group.classList.add('match-ok');
        icon.className = 'bi bi-check-circle-fill';
    } else {
        group.classList.remove('match-ok', 'shake');
        group.classList.add('match-error');
        icon.className = 'bi bi-x-circle-fill';
    }
};

// ✅ Функция для тряски элемента
function shakeElement(el) {
    if (!el) return;
    el.classList.remove('shake');
    // Трюк для перезапуска анимации
    void el.offsetWidth;
    el.classList.add('shake');
    setTimeout(() => el.classList.remove('shake'), 500);
}

// ✅ Обработка Caps Lock
function checkCapsLock(e, warningId) {
    const warning = document.getElementById(warningId);
    if (!warning) return;
    if (e.getModifierState && e.getModifierState('CapsLock')) {
        warning.classList.add('show');
    } else {
        warning.classList.remove('show');
    }
}

function updateStrengthBar() {
    const pwd = document.getElementById('newPasswordInput').value;
    let score = 0;
    if (pwd.length >= 8) score++;
    if (pwd.length >= 12) score++;
    if (/[A-Z]/.test(pwd)) score++;
    if (/[0-9]/.test(pwd)) score++;
    if (/[^A-Za-z0-9]/.test(pwd)) score++;

    let width = 0;
    let bg = '';
    let text = '';
    let color = '';

    if (pwd.length > 0) {
        if (score <= 2) {
            width = 33;
            bg = 'linear-gradient(90deg, #ef4444, #f87171)';
            text = window.__T__?.strength_weak || 'Слабый';
            color = '#ef4444';
        } else if (score <= 4) {
            width = 66;
            bg = 'linear-gradient(90deg, #f59e0b, #fbbf24)';
            text = window.__T__?.strength_medium || 'Средний';
            color = '#f59e0b';
        } else {
            width = 100;
            bg = 'linear-gradient(90deg, #10b981, #34d399)';
            text = window.__T__?.strength_strong || 'Надёжный';
            color = '#10b981';
        }
    }

    const bar = document.getElementById('pwd-strength-bar');
    const textEl = document.getElementById('pwd-strength-text');

    if (bar) {
        bar.style.width = width + '%';
        bar.style.background = bg;
    }
    if (textEl) {
        textEl.textContent = text;
        textEl.style.color = color;
    }

    // При изменении нового пароля проверяем совпадение с подтверждением
    checkPasswordMatch();
}

document.addEventListener('DOMContentLoaded', () => {
    const input = document.getElementById('newPasswordInput');
    if (input) {
        input.addEventListener('input', updateStrengthBar);
        input.addEventListener('keyup', (e) => checkCapsLock(e, 'capsLockNew'));
    }

    const confirmInput = document.getElementById('confirmPasswordInput');
    if (confirmInput) {
        confirmInput.addEventListener('keyup', (e) => checkCapsLock(e, 'capsLockConfirm'));
    }

    const oldInput = document.querySelector('input[name="old_password"]');
    if (oldInput) {
        oldInput.addEventListener('keyup', (e) => checkCapsLock(e, 'capsLockOld'));
    }
});

window.submitChangePassword = function() {
    const form = document.getElementById('changePwdForm');
    const data = Object.fromEntries(new FormData(form).entries());

    if (data.new_password !== data.confirm_password) {
        shakeElement(document.getElementById('confirmPwdGroup'));
        showToast(window.__T__?.password_mismatch || 'Пароли не совпадают', 'error');
        return;
    }
    if (data.new_password.length < 8) {
        shakeElement(document.getElementById('newPasswordInput').closest('.pwd-input-group'));
        showToast(window.__T__?.password_too_short || 'Пароль слишком короткий (мин. 8)', 'error');
        return;
    }
    if (!data.old_password) {
        shakeElement(document.querySelector('input[name="old_password"]').closest('.pwd-input-group'));
        showToast(window.__T__?.enter_current_password || 'Введите текущий пароль', 'error');
        return;
    }

    const btn = document.getElementById('changePwdBtn');
    btn.disabled = true;
    btn.innerHTML = '<span class="spinner-border spinner-border-sm me-1"></span>...';

    csrfFetch('/api/change_own_password', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({old_password: data.old_password, new_password: data.new_password})
    }).then(r => r.json()).then(res => {
        btn.disabled = false;
        btn.textContent = window.__T__?.save || 'Сменить';
        if (res.status === 'success') {
            window._mustChange = false;
            changePwdModalInstance.hide();
            showToast(window.__T__?.password_changed || 'Пароль изменён!', 'success');
            setTimeout(() => window.location.href = '/dashboard', 800);
        } else {
            shakeElement(form.querySelector('input[name="old_password"]').closest('.pwd-input-group'));
            showToast((window.__T__?.error || 'Ошибка') + ': ' + res.message, 'error');
        }
    }).catch(err => {
        btn.disabled = false;
        btn.textContent = window.__T__?.save || 'Сменить';
        if (err && err.message === 'redirect') return;
        showToast((window.__T__?.network_error || 'Ошибка сети') + ': ' + err.message, 'error');
    });
};

window.handleMustChange = function(res) {
    if (res && res.code === 'MUST_CHANGE_PWD') {
        window._mustChange = true;
        if (typeof window.showChangePasswordModal === 'function') {
            window.showChangePasswordModal(true);
        } else {
            showToast(res.message || window.__T__?.must_change_password || 'Необходимо сменить пароль', 'error');
            setTimeout(() => window.location.href = '/dashboard', 1500);
        }
        return true;
    }
    return false;
};