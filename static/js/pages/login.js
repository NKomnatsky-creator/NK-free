document.addEventListener('DOMContentLoaded', () => {
    const loginForm = document.getElementById('loginForm');
    if (loginForm) {
        const btn = document.getElementById('loginBtn');
        const originalHtml = btn ? btn.innerHTML : '';
        loginForm.addEventListener('submit', function() {
            if (btn) {
                btn.disabled = true;
                btn.innerHTML = '<span class="spinner-border spinner-border-sm me-2"></span>...';
            }
        });
        setTimeout(() => {
            if (btn && btn.disabled) {
                btn.disabled = false;
                btn.innerHTML = originalHtml;
            }
        }, 10000);
    }
});