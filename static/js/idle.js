let idleTimer;
let logoutCountdownInterval = null;
const IDLE_MS = 25 * 60 * 1000;

function resetIdleTimer() {
    clearTimeout(idleTimer);
    const overlay = document.getElementById('session-overlay');
    if (overlay && overlay.style.display === 'flex') return;
    idleTimer = setTimeout(() => {
        if (overlay) {
            overlay.style.display = 'flex';
            let sec = 60;
            const countdownEl = document.getElementById('logout-countdown');
            if (countdownEl) countdownEl.textContent = sec;
            if (logoutCountdownInterval) clearInterval(logoutCountdownInterval);
            logoutCountdownInterval = setInterval(() => {
                sec--;
                if (countdownEl) countdownEl.textContent = sec;
                if (sec <= 0) {
                    clearInterval(logoutCountdownInterval);
                    window.location.href = '/logout';
                }
            }, 1000);
        }
    }, IDLE_MS);
}

function extendSession() {
    const overlay = document.getElementById('session-overlay');
    if (overlay) overlay.style.display = 'none';
    if (logoutCountdownInterval) {
        clearInterval(logoutCountdownInterval);
        logoutCountdownInterval = null;
    }
    resetIdleTimer();
    csrfFetch('/api/ping').catch(() => {});
}

if (window.location.pathname !== '/login' && window.location.pathname !== '/') {
    ['mousemove', 'keydown', 'mousedown', 'touchstart', 'scroll'].forEach(evt =>
        document.addEventListener(evt, resetIdleTimer, true));

    document.addEventListener('visibilitychange', () => {
        if (!document.hidden) resetIdleTimer();
    });

    resetIdleTimer();
}