function csrfFetch(url, options = {}) {
    const token = document.querySelector('meta[name="csrf-token"]')?.content;
    options.headers = options.headers || {};
    if (token) options.headers['X-CSRFToken'] = token;

    return fetch(url, options).then(async (res) => {
        if (res.status === 401) {
            let data = null;
            try {
                data = await res.clone().json();
            } catch (_) {
                data = null;
            }
            if (data && data.redirect) {
                window.location.href = data.redirect;
                return Promise.reject(new Error('redirect'));
            }
        }
        return res;
    });
}

function escapeHtml(t) {
    if (t === null || t === undefined) return '';
    const d = document.createElement('div');
    d.textContent = String(t);
    return d.innerHTML;
}

function escapeAttr(t) {
    if (t === null || t === undefined) return '';
    return String(t)
        .replace(/&/g, '&amp;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;');
}

function showToast(message, type = 'success', actionText = null, actionCallback = null) {
    const container = document.getElementById('toastContainer');
    if (!container) return;
    const toast = document.createElement('div');
    const toneClass = type === 'error' ? 'toast--danger'
        : type === 'warning' ? 'toast--warning'
        : type === 'info' ? 'toast--info'
        : 'toast--success';
    toast.className = `toast align-items-center text-white ${toneClass} border-0 rounded-4 shadow-lg`;
    const icon = type === 'success' ? 'bi-check-circle-fill'
        : type === 'info' ? 'bi-info-circle-fill'
        : 'bi-exclamation-triangle-fill';

    let actionHtml = '';
    if (actionText) {
        toast.dataset.hasAction = 'true';
        actionHtml = `<button class="toast-action-btn">${escapeHtml(actionText)}</button>`;
    }

    toast.innerHTML = `
        <div class="d-flex p-2 align-items-center">
            <div class="toast-body d-flex align-items-center gap-2 fw-bold">
                <i class="bi ${icon} fs-5"></i> <span>${escapeHtml(message)}</span>
                ${actionHtml}
            </div>
            <button type="button" class="btn-close btn-close-white me-2 m-auto" data-bs-dismiss="toast"></button>
        </div>
    `;
    container.appendChild(toast);

    if (actionText && actionCallback) {
        const btn = toast.querySelector('.toast-action-btn');
        if (btn) {
            btn.addEventListener('click', (e) => {
                e.preventDefault();
                actionCallback();
                const inst = bootstrap.Toast.getInstance(toast);
                if (inst) inst.hide();
            });
        }
    }

    const bsToast = new bootstrap.Toast(toast, { delay: actionText ? 8000 : 3500 });
    bsToast.show();
    toast.addEventListener('hidden.bs.toast', () => toast.remove());
}

function toggleTheme() {
    const current = document.documentElement.getAttribute('data-bs-theme');
    const newTheme = current === 'dark' ? 'light' : 'dark';
    document.documentElement.setAttribute('data-bs-theme', newTheme);
    localStorage.setItem('theme', newTheme);
    document.querySelectorAll('.theme-toggle-icon').forEach(icon => {
        icon.className = newTheme === 'dark'
            ? 'bi bi-sun-fill fs-5 theme-toggle-icon'
            : 'bi bi-moon-stars-fill fs-5 theme-toggle-icon';
    });
}

function toggleSidebar() {
    const sidebar = document.getElementById('sidebar');
    const overlay = document.getElementById('sidebarOverlay');
    if (!sidebar || !overlay) return;
    if (sidebar.classList.contains('show')) { closeSidebar(); }
    else {
        sidebar.classList.add('show');
        overlay.classList.add('show');
        document.body.classList.add('sidebar-open');
        document.body.style.overflow = 'hidden';
    }
}

function closeSidebar() {
    const sidebar = document.getElementById('sidebar');
    const overlay = document.getElementById('sidebarOverlay');
    if (!sidebar || !overlay) return;
    sidebar.classList.remove('show');
    overlay.classList.remove('show');
    document.body.classList.remove('sidebar-open');
    document.body.style.overflow = '';
}

window.addEventListener('resize', () => {
    if (window.innerWidth >= 992) closeSidebar();
});

if ('serviceWorker' in navigator) {
    window.addEventListener('load', () => {
        navigator.serviceWorker.register('/static/service-worker.js').catch(() => {});
    });
}

(function initTheme() {
    const savedTheme = localStorage.getItem('theme');
    if (savedTheme) return;
    const serverDefault = window.__THEME_DEFAULT__ || 'system';
    const systemPrefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
    let theme;
    if (serverDefault === 'system') theme = systemPrefersDark ? 'dark' : 'light';
    else theme = serverDefault;
    document.documentElement.setAttribute('data-bs-theme', theme);
})();

document.addEventListener('DOMContentLoaded', () => {
    const current = document.documentElement.getAttribute('data-bs-theme');
    document.querySelectorAll('.theme-toggle-icon').forEach(icon => {
        icon.className = current === 'dark'
            ? 'bi bi-sun-fill fs-5 theme-toggle-icon'
            : 'bi bi-moon-stars-fill fs-5 theme-toggle-icon';
    });
});

/* --- Локализованное форматирование через Intl ------------------------- */
function currentLocale() {
    const lang = (document.documentElement.lang || 'ru').toLowerCase();
    return lang.startsWith('en') ? 'en-US' : 'ru-RU';
}

function formatDate(value, options) {
    if (value === null || value === undefined || value === '') return '—';
    const date = value instanceof Date ? value : new Date(value);
    if (Number.isNaN(date.getTime())) return String(value);
    try {
        return new Intl.DateTimeFormat(currentLocale(), options || { dateStyle: 'medium' }).format(date);
    } catch (_) {
        return date.toLocaleString();
    }
}

function formatNumber(value, options) {
    const num = Number(value);
    if (!Number.isFinite(num)) return '—';
    try {
        return new Intl.NumberFormat(currentLocale(), options).format(num);
    } catch (_) {
        return String(num);
    }
}

function formatCurrency(value, currency) {
    const num = Number(value);
    if (!Number.isFinite(num)) return '—';
    try {
        return new Intl.NumberFormat(currentLocale(), {
            style: 'currency',
            currency: currency || 'RUB',
            maximumFractionDigits: 2
        }).format(num);
    } catch (_) {
        return formatNumber(num, { maximumFractionDigits: 2 }) + ' ' + (currency || '');
    }
}

/* --- Единое пустое состояние ------------------------------------------ */
function emptyStateHtml(icon, title, text, compact) {
    return `<div class="empty-state${compact ? ' empty-state--compact' : ''}">
        <span class="empty-state__icon" aria-hidden="true"><i class="bi bi-${icon}"></i></span>
        <p class="empty-state__title">${escapeHtml(title || '')}</p>
        ${text ? `<p class="empty-state__text">${escapeHtml(text)}</p>` : ''}
    </div>`;
}

/* --- Возврат фокуса после закрытия модалки ---------------------------- */
document.addEventListener('show.bs.modal', (event) => {
    event.target._returnFocusEl = document.activeElement;
});

document.addEventListener('hidden.bs.modal', (event) => {
    const el = event.target._returnFocusEl;
    event.target._returnFocusEl = null;
    if (el && document.body.contains(el) && el.getClientRects().length && typeof el.focus === 'function') {
        el.focus();
    }
});