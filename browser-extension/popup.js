const els = {
  server: document.getElementById('serverUrl'),
  token: document.getElementById('apiToken'),
  search: document.getElementById('search'),
  entries: document.getElementById('entries'),
  message: document.getElementById('message'),
  dot: document.getElementById('statusDot'),
  save: document.getElementById('saveBtn'),
  refresh: document.getElementById('refreshBtn'),
};

let entries = [];
let settings = { server: 'http://localhost:8000', token: '' };

function message(text, error = false) {
  els.message.textContent = text || '';
  els.message.classList.toggle('error', !!error);
}

function status(ok) {
  els.dot.classList.toggle('ok', ok);
  els.dot.classList.toggle('bad', !ok);
}

function normalizeServer(value) {
  let url = String(value || '').trim();
  if (url && !/^https?:\/\//i.test(url)) url = 'http://' + url;
  return url.replace(/\/+$/, '');
}

async function loadSettings() {
  const stored = await chrome.storage.local.get(['server', 'token']);
  settings = {
    server: normalizeServer(stored.server) || 'http://localhost:8000',
    token: stored.token || '',
  };
  els.server.value = settings.server;
  els.token.value = settings.token;
}

async function saveSettings() {
  settings.server = normalizeServer(els.server.value);
  settings.token = els.token.value.trim();
  if (!settings.server || !settings.token) {
    message('Укажите адрес сервера и API-токен', true);
    return;
  }
  let origin;
  try { origin = new URL(settings.server).origin + '/*'; }
  catch (_) { message('Неверный адрес сервера', true); return; }
  // Запрашиваем доступ к произвольному серверу только по действию пользователя.
  if (!(await chrome.permissions.contains({ origins: [origin] }))) {
    const granted = await chrome.permissions.request({ origins: [origin] });
    if (!granted) { message('Разрешите доступ к серверу в браузере', true); return; }
  }
  await chrome.storage.local.set(settings);
  message('Настройки сохранены');
  await loadEntries();
}

async function api(path, options = {}) {
  if (!settings.server || !settings.token) throw new Error('Не заданы сервер или токен');
  const response = await fetch(settings.server + path, {
    ...options,
    headers: {
      'Authorization': 'Bearer ' + settings.token,
      'Accept': 'application/json',
      ...(options.headers || {}),
    },
  });
  if (response.status === 401) {
    throw new Error('Токен недействителен или истёк');
  }
  let data;
  try { data = await response.json(); } catch (_) { data = null; }
  if (!response.ok || !data || data.status !== 'success') {
    throw new Error((data && data.message) || ('HTTP ' + response.status));
  }
  return data.data;
}

async function loadEntries() {
  els.refresh.disabled = true;
  message('Загрузка...');
  try {
    entries = await api('/api/passwords') || [];
    status(true);
    render();
    message(`Найдено записей: ${entries.length}`);
  } catch (err) {
    status(false);
    els.entries.innerHTML = `<div class="empty">${escapeHtml(err.message)}</div>`;
    message(err.message, true);
  } finally {
    els.refresh.disabled = false;
  }
}

function escapeHtml(value) {
  const div = document.createElement('div');
  div.textContent = value == null ? '' : String(value);
  return div.innerHTML;
}

function render() {
  const query = els.search.value.trim().toLowerCase();
  const visible = entries.filter(item => {
    const service = String(item.service_name || '').toLowerCase();
    const user = String(item.username || '').toLowerCase();
    return !query || service.includes(query) || user.includes(query);
  });
  if (!visible.length) {
    els.entries.innerHTML = '<div class="empty">Ничего не найдено</div>';
    return;
  }
  els.entries.innerHTML = visible.map(item => {
    const service = escapeHtml(item.service_name);
    const user = escapeHtml(item.username || '');
    const id = Number(item.id) || 0;
    return `<div class="entry">
      <div class="meta"><div class="service">${service}</div><div class="user">${user}</div></div>
      <button type="button" data-action="fill" data-id="${id}">Вставить</button>
      <button type="button" class="copy" data-action="copy" data-id="${id}">Копировать</button>
    </div>`;
  }).join('');
}

async function credentials(id) {
  // /api/passwords уже возвращает расшифрованные пароли для текущего пользователя.
  const all = await api('/api/passwords') || [];
  const item = all.find(p => Number(p.id) === Number(id));
  if (!item) throw new Error('Запись не найдена');
  if (!item.password || String(item.password).includes('•')) {
    throw new Error('Не удалось получить пароль — проверьте права токена');
  }
  return { username: item.username || '', password: String(item.password) };
}

async function withTab(callback) {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab || !tab.id) throw new Error('Нет активной вкладки');
  return callback(tab);
}

async function fill(id) {
  try {
    const cred = await credentials(id);
    await withTab(tab => chrome.scripting.executeScript({
      target: { tabId: tab.id },
      func: ({ username, password }) => {
        const userInputs = Array.from(document.querySelectorAll(
          'input[type="text"], input[type="email"], input[autocomplete="username"]'));
        const passInputs = Array.from(document.querySelectorAll('input[type="password"]'));
        if (!passInputs.length) return false;
        const pass = passInputs[0];
        const user = userInputs.find(i => !i.disabled && !i.readOnly) || null;
        const setValue = (input, value) => {
          const setter = Object.getOwnPropertyDescriptor(
            input instanceof HTMLTextAreaElement ? HTMLTextAreaElement.prototype
              : HTMLInputElement.prototype, 'value').set;
          setter.call(input, value);
          input.dispatchEvent(new Event('input', { bubbles: true }));
          input.dispatchEvent(new Event('change', { bubbles: true }));
        };
        if (user) setValue(user, username);
        setValue(pass, password);
        pass.focus();
        return true;
      },
      args: [cred],
    }));
    message('Данные вставлены');
  } catch (err) {
    message(err.message, true);
  }
}

async function copy(id) {
  try {
    const cred = await credentials(id);
    await navigator.clipboard.writeText(cred.password);
    message('Пароль скопирован');
  } catch (err) {
    message(err.message, true);
  }
}

els.save.addEventListener('click', saveSettings);
els.refresh.addEventListener('click', loadEntries);
els.search.addEventListener('input', render);
els.entries.addEventListener('click', event => {
  const button = event.target.closest('button[data-action]');
  if (!button) return;
  const id = Number(button.dataset.id);
  if (button.dataset.action === 'fill') fill(id);
  else copy(id);
});

loadSettings().then(() => { if (settings.token) loadEntries(); });
