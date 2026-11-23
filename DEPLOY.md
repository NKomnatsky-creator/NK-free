# Развёртывание PassVault / NK Secure — Free

Документ для публичной free-сборки. В неё не входят Enterprise-модули
и связанные с ними секреты.

## Состав

- `app.py` — Flask-фронтенд и HTTP API (порт `8000` по умолчанию).
- `server.py` — внутренний сервер работы с базой (порт `5000`, по умолчанию только `127.0.0.1`).
- `database.py` — SQLite, шифрование, миграции.
- `start.py` — запускает оба процесса.
- `license.py` — заглушка free-редакции: только базовые функции, без сети и крипто.

**Важно:** порт `5000` не должен быть доступен извне. Внешним остаётся только
`8000` (желательно через HTTPS-прокси).

---

## Локальный запуск

Требуется Python 3.10+ (проверено на 3.12).

```bash
python -m pip install -r requirements.txt
python start.py
```

Откройте `http://localhost:8000`.

При первом запуске создаётся пользователь `admin`. Пароль берётся из
`DEFAULT_ADMIN_PASSWORD`, иначе генерируется случайно и записывается в
`DATA_DIR/.initial_admin_password` (права `0600`) — в логи он не попадает.
При первом входе система потребует смену пароля.

---

## Docker / Docker Compose

Готовый образ:

```bash
docker run -d --name nk-free -p 8000:8000 \
  -v nk-data:/data \
  -e DEFAULT_ADMIN_PASSWORD='смените-на-свой' \
  ghcr.io/NKomnatsky-creator/nk-free:latest
```

Сборка из исходников:

```bash
cp .env.example .env   # при необходимости
docker compose up -d --build
```

Все изменяемые данные находятся в именованном томе `appdata` (`/data` внутри
контейнера):

- `passwords.db`
- `secret.key` — ключ шифрования паролей;
- `.flask_secret` — секрет Flask-сессий;
- `backups/`, `master.json` — если включён мастер-пароль.

### Переменные окружения

| Переменная | Назначение |
|---|---|
| `DATA_DIR` | Каталог данных. По умолчанию каталог с кодом, в Docker — `/data`. |
| `FLASK_SECRET` | Секрет подписи сессий. Если не задан, создаётся файл `.flask_secret`. |
| `FLASK_SECRET_FILE` | Альтернативный путь к файлу секрета. |
| `DEFAULT_ADMIN_PASSWORD` | Пароль `admin` при первом создании базы. |
| `HTTPS` | `1` — включать `Secure` у cookie сессии (нужно за HTTPS). |
| `TRUSTED_PROXY_COUNT` | Число доверенных прокси, от которых читать `X-Forwarded-*`. По умолчанию `0`. |
| `SERVER_HOST` / `SERVER_PORT` | Адрес внутреннего бэкенда для `app.py`. По умолчанию `127.0.0.1:5000`. |
| `INTERNAL_API_SECRET` | Общий секрет `app.py` и `server.py`; нужен, только когда фронтенд подключается к бэкенду не с loopback. |
| `TLS_CERT` / `TLS_KEY` / `TLS_CA` | Взаимный TLS между `app.py` и `server.py`. Задавать все три вместе. |
| `USE_WAITRESS` | `1` — использовать Waitress вместо встроенного сервера Flask (в Docker включено). |
| `MASTER_PASSWORD` | Мастер-пароль для неинтерактивного запуска (иначе `start.py` запросит его в терминале). |
| `SSO_MODE` | `off` (по умолчанию), `ldap` или `oidc`. |
| `SSO_LABEL` | Название кнопки входа на странице логина. |
| `SSO_ADMIN_GROUPS` / `SSO_MANAGER_GROUPS` | Подстроки в именах групп через запятую для назначения роли. |
| `SSO_DEFAULT_ROLE` | Роль новых пользователей: `user` (по умолчанию), `manager`, `admin`. |

Пример `.env`:

```env
FLASK_SECRET=замените-на-длинную-случайную-строку
DEFAULT_ADMIN_PASSWORD=смените-при-первом-входе
HTTPS=0
TRUSTED_PROXY_COUNT=0
```

---

## HTTPS через nginx

1. Скопируйте `nginx/passvault.conf.example` в конфигурацию nginx и замените `passvault.example.com`.
2. Положите сертификаты в `certs/fullchain.pem` и `certs/privkey.pem`.
3. В `docker-compose.yml` уберите прямое опубликование порта `8000`.
4. Задайте `HTTPS=1` и `TRUSTED_PROXY_COUNT=1`.

`TRUSTED_PROXY_COUNT` можно включать **только** когда приложение доступно
исключительно через доверенный прокси. Иначе клиент сможет подделать
`X-Forwarded-For` и обойти блокировки по IP.

Пример nginx-профиля можно добавить в `docker-compose.yml`:

```yaml
  nginx:
    image: nginx:1.27-alpine
    profiles: ["https"]
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx/passvault.conf.example:/etc/nginx/conf.d/default.conf:ro
      - ./certs:/etc/nginx/certs:ro
    depends_on:
      - app
```

Запуск: `docker compose --profile https up -d`.

---

## Возможности free

Бесплатно доступны: управление паролями, импорт, экспорт, центр безопасности,
уведомления, 2FA, API-токены, LDAP/OIDC и мастер-пароль. Лимит — 5 пользователей.

Резервные копии, общие ссылки и брендинг доступны только в Enterprise.

---

## Двухфакторная аутентификация (2FA)

1. Откройте **Центр безопасности → 2FA**.
2. Нажмите **Настроить 2FA**, отсканируйте QR или введите секрет в приложение.
3. Введите код из приложения и подтвердите.
4. **Скопируйте коды восстановления** — они показываются только один раз.

---

## API-токены

Создаются в **Центр безопасности → API-токены**. Открытый токен показывается
только при создании; в базе хранится только SHA-256.

```bash
curl -H "Authorization: Bearer pt_..." http://localhost:8000/api/passwords
```

Токен работает без браузерной сессии и без CSRF-токена. Отзывается в том же
разделе. Срок действия — от 0 (бессрочно) до 365 дней.

---

## Экспорт и журналы

- Экспорт с главной страницы: CSV или JSON, фильтр «все / утечки / давно не менялись».
- Файл содержит пароли в открытом виде — храните его безопасно и удаляйте после использования.
- Журнал событий поддерживает фильтры по пользователю, действию, IP и датам, а также экспорт CSV.

---

## Мастер-пароль (KDF)

По умолчанию ключ шифрования лежит в `$DATA_DIR/secret.key`. Включение
мастер-пароля убирает plaintext-ключ с диска: ключ выводится из пароля через
PBKDF2-HMAC-SHA256 (600 000 итераций) и существует только в памяти процессов.

```bash
python master.py status     # состояние
python master.py enable     # включить (перешифрует БД и копии)
python master.py verify     # проверить пароль
python master.py disable    # снять (нужен мастер-пароль)
```

При включении старый ключ сохраняется в `$DATA_DIR/master.json` в зашифрованном
виде, `$DATA_DIR/secret.key` удаляется, а `start.py` запрашивает пароль и
передаёт производный ключ дочерним процессам. Для Docker передайте
`MASTER_PASSWORD` через окружение.

**Внимание:** пароль нельзя восстановить. Сделайте резервную копию `master.json`
и отдельно сохраните пароль в надёжном месте.

---

## Внешняя аутентификация (LDAP / OIDC)

Включение: задайте `SSO_MODE=ldap` или `SSO_MODE=oidc`. Обычный вход по паролю
остаётся доступным.

### LDAP

Требуется пакет `ldap3` (уже в `requirements.txt`).

```env
SSO_MODE=ldap
SSO_LABEL=Корпоративный LDAP
LDAP_SERVER=ldap.example.com
LDAP_PORT=389
LDAP_START_TLS=1
LDAP_BASE_DN=OU=Users,DC=example,DC=com
LDAP_BIND_DN=CN=svc,OU=Service,DC=example,DC=com
LDAP_BIND_PASSWORD=...
LDAP_USER_FILTER=(sAMAccountName={login})
LDAP_ATTR_USERNAME=sAMAccountName
LDAP_ATTR_SUB=objectGUID
LDAP_GROUP_FILTER=(&(objectClass=group)(member={user_dn}))
SSO_ADMIN_GROUPS=Admins
SSO_MANAGER_GROUPS=Managers
```

Без TLS вход запрещён; для доверенной сети можно явно задать `LDAP_ALLOW_INSECURE=1`.

### OIDC

Код-флоу с PKCE, состояние проверяется через сессию. Требуется `userinfo_endpoint`.

```env
SSO_MODE=oidc
SSO_LABEL=Вход через корпоративный аккаунт
OIDC_ISSUER=https://id.example.com
OIDC_CLIENT_ID=...
OIDC_CLIENT_SECRET=...
OIDC_REDIRECT_URI=https://passvault.example.com/login/oidc/callback
OIDC_SCOPES=openid profile email groups
OIDC_GROUP_CLAIM=groups
SSO_ADMIN_GROUPS=admins
```

Зарегистрируйте `OIDC_REDIRECT_URI` в провайдере. Пользователи создаются
автоматически при первом входе; локальный аккаунт с таким же именем **не**
связывается — создаётся уникальный логин с суффиксом.

---

## Браузерное расширение

Папка `browser-extension/` — расширение Manifest V3 (Chrome/Edge/Firefox).

1. Откройте `chrome://extensions`, включите режим разработчика, загрузите распакованное расширение из этой папки.
2. Создайте API-токен в **Центр безопасности → API-токены**.
3. В popup укажите адрес сервера и токен, нажмите «Обновить список».

Токен хранится только в `chrome.storage.local`.

---

## Проверка после развёртывания

```bash
curl -I http://localhost:8000/login
curl -H "X-API-Token: pt_..." http://localhost:8000/api/passwords
```

В логах не должно быть ошибок миграции БД.
