#!/usr/bin/env python3
"""Запуск рабочей системы для работы по сети"""

import subprocess
import sys
import time
import threading
import os
import socket
import re

# Цвета для терминала
C_RESET = '\033[0m'
C_BOLD = '\033[1m'
C_GREEN = '\033[92m'
C_BLUE = '\033[94m'
C_YELLOW = '\033[93m'
C_CYAN = '\033[96m'
C_RED = '\033[91m'


def get_network_info():
    try:
        hostname = socket.gethostname()
        all_ips = socket.gethostbyname_ex(hostname)[2]
        local_ips = [ip for ip in all_ips if ip != '127.0.0.1']
        if not local_ips:
            local_ips.append('127.0.0.1')
        return local_ips
    except Exception:
        return ['127.0.0.1']


def _wait_for_port(host, port, timeout=15):
    deadline = time.time() + timeout
    while time.time() < deadline:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)
        try:
            if s.connect_ex((host, port)) == 0:
                return True
        finally:
            s.close()
        time.sleep(0.3)
    return False


def _spawn(script, port, name, host='127.0.0.1'):
    if not os.path.exists(script):
        print(f"{C_RED}ОШИБКА: Файл {script} не найден!{C_RESET}")
        return None
    process = subprocess.Popen(
        [sys.executable, script],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        encoding='utf-8',
        errors='replace',
        bufsize=1,
    )
    probes = [host] if host == '127.0.0.1' else [host, '127.0.0.1']
    if not any(_wait_for_port(h, port, timeout=15 if i == 0 else 2)
               for i, h in enumerate(probes)):
        if process.poll() is not None:
            try:
                out = process.stdout.read()
            except Exception:
                out = ''
            print(f"{C_RED}✗ Ошибка запуска {name} (процесс завершился){C_RESET}")
            if out:
                print(f"--- Вывод {name} ---")
                print(out)
                print(f"--- конец вывода ---")
        else:
            print(f"{C_YELLOW}⚠ {name} запущен, но порт {port} недоступен{C_RESET}")
        return None
    print(f"{C_GREEN}✓ {name} запущен на порту {port}{C_RESET}")
    return process


def run_server():
    print("Запуск сервера...")
    return _spawn("server.py", 5000, "Сервер",
                  host=os.environ.get('SERVER_HOST', '127.0.0.1'))


def run_app():
    print("\nЗапуск веб-приложения...")
    if not os.path.exists('templates'):
        print(f"{C_RED}ОШИБКА: Папка templates не найдена!{C_RESET}")
        return None
    return _spawn("app.py", 8000, "Веб-приложение")


def print_output(process, name, color):
    while True:
        try:
            line = process.stdout.readline()
            if not line:
                if process.poll() is not None:
                    print(
                        f"{color}[{name}]{C_RESET} {C_YELLOW}⚠ Процесс завершился (код {process.returncode}){C_RESET}")
                    break
                time.sleep(0.1)
                continue

            # Красим префикс в зависимости от процесса
            prefix = f"{color}[{name}]{C_RESET}"

            # Немного чистим вывод Flask от лишних пробелов
            clean_line = line.rstrip()

            # Если это блок с паролем, выводим его ярко
            if '🔐' in clean_line or 'Логин:' in clean_line or 'Пароль:' in clean_line or '====' in clean_line:
                print(f"{prefix} {C_BOLD}{C_YELLOW}{clean_line}{C_RESET}", flush=True)
            else:
                print(f"{prefix} {clean_line}", flush=True)

        except Exception:
            break


def unlock_master():
    """Запрашивает мастер-пароль до запуска процессов и передаёт ключ через env."""
    try:
        import kdf
    except ImportError:
        print(f"{C_RED}Ошибка: не установлен cryptography{C_RESET}")
        return False
    if not kdf.enabled():
        return True
    if os.environ.get('MASTER_PASSWORD'):
        try:
            key = kdf.verify(os.environ['MASTER_PASSWORD'])
        except kdf.MasterError as exc:
            print(f"{C_RED}✗ {exc}{C_RESET}")
            return False
    else:
        import getpass
        if not sys.stdin.isatty():
            print(f"{C_RED}✗ Нужен мастер-пароль. Запустите в терминале или задайте MASTER_PASSWORD.{C_RESET}")
            return False
        key = None
        for _ in range(3):
            try:
                key = kdf.verify(getpass.getpass('Мастер-пароль: '))
                break
            except kdf.MasterError as exc:
                print(f"{C_YELLOW}⚠ {exc}{C_RESET}")
        if key is None:
            return False
    os.environ['MASTER_DERIVED_KEY'] = key.decode('ascii')
    print(f"{C_GREEN}✓ Мастер-пароль принят{C_RESET}")
    return True


def main():
    print(f"{C_BOLD}{C_CYAN}" + "=" * 70)
    print("          СИСТЕМА УПРАВЛЕНИЯ ПАРОЛЯМИ")
    print("                  NK Secure")
    print("            Автор: Nikita Komnatsky")
    print("=" * 70 + f"{C_RESET}")

    network_ips = get_network_info()

    print(f"\n{C_BOLD}📡 СЕТЕВЫЕ НАСТРОЙКИ:{C_RESET}")
    for ip in network_ips:
        if ip != '127.0.0.1':
            print(f"   • {C_CYAN}http://{ip}:8000{C_RESET}")
    print(f"   • {C_CYAN}http://localhost:8000{C_RESET} (локально)")
    print(f"   • {C_CYAN}http://127.0.0.1:8000{C_RESET} (локально)")
    print(f"   • Бэкенд: {os.environ.get('SERVER_HOST', '127.0.0.1')}:5000 (переопределяется SERVER_HOST)")
    if os.environ.get('HTTPS', '0') != '1':
        print(f"   {C_YELLOW}⚠ Веб-интерфейс работает по HTTP. Для доступа по сети используйте HTTPS (обратный прокси).{C_RESET}")
    tls_server = bool(os.environ.get('TLS_CERT') and os.environ.get('TLS_KEY'))
    if tls_server != bool(os.environ.get('TLS_CA')):
        print(f"   {C_YELLOW}⚠ TLS настроен частично: задайте TLS_CERT, TLS_KEY и TLS_CA вместе.{C_RESET}")

    print(f"\n{C_BOLD}🔐 ДАННЫЕ ДЛЯ ПЕРВОГО ВХОДА:{C_RESET}")
    print(f"   Логин:  {C_BOLD}admin{C_RESET}")
    if os.environ.get('DEFAULT_ADMIN_PASSWORD'):
        print(f"   Пароль: {C_GREEN}из переменной DEFAULT_ADMIN_PASSWORD{C_RESET}")
    else:
        print(f"   Пароль: {C_YELLOW}сгенерирован случайно{C_RESET} — смотрите лог сервера ниже (🔐)")
    print(f"   {C_YELLOW}⚠ Система потребует сменить пароль при первом входе!{C_RESET}")
    print("=" * 70)

    missing = []
    try:
        import flask  # noqa
    except ImportError:
        missing.append('flask')
    try:
        import qrcode  # noqa
    except ImportError:
        missing.append('qrcode')
    try:
        import cryptography  # noqa
    except ImportError:
        missing.append('cryptography')
    try:
        import flask_wtf  # noqa
    except ImportError:
        missing.append('flask-wtf')
    if missing:
        print(f"{C_RED}✗ Не установлены пакеты: {', '.join(missing)}{C_RESET}")
        print(f"   pip install {' '.join(missing)}")
        return
    print(f"{C_GREEN}✓ Зависимости установлены{C_RESET}")

    if not unlock_master():
        print(f"{C_RED}✗ Запуск прерван: не удалось разблокировать хранилище{C_RESET}")
        return

    # В Enterprise-сборке рядом лежит enterprise_bootstrap.py; в free его нет.
    # Активация до запуска детей нужна, чтобы код не погашался дважды.
    try:
        import enterprise_bootstrap
    except ImportError:
        pass
    else:
        enterprise_bootstrap.activate_from_env()

    print(f"\n{C_BOLD}🚀 ЗАПУСК СЕРВЕРА...{C_RESET}")
    server_process = run_server()
    if not server_process:
        print(f"{C_RED}✗ Не удалось запустить сервер{C_RESET}")
        return

    print(f"\n{C_BOLD}🌐 ЗАПУСК ВЕБ-ИНТЕРФЕЙСА...{C_RESET}")
    app_process = run_app()
    if not app_process:
        print(f"{C_RED}✗ Не удалось запустить веб-приложение{C_RESET}")
        server_process.terminate()
        return

    print(f"\n{C_BOLD}{C_GREEN}" + "=" * 70)
    print("✅ СИСТЕМА УСПЕШНО ЗАПУЩЕНА!")
    print("=" * 70 + f"{C_RESET}")

    print(f"\n{C_BOLD}📋 КАК ПОДКЛЮЧИТЬСЯ:{C_RESET}")
    print(f"   • {C_CYAN}http://localhost:8000{C_RESET} (локально)")
    for ip in network_ips:
        if ip != '127.0.0.1':
            print(f"   • {C_CYAN}http://{ip}:8000{C_RESET} (сеть)")

    print(f"\n{C_BOLD}🛑 ДЛЯ ОСТАНОВКИ нажмите Ctrl+C{C_RESET}")
    print("=" * 70 + "\n")

    # Запускаем потоки вывода с разными цветами
    threading.Thread(target=print_output, args=(server_process, "СЕРВЕР", C_BLUE), daemon=True).start()
    threading.Thread(target=print_output, args=(app_process, "ВЕБ", C_GREEN), daemon=True).start()

    try:
        while True:
            time.sleep(1)
            if server_process.poll() is not None:
                print(f"\n{C_YELLOW}⏹ Сервер неожиданно завершился. Останавливаю систему.{C_RESET}")
                app_process.terminate()
                break
            if app_process.poll() is not None:
                print(f"\n{C_YELLOW}⏹ Веб-приложение неожиданно завершилось. Останавливаю систему.{C_RESET}")
                server_process.terminate()
                break
    except KeyboardInterrupt:
        print(f"\n{C_YELLOW}⏹ ОСТАНОВКА СИСТЕМЫ...{C_RESET}")
    finally:
        for p in (server_process, app_process):
            if p and p.poll() is None:
                p.terminate()
        time.sleep(1)
        print(f"{C_GREEN}✅ СИСТЕМА ОСТАНОВЛЕНА{C_RESET}")


if __name__ == "__main__":
    main()