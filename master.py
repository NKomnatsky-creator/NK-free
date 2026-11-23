#!/usr/bin/env python3
"""Управление мастер-паролем хранилища.

    python master.py status
    python master.py enable
    python master.py verify
    python master.py disable

Для неинтерактивного использования задайте MASTER_PASSWORD в окружении.
"""

from kdf import main

if __name__ == '__main__':
    main()
