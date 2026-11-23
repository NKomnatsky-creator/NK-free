FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    DATA_DIR=/data \
    USE_WAITRESS=1

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN useradd --create-home --uid 10001 appuser \
    && mkdir -p /data/backups \
    && chown -R appuser:appuser /app /data

USER appuser

EXPOSE 8000
VOLUME ["/data"]

# start.py ловит KeyboardInterrupt и корректно останавливает оба процесса.
STOPSIGNAL SIGINT

# Проверяем и веб (8000), и внутренний сервер БД (5000).
HEALTHCHECK --interval=30s --timeout=5s --start-period=40s --retries=3 \
  CMD ["python", "-c", "import socket,urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/login', timeout=3).read(); s=socket.create_connection(('127.0.0.1', 5000), 2); s.close()"]

CMD ["python", "start.py"]
