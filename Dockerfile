FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PULSE_BIND_HOST=0.0.0.0 \
    PORT=3000

RUN apt-get update && apt-get install -y --no-install-recommends \
    iputils-ping \
    iproute2 \
    net-tools \
    traceroute \
    nmap \
    ca-certificates \
  && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt ./
RUN python -m pip install --no-cache-dir -r requirements.txt

COPY server.py monitor.py manage.py ./
COPY pulse_monitor ./pulse_monitor
COPY public ./public

RUN mkdir -p /app/data

EXPOSE 3000
VOLUME ["/app/data"]

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
  CMD python3 -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:3000/healthz', timeout=3)" || exit 1

CMD ["python3", "server.py"]
