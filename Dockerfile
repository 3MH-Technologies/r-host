# ============================================================
#  Wolf Host  |  Telegram Bot Hosting Platform
#  Internal codename: r-host
#
#  (c) 3MH TECHNOLOGIES : https://3mh.pages.dev/
#  Developed by White Wolf : https://t.me/j49_c
#
#  All rights reserved.
# ============================================================

FROM python:3.11-slim

RUN apt-get update && apt-get install -y \
    gcc \
    python3-dev \
    dnsutils \
    ca-certificates \
    curl \
    git \
    util-linux \
    iptables \
    && rm -rf /var/lib/apt/lists/*

# Zero-trust: the panel runs as root so it can create a dedicated OS user per
# bot and demote every bot process into it (useradd + prlimit). Bots themselves
# never run as root. Keep util-linux installed for prlimit (rlimits).
RUN useradd -r -M -s /usr/sbin/nologin panel || true

ENV PATH="/usr/local/bin:/usr/bin:/bin"
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade -r requirements.txt

COPY . .

ENV SERVER_PORT=7860
EXPOSE 7860

CMD ["python", "app.py"]
