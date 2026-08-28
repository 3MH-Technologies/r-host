# ============================================================
#  Wolf Host  |  Telegram Bot Hosting Platform
#  Internal codename: r-host
#
#  (c) 3MH TECHNOLOGIES : https://3mh.pages.dev/
#  Developed by White Wolf : https://t.me/j49_c
#
#  All rights reserved.
# ============================================================
#
# Standalone keep-alive: hits the panel's /health endpoint on a timer so the
# service stays warm (useful on sandboxed hosts that idle out).

import requests
import time
import datetime
import os

LOCAL_PORT = os.environ.get("SERVER_PORT", "7860")
LOCAL_URL = f"http://127.0.0.1:{LOCAL_PORT}/health"
TARGETS = [LOCAL_URL]


def start_pinging():
    print(f"[*] Keep-alive targets: {TARGETS}")
    fail_count = 0
    while True:
        for url in TARGETS:
            try:
                r = requests.get(url, timeout=15)
                now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                print(f"[{now}] {url} -> {r.status_code}")
                fail_count = 0
            except Exception as e:
                fail_count += 1
                print(f"[!] Error: {url} -> {e}")
        sleep_time = 180 if fail_count == 0 else 60
        time.sleep(sleep_time)


if __name__ == "__main__":
    start_pinging()
