# -*- coding: utf-8 -*-
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
# Telegram Reverse Proxy relay (zero-trust default egress for bots).
#
# Routes every bot's api.telegram.org traffic AUTOMATICALLY through the
# 3MH TECHNOLOGIES Telegram Reverse Proxy (tg-proxy.contact-3mh.workers.dev):
#
#   bot -> [our local proxy] --TLS--> 3MH worker --TLS--> api.telegram.org
#
# Why this exists: the Worker is a REVERSE proxy, not a forward/CONNECT proxy.
# A plain HTTPS_PROXY would not work, because a CONNECT tunnel carries the
# client's TLS ClientHello verbatim and its SNI is `api.telegram.org` (taken from
# the bot's URL) - so Cloudflare would route the handshake to Telegram's own
# zone, never to our Worker.
#
# The solution is to act as a tiny TLS-terminating relay for the api.telegram.org
# hosts (using a dedicated CA that every bot trusts via REQUESTS_CA_BUNDLE /
# SSL_CERT_FILE and a certifi shim), then re-issue a fresh TLS connection to the
# Worker with the correct SNI. The bot's HTTP bytes are relayed verbatim (path +
# params unchanged; the Worker rewrites Host itself). Everything else is PURE TCP
# passthrough: no MITM, no overhead for non-Telegram traffic.
#
# Two ingress modes:
#   * CONNECT proxy  (port TG_LOCAL_PROXY_PORT, bots pointed at it via env vars)
#   * transparent    (port TG_TRANSPARENT_PORT, iptables nat REDIRECT catches
#                     bot flows destined to Telegram's CIDRs -> covers any client,
#                     e.g. PHP/aiogram which ignore environment proxies)
#
# Cost is trivial: the CA and certs are generated once at boot and cached, and
# each connection is just a byte pipe (two threaded sockets). Bots are already
# capped at 256 processes by prlimit, so this can't be abused into a fork bomb.

import json
import os
import select
import socket
import ssl
import sys
import threading
from datetime import datetime, timedelta, timezone

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

TG_PROXY_ENABLED = os.environ.get("TG_PROXY_ENABLED", "1").lower() not in ("0", "off", "no", "false")
UPSTREAM = os.environ.get("TG_PROXY_URL", "https://tg-proxy.contact-3mh.workers.dev").rstrip("/")

# Ingress listeners (bind 0.0.0.0 for the transparent one so a local nat
# REDIRECT always lands on it, and 127.0.0.1 for the env-proxy one).
LISTEN_HOST = os.environ.get("TG_LOCAL_PROXY_HOST", "127.0.0.1")
LISTEN_PORT = int(os.environ.get("TG_LOCAL_PROXY_PORT", "7788"))
TRANS_LISTEN_HOST = os.environ.get("TG_LOCAL_PROXY_TRANS_HOST", "0.0.0.0")
TRANS_LISTEN_PORT = int(os.environ.get("TG_TRANSPARENT_PORT", "7443"))

# Hosts that get re-routed to the Worker (Bot API and its regional/ip aliases).
_TG_HOSTS = tuple(
    h.strip().lower().rstrip(".")
    for h in os.environ.get("TG_PROXY_HOSTS", "api.telegram.org,core.telegram.org").split(",")
    if h.strip()
)

# Telegram's server CIDRs that bots must never reach directly. Env override for
# updates: TG_DIRECT_BLOCK_CIDRS="a.b.c.d/n,...."
TG_CIDRS = tuple(
    c.strip()
    for c in os.environ.get(
        "TG_DIRECT_BLOCK_CIDRS",
        ",".join((
            "149.154.160.0/20", "149.154.164.0/22", "91.108.4.0/22",
            "91.108.8.0/22", "91.108.12.0/22", "91.108.16.0/22", "91.108.20.0/22",
            "91.108.56.0/23", "185.76.151.0/23", "95.161.64.0/20",
        )),
    ).split(",")
    if c.strip()
)

CERT_DIR = os.path.join(BASE_DIR, "tgcert")
_CA_PEM = os.path.join(CERT_DIR, "ca.pem")
_CA_KEY = os.path.join(CERT_DIR, "ca.key")
_SRV_PEM = os.path.join(CERT_DIR, "tg-server.pem")
_SRV_KEY = os.path.join(CERT_DIR, "tg-server.key")
BUNDLE = os.path.join(CERT_DIR, "bundle.crt")

try:
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    HAVE_CRYPTO = True
except ImportError:
    HAVE_CRYPTO = False

_OK = b"HTTP/1.1 200 Connection established\r\n\r\n"

_server_ctx = None
_started = False
_ready = threading.Event()
_lock = threading.Lock()


def is_tg_host(host):
    host = (host or "").strip().lower().rstrip(".")
    return any(host == h or host.endswith("." + h) for h in _TG_HOSTS)


def running():
    """True once both listeners are bound and the accept loops are alive."""
    return _started and _ready.is_set()


# --------------------------------------------------------------------------
# CA + server certificate (generated once, persisted in tgcert/)
# --------------------------------------------------------------------------

def _system_roots():
    paths = []
    try:
        import certifi
        paths.append(certifi.where())
    except Exception:
        pass
    paths += [
        "/etc/ssl/certs/ca-certificates.crt",
        "/etc/pki/tls/certs/ca-bundle.crt",
        "/usr/local/share/ca-certificates/",
    ]
    for p in paths:
        try:
            if os.path.isfile(p):
                with open(p, "rb") as f:
                    data = f.read()
                if b"BEGIN CERTIFICATE" in data:
                    return data
        except Exception:
            continue
    return b""


def _gen_ca():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "r-host bot relay CA")])
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(digital_signature=True, content_commitment=False,
                          key_encipherment=False, data_encipherment=False,
                          key_agreement=False, encipher_only=False,
                          decipher_only=False, key_cert_sign=True, crl_sign=True),
            critical=True,
        )
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .sign(key, hashes.SHA256())
    )
    return key, cert


def _gen_server_cert(ca_key, ca_cert, hosts):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    san = x509.SubjectAlternativeName([x509.DNSName(h) for h in hosts])
    sname = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, hosts[0])])
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(sname)
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=825))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(digital_signature=True, content_commitment=False,
                          key_encipherment=True, data_encipherment=False,
                          key_agreement=False, encipher_only=False,
                          decipher_only=False, key_cert_sign=False, crl_sign=False),
            critical=True,
        )
        .add_extension(x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_cert.public_key()), critical=False
        )
        .add_extension(san, critical=False)
        .sign(ca_key, hashes.SHA256())
    )
    return key, cert


def _ensure_certs():
    os.makedirs(CERT_DIR, mode=0o755, exist_ok=True)
    if os.path.isfile(_CA_PEM) and os.path.isfile(_CA_KEY):
        with open(_CA_KEY, "rb") as f:
            ca_key = serialization.load_pem_private_key(f.read(), password=None)
        with open(_CA_PEM, "rb") as f:
            ca_cert = x509.load_pem_x509_certificate(f.read())
    else:
        ca_key, ca_cert = _gen_ca()
        with open(_CA_KEY, "wb") as f:
            f.write(ca_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.NoEncryption(),
            ))
        with open(_CA_PEM, "wb") as f:
            f.write(ca_cert.public_bytes(serialization.Encoding.PEM))
        os.chmod(_CA_KEY, 0o600)

    if not (os.path.isfile(_SRV_PEM) and os.path.isfile(_SRV_KEY)):
        hosts = list(dict.fromkeys(list(_TG_HOSTS) + ["api.telegram.org", "*.api.telegram.org"]))
        srv_key, srv_cert = _gen_server_cert(ca_key, ca_cert, hosts)
        with open(_SRV_KEY, "wb") as f:
            f.write(srv_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.NoEncryption(),
            ))
        with open(_SRV_PEM, "wb") as f:
            f.write(srv_cert.public_bytes(serialization.Encoding.PEM))
        os.chmod(_SRV_KEY, 0o600)

    # Bundle for the bots: our CA + the system roots, world readable.
    bundle = ca_cert.public_bytes(serialization.Encoding.PEM) + _system_roots()
    tmp = BUNDLE + ".tmp"
    with open(tmp, "wb") as f:
        f.write(bundle)
    os.chmod(tmp, 0o644)
    os.replace(tmp, BUNDLE)
    return BUNDLE


# --------------------------------------------------------------------------
# Upstream + relay machinery
# --------------------------------------------------------------------------

def _connect_upstream():
    host, port, _scheme = _parse_uri(UPSTREAM)
    raw = socket.create_connection((host, port), timeout=15)
    ctx = ssl.create_default_context()
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED
    return ctx.wrap_socket(raw, server_hostname=host)


def _parse_uri(uri):
    rest = uri.split("://", 1)[1] if "://" in uri else uri
    scheme = uri.split("://", 1)[0].lower() if "://" in uri else "https"
    hostpart = rest.split("/", 1)[0]
    if ":" in hostpart and not hostpart.startswith("["):
        host, _, port = hostpart.rpartition(":")
        port = int(port)
    elif hostpart.startswith("[") and "]" in hostpart:
        host = hostpart[1:hostpart.index("]")]
        port = int(hostpart.split(":")[-1]) if ":" in hostpart.split("]")[1] else (443 if scheme == "https" else 80)
    else:
        host = hostpart
        port = 443 if scheme == "https" else 80
    return host, port, scheme


def _parse_authority(target):
    target = target.strip()
    if target.startswith("["):  # IPv6 literal
        host, _, rest = target[1:].partition("]")
        port = int(rest.lstrip(":")) if rest.lstrip(":") else 443
        return host, port
    if ":" in target:
        host, _, p = target.rpartition(":")
        if p.isdigit():
            return host, int(p)
    return target, 443


def _url_host(target):
    if "://" in target:
        host = target.split("://", 1)[1].split("/", 1)[0]
        host = host[:host.index(":")] if ":" in host and not host.startswith("[") else host
        host = host.replace("[", "").replace("]", "")
        return host
    return None


def _relay_one_way(src, dst):
    try:
        while True:
            data = src.recv(65536)
            if not data:
                break
            dst.sendall(data)
    except Exception:
        pass
    finally:
        try:
            dst.shutdown(socket.SHUT_WR)
        except Exception:
            pass


def _pipe_pair(a, b):
    """Bidirectional byte relay: two worker threads. Half-close on EOF propagates
    so long-polling (getUpdates) streams terminate correctly at both ends."""
    threading.Thread(target=_relay_one_way, args=(a, b), daemon=True).start()
    _relay_one_way(b, a)


# --------------------------------------------------------------------------
# Ingress handlers
# --------------------------------------------------------------------------

def _read_head(conn, limit=65536):
    conn.settimeout(8)
    buf = b""
    try:
        while b"\r\n\r\n" not in buf and len(buf) < limit:
            chunk = conn.recv(4096)
            if not chunk:
                break
            buf += chunk
    except Exception:
        pass
    finally:
        conn.settimeout(None)
    return buf


def _handle_transparent(conn):
    """iptables-REDIRECTed flow: bot dialed api.telegram.org:443 but the kernel
    sent it here. TLS-terminate (SNI matches our wildcard cert), relay to Worker."""
    up = _connect_upstream()
    srv = _server_ctx.wrap_socket(conn, server_side=True)
    _pipe_pair(srv, up)


def _handle_proxy(conn):
    """CONNECT / absolute-form handler for the env-proxy ingress."""
    head = _read_head(conn)
    first = head.split(b"\r\n", 1)[0].decode("utf-8", "ignore")
    tokens = first.split()
    if not tokens:
        return
    method, target = tokens[0].upper(), (tokens[1] if len(tokens) > 1 else "")

    if method == "CONNECT":
        host, port = _parse_authority(target)
        tg = is_tg_host(host)
        try:
            up = _connect_upstream() if tg else socket.create_connection((host, port), timeout=10)
        except Exception:
            return
        conn.sendall(_OK)
        if tg:
            srv = _server_ctx.wrap_socket(conn, server_side=True)
            _pipe_pair(srv, up)
        else:
            _pipe_pair(conn, up)
        return

    host = _url_host(target)
    if not host:
        conn.sendall(b"HTTP/1.1 400 Bad Request\r\n\r\n")
        return
    tg = is_tg_host(host)
    try:
        up = _connect_upstream() if tg else socket.create_connection((host, 80), timeout=10)
    except Exception:
        return
    if tg:
        srv = _server_ctx.wrap_socket(conn, server_side=True)
        srv.sendall(head)
        _pipe_pair(srv, up)
    else:
        up.sendall(head)
        _pipe_pair(conn, up)


def _handle(conn, transparent):
    try:
        if transparent:
            _handle_transparent(conn)
        else:
            _handle_proxy(conn)
    except Exception:
        pass
    finally:
        try:
            conn.close()
        except Exception:
            pass


def _serve(listen_sock, transparent):
    while True:
        try:
            conn, _addr = listen_sock.accept()
        except OSError:
            return
        threading.Thread(target=_handle, args=(conn, transparent), daemon=True).start()


# --------------------------------------------------------------------------
# Public API used by app.py
# --------------------------------------------------------------------------

def safe_rule_target():
    """(proxy_port, transparent_port) for iptables acceptance rules."""
    return LISTEN_PORT, TRANS_LISTEN_PORT


def annotate_bot_env(bot_env, pyuser):
    """Call once per spawned bot: inject proxy + CA env vars and drop a certifi
    shim in the bot's .pyuser user-site so requests/httpx/certifi all trust the
    relay CA. Idempotent and cheap (small file write)."""
    global _started
    if not _started or not BUNDLE or not os.path.isfile(BUNDLE):
        return
    proxy = f"http://{LISTEN_HOST}:{LISTEN_PORT}"
    for k in ("http_proxy", "https_proxy", "HTTP_PROXY", "HTTPS_PROXY"):
        bot_env[k] = proxy
    bot_env["REQUESTS_CA_BUNDLE"] = BUNDLE
    bot_env["SSL_CERT_FILE"] = BUNDLE
    bot_env["TG_PROXY_URL"] = UPSTREAM
    bot_env["TELEGRAM_API_BASE"] = UPSTREAM

    if pyuser:
        pyver = f"python{sys.version_info.major}.{sys.version_info.minor}"
        site = os.path.join(pyuser, "lib", pyver, "site-packages")
        shim_dir = os.path.join(site, "certifi")
        try:
            os.makedirs(shim_dir, exist_ok=True)
            shim = os.path.join(shim_dir, "__init__.py")
            code = (
                "__where = %r\n"
                "def where():\n"
                "    return __where\n"
                "__version__ = 'tgproxy-shim'\n" % BUNDLE
            )
            with open(shim, "w", encoding="utf-8") as f:
                f.write(code)
        except Exception:
            pass


def ensure():
    """Generate keys/certs, build contexts, bind both listeners and start accept
    loops. Returns True when operational. Idempotent, single-shot, called at boot
    (before forking gunicorn)."""
    global _server_ctx, _started
    if not TG_PROXY_ENABLED:
        _ready.clear()
        return False
    if not HAVE_CRYPTO:
        _started = False
        _ready.clear()
        return False
    with _lock:
        if _started:
            return True
        try:
            _ensure_certs()
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(_SRV_PEM, _SRV_KEY)
            _server_ctx = ctx
        except Exception:
            _server_ctx = None
            return False

        socks = [
            ("env-proxy", LISTEN_HOST, LISTEN_PORT, False),
            ("transparent", TRANS_LISTEN_HOST, TRANS_LISTEN_PORT, True),
        ]
        bound = 0
        for name, host, port, transp in socks:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                s.bind((host, port))
                s.listen(128)
                threading.Thread(target=_serve, args=(s, transp), daemon=True).start()
                bound += 1
            except OSError:
                try:
                    s.close()
                except Exception:
                    pass
        if bound == 0:
            _started = False
            _ready.clear()
            return False
        _started = True
        _ready.set()
        return True


def summary_json():
    return {
        "enabled": _started,
        "upstream": UPSTREAM,
        "proxy_port": LISTEN_PORT,
        "transparent_port": TRANS_LISTEN_PORT,
        "tg_hosts": list(_TG_HOSTS),
        "tg_cidrs": list(TG_CIDRS),
        "bundle": BUNDLE if os.path.isfile(BUNDLE) else None,
    }