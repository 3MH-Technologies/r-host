import os
import json
import re
import shutil
import socket
import hashlib
import subprocess
import threading
import time
import sys
import signal
import logging
import requests
import psutil
import smtplib
from flask import Flask, send_from_directory, request, jsonify, redirect, session
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.middleware.proxy_fix import ProxyFix
from functools import wraps
from collections import defaultdict

ai_client = None

def get_ai_client():
    global ai_client
    if ai_client is not None:
        return ai_client
    try:
        from ollamafreeapi import OllamaFreeAPI
        ai_client = OllamaFreeAPI()
        return ai_client
    except Exception:
        return None

logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] %(levelname)s: %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger('hostbot')

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
USERS_ROOT = os.path.join(BASE_DIR, "USERS")
DATA_DIR = os.path.join(BASE_DIR, "DATA")
USERS_DB = os.path.join(DATA_DIR, "users.json")

os.makedirs(USERS_ROOT, exist_ok=True)
os.makedirs(DATA_DIR, exist_ok=True)

app = Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)
app.secret_key = os.environ.get("PANEL_SECRET_KEY") or os.urandom(24)
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Strict',
    SESSION_COOKIE_SECURE=os.environ.get("SESSION_COOKIE_SECURE", "true").lower() == "true",
    PERMANENT_SESSION_LIFETIME=604800,
    MAX_CONTENT_LENGTH=50 * 1024 * 1024
)

_rate_store = defaultdict(list)
_rate_lock = threading.Lock()
RATE_LIMIT = 120
RATE_WINDOW = 60


def rate_limited(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        ip = request.remote_addr or '0.0.0.0'
        now = time.time()
        with _rate_lock:
            _rate_store[ip] = [t for t in _rate_store[ip] if now - t < RATE_WINDOW]
            if len(_rate_store[ip]) >= RATE_LIMIT:
                return jsonify({"success": False, "message": "Rate limit exceeded"}), 429
            _rate_store[ip].append(now)
        return fn(*args, **kwargs)
    return wrapper


@app.after_request
def add_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['Content-Security-Policy'] = "default-src 'self' 'unsafe-inline' 'unsafe-eval' https://fonts.googleapis.com https://fonts.gstatic.com https://f.top4top.io; object-src 'none';"
    response.headers['Referrer-Policy'] = 'strict-origin-when-downgrade'
    return response


# Sentinel: Admin credentials must come from the environment. Fail closed if they
# are missing - a hardcoded fallback password is a critical auth bypass in a public
# repo (anyone can read the default and log in as admin). Require explicit secrets.
ADMIN_USERNAME = os.environ.get("ADMIN_USER")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASS")
if not ADMIN_USERNAME or not ADMIN_PASSWORD:
    logger.critical(
        "FATAL: ADMIN_USER and ADMIN_PASS environment variables are required. "
        "Refusing to start with unsecured admin credentials."
    )
    sys.exit(1)
MAX_PROCESS_MEMORY_MB = int(os.environ.get("MAX_PROC_MEM_MB", 512))
MAX_LOG_SIZE = 2 * 1024 * 1024

running_procs = {}
server_states = {}
lock = threading.Lock()

# Bolt: per-path cache of server.log contents, keyed on mtime+size so reads are
# skipped when the file is unchanged (append-only logs). Bounded by the number of
# servers and by MAX_LOG_SIZE (logs are truncated to ~1MB by truncate_large_logs).
_log_cache = {}


def read_server_log(path):
    try:
        st = os.stat(path)
        entry = _log_cache.get(path)
        # The dashboard console polls /server/stats every 2s and we return the full
        # log each time, so an unchanged appending log used to be re-read on every
        # poll (~3.5ms for a 1.4MB read every 2s). Skip the disk read when possible.
        if entry and entry["mtime"] == st.st_mtime and entry["size"] == st.st_size:
            return entry["data"]
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            data = f.read()
        _log_cache[path] = {"mtime": st.st_mtime, "size": st.st_size, "data": data}
        return data
    except FileNotFoundError:
        return ""
    except Exception:
        return ""


def get_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("10.255.255.255", 1))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


def sanitize_folder_name(name):
    name = (name or "").strip()
    name = re.sub(r"\s+", "-", name)
    name = re.sub(r"[^A-Za-z0-9\-_\.]", "", name)
    return name[:200]


def safe_name(name):
    name = (name or "").strip()
    name = re.sub(r"[\\/]+", "", name)
    name = re.sub(r"[^A-Za-z0-9\-_\. ]", "", name)
    return name[:200].strip()


def set_state(key, state):
    with lock:
        server_states[key] = state


def get_state(key):
    with lock:
        return server_states.get(key, "Offline")


def log_append(key, text):
    try:
        if "::" in key:
            owner, folder = key.split("::", 1)
            owner = owner.strip()
            folder = folder.strip()
        else:
            owner = current_username()
            folder = key
        p = os.path.join(get_server_dir(owner, folder), "server.log")
        with open(p, "a", encoding="utf-8", errors="ignore") as f:
            f.write(text)
    except Exception:
        pass


_users_cache = {"mtime": None, "size": None, "data": None}


def load_users():
    if not os.path.exists(USERS_DB):
        return {"users": []}
    try:
        st = os.stat(USERS_DB)
        cache = _users_cache
        # Bolt: cache the parsed users DB keyed on file mtime+size. users.json is
        # read on nearly every authenticated request (sometimes 2-3x per request,
        # e.g. api_user_profile via get_user_limit + get_user_mem_limit), and a
        # cold parse of a large DB costs ~25ms. save_users() writes atomically via
        # os.replace, so mtime/size change on every save and the cache self-invalidates;
        # manual/hand edits to the file are also picked up on the next read.
        if cache["data"] is not None and cache["mtime"] == st.st_mtime and cache["size"] == st.st_size:
            return cache["data"]
        with open(USERS_DB, "r", encoding="utf-8") as f:
            data = json.load(f) or {"users": []}
        cache["mtime"] = st.st_mtime
        cache["size"] = st.st_size
        cache["data"] = data
        return data
    except Exception:
        return {"users": []}


def save_users(db):
    tmp = USERS_DB + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(db, f, indent=2)
    os.replace(tmp, USERS_DB)


def find_user(db, username):
    u = (username or "").strip().lower()
    for x in db.get("users", []):
        if (x.get("username") or "").strip().lower() == u:
            return x
    return None


def is_admin_session():
    u = session.get("user") or {}
    return bool(u.get("is_admin"))


def current_username():
    u = session.get("user") or {}
    return (u.get("username") or "").strip()


PLANS = {
    "free": {"label": "Free", "max_bots": 1, "max_mem_mb": 256, "max_disk_mb": 100},
    "pro": {"label": "Pro", "max_bots": 3, "max_mem_mb": 512, "max_disk_mb": 1000},
    "enterprise": {"label": "Enterprise", "max_bots": 10, "max_mem_mb": 1024, "max_disk_mb": 5000},
}

ADS_FILE = os.path.join(DATA_DIR, "ads.json")

WT_CONTACT = "https://t.me/j49_c"
WT_CHANNEL = "https://t.me/bshshshkk"

def load_ads():
    if not os.path.exists(ADS_FILE):
        return {"current_ad": "", "contact_link": WT_CONTACT, "channel_link": WT_CHANNEL}
    try:
        with open(ADS_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except:
        return {"current_ad": "", "contact_link": WT_CONTACT, "channel_link": WT_CHANNEL}


def save_ads(data):
    with open(ADS_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)


BOT_RENEW_DAYS = 4
AI_DAILY_LIMIT = 20


def get_user_plan(username):
    db = load_users()
    u = find_user(db, username)
    if not u:
        return PLANS["free"]
    plan_name = u.get("plan", "free")
    return PLANS.get(plan_name, PLANS["free"])


def get_user_limit(username):
    if is_admin_session():
        return 999999
    plan = get_user_plan(username)
    return plan["max_bots"]


def get_user_mem_limit(username):
    if is_admin_session():
        return MAX_PROCESS_MEMORY_MB
    plan = get_user_plan(username)
    return plan["max_mem_mb"]


def get_user_disk_limit(username):
    if is_admin_session():
        return 999999
    plan = get_user_plan(username)
    return plan.get("max_disk_mb", 50)


def get_dir_size(path='.'):
    total = 0
    with os.scandir(path) as it:
        for entry in it:
            if entry.is_file() and not entry.is_symlink():
                total += entry.stat().st_size
            elif entry.is_dir() and not entry.is_symlink():
                total += get_dir_size(entry.path)
    return total


def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not session.get("user"):
            return redirect("/login")
        return fn(*args, **kwargs)
    return wrapper


def admin_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not session.get("user"):
            return redirect("/login")
        if not is_admin_session():
            return jsonify({"success": False, "message": "Admin only"}), 403
        return fn(*args, **kwargs)
    return wrapper


def get_user_servers_root(username):
    return os.path.join(USERS_ROOT, username, "servers")


def get_server_dir(owner, folder):
    return os.path.join(get_user_servers_root(owner), folder)


def ensure_user_dirs(username):
    os.makedirs(get_user_servers_root(username), exist_ok=True)


def parse_server_key(key, allow_admin):
    key = (key or "").strip()
    if "::" in key:
        owner, folder = key.split("::", 1)
        owner = owner.strip()
        folder = folder.strip()
        if not allow_admin:
            raise ValueError("not allowed")
        if not is_admin_session():
            raise ValueError("forbidden")
        return owner, folder
    return current_username(), key


def can_access_key(key):
    try:
        owner, folder = parse_server_key(key, allow_admin=True)
    except Exception:
        return False
    if is_admin_session():
        return True
    return owner == current_username()


def safe_join_server_path(key, rel_path=""):
    owner, folder = parse_server_key(key, allow_admin=True)
    root = os.path.abspath(get_server_dir(owner, folder))
    rel_path = (rel_path or "").replace("\\", "/").strip()
    if rel_path.startswith("/") or rel_path.startswith("~"):
        rel_path = rel_path.lstrip("/").lstrip("~")
    joined = os.path.abspath(os.path.join(root, rel_path))
    if not (joined == root or joined.startswith(root + os.sep)):
        raise ValueError("Invalid path")
    return joined


def ensure_meta(owner, folder):
    server_dir = get_server_dir(owner, folder)
    os.makedirs(server_dir, exist_ok=True)
    meta_path = os.path.join(server_dir, "meta.json")
    base = {
        "display_name": folder,
        "startup_file": "",
        "owner": owner,
        "banned": False,
        "last_renewed": time.time()
    }
    if not os.path.exists(meta_path):
        with open(meta_path, "w", encoding="utf-8") as f:
            json.dump(base, f, indent=2)
    else:
        try:
            with open(meta_path, "r", encoding="utf-8") as f:
                m = json.load(f) or {}
        except Exception:
            m = {}
        changed = False
        for k, v in base.items():
            if k not in m:
                m[k] = v
                changed = True
        if m.get("owner") != owner:
            m["owner"] = owner
            changed = True
        if changed:
            with open(meta_path, "w", encoding="utf-8") as f:
                json.dump(m, f, indent=2)
    return meta_path


def read_meta(owner, folder):
    meta_path = ensure_meta(owner, folder)
    try:
        with open(meta_path, "r", encoding="utf-8") as f:
            return json.load(f) or {}
    except Exception:
        return {"display_name": folder, "startup_file": "", "owner": owner, "banned": False}


def write_meta(owner, folder, meta):
    meta_path = ensure_meta(owner, folder)
    with open(meta_path, "w", encoding="utf-8") as f:
        json.dump(meta, f, indent=2)


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def installed_file_path(owner, folder):
    return os.path.join(get_server_dir(owner, folder), ".installed")


def read_installed(owner, folder):
    p = installed_file_path(owner, folder)
    data = {"req_sha": "", "pkgs": set()}
    if not os.path.exists(p):
        return data
    try:
        with open(p, "r", encoding="utf-8", errors="ignore") as f:
            for line in f.read().splitlines():
                line = line.strip()
                if not line:
                    continue
                if line.startswith("REQ_SHA="):
                    data["req_sha"] = line.split("=", 1)[1].strip()
                else:
                    data["pkgs"].add(line)
    except Exception:
        pass
    return data


def write_installed(owner, folder, req_sha=None, add_pkgs=None):
    p = installed_file_path(owner, folder)
    cur = read_installed(owner, folder)
    if req_sha is not None:
        cur["req_sha"] = req_sha
    if add_pkgs:
        cur["pkgs"].update(add_pkgs)
    lines = []
    if cur["req_sha"]:
        lines.append(f"REQ_SHA={cur['req_sha']}")
    lines.extend(sorted(cur["pkgs"]))
    with open(p, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + ("\n" if lines else ""))


def ensure_requirements_installed(owner, folder):
    server_dir = get_server_dir(owner, folder)
    req_path = os.path.join(server_dir, "requirements.txt")
    if not os.path.exists(req_path):
        return False
    req_sha = sha256_file(req_path)
    cur = read_installed(owner, folder)
    if cur["req_sha"] == req_sha:
        return False
    log_append(f"{owner}::{folder}", "[SYSTEM] Installing requirements.txt...\n")
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "install", "-r", "requirements.txt"], cwd=server_dir)
        write_installed(owner, folder, req_sha=req_sha)
        log_append(f"{owner}::{folder}", "[SYSTEM] Requirements installed\n")
        return True
    except subprocess.CalledProcessError as e:
        log_append(f"{owner}::{folder}", f"[SYSTEM] Requirements install failed: {e}\n")
        return False


def get_subprocess_env():
    env = os.environ.copy()
    env['PYTHONUNBUFFERED'] = '1'
    env['PYTHONDONTWRITEBYTECODE'] = '1'
    return env


WRAPPER_TEMPLATE = '''
import sys, os
sys.path.insert(0, "{base_dir}")
try:
    import dns_fix
except:
    pass
import runpy, subprocess, traceback, re, logging
logging.getLogger("httpx").setLevel(logging.WARNING)
logging.getLogger("httpcore").setLevel(logging.WARNING)
logging.getLogger("urllib3").setLevel(logging.WARNING)
script = sys.argv[1]
cwd = os.getcwd()

def append_installed(pkg):
    try:
        p = os.path.join(cwd, ".installed")
        existing = set()
        if os.path.exists(p):
            with open(p, "r", encoding="utf-8", errors="ignore") as f:
                existing = set([x.strip() for x in f.read().splitlines() if x.strip()])
        if pkg and pkg not in existing:
            with open(p, "a", encoding="utf-8") as f:
                f.write(pkg + "\\n")
    except:
        pass

def parse_missing_name(e):
    s = str(e)
    m = re.search(r"No module named \\'([^\\']+)\\'", s)
    if m: return m.group(1)
    m = re.search(r"cannot import name \\'[^\\']+\\' from \\'([^\\']+)\\'", s)
    if m: return m.group(1)
    n = getattr(e, "name", None)
    if n: return n
    return None

IMPORT_TO_PKG = {{
    "telegram": "python-telegram-bot",
    "telegram.ext": "python-telegram-bot",
    "telegram.request": "python-telegram-bot",
    "discord": "discord.py",
    "flask_cors": "Flask-Cors",
    "flask_login": "Flask-Login",
    "flask_sqlalchemy": "Flask-SQLAlchemy",
    "flask_socketio": "Flask-SocketIO",
    "PIL": "Pillow",
    "cv2": "opencv-python",
    "sklearn": "scikit-learn",
    "skimage": "scikit-image",
    "yaml": "PyYAML",
    "bs4": "beautifulsoup4",
    "git": "GitPython",
    "dotenv": "python-dotenv",
    "Crypto": "pycryptodome",
    "dateutil": "python-dateutil",
}}

def resolve_pkg(mod_name):
    top = mod_name.split(".")[0]
    return IMPORT_TO_PKG.get(top, IMPORT_TO_PKG.get(mod_name, mod_name))

try:
    subprocess.check_call([sys.executable, "-m", "pip", "install", "--upgrade", "pip"], stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)
except:
    pass

while True:
    try:
        runpy.run_path(script, run_name="__main__")
        break
    except ModuleNotFoundError as e:
        pkg = parse_missing_name(e)
        if not pkg:
            traceback.print_exc()
            break
        install_name = resolve_pkg(pkg)
        print(f"[AUTO] Missing: {{pkg}} -> installing {{install_name}}...")
        try:
            top_mod = pkg.split('.')[0]
            if top_mod != install_name:
                subprocess.check_call([sys.executable, "-m", "pip", "uninstall", "-y", top_mod], stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)
            subprocess.check_call([sys.executable, "-m", "pip", "install", install_name])
            append_installed(install_name)
            print(f"[AUTO] Installed: {{install_name}} -> restarting...")
            continue
        except Exception as ex:
            print(f"[AUTO] Failed: {{ex}}")
            traceback.print_exc()
            break
    except ImportError as e:
        print(f"[AUTO] ImportError: {{e}}")
        pkg = parse_missing_name(e)
        if pkg:
            install_name = resolve_pkg(pkg)
            if install_name != pkg:
                print(f"[AUTO] Re-trying with: {{install_name}}")
                try:
                    top_mod = pkg.split('.')[0]
                    subprocess.check_call([sys.executable, "-m", "pip", "uninstall", "-y", top_mod], stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)
                    subprocess.check_call([sys.executable, "-m", "pip", "install", install_name])
                    append_installed(install_name)
                    print(f"[AUTO] Installed: {{install_name}} -> restarting...")
                    continue
                except:
                    pass
        traceback.print_exc()
        break
    except Exception:
        traceback.print_exc()
        break
'''


def start_with_autoinstall(owner, folder, startup_file):
    server_dir = get_server_dir(owner, folder)
    log_path = os.path.join(server_dir, "server.log")
    log_file = open(log_path, "a", encoding="utf-8", errors="ignore")

    if startup_file.lower().endswith(".php"):
        proc = subprocess.Popen(
            ["php", startup_file],
            cwd=server_dir,
            stdout=log_file,
            stderr=log_file,
            env=get_subprocess_env(),
        )
    else:
        wrapper_code = WRAPPER_TEMPLATE.format(base_dir=BASE_DIR)
        proc = subprocess.Popen(
            [sys.executable, "-u", "-c", wrapper_code, startup_file],
            cwd=server_dir,
            stdout=log_file,
            stderr=log_file,
            env=get_subprocess_env(),
        )
    return proc, log_file


def stop_proc(key):
    if key in running_procs:
        proc, logf = running_procs[key]
        try:
            p = psutil.Process(proc.pid)
            for child in p.children(recursive=True):
                child.kill()
            p.kill()
        except Exception:
            pass
        try:
            logf.close()
        except Exception:
            pass
        running_procs.pop(key, None)


@app.route("/")
def home():
    if not session.get("user"):
        return send_from_directory(BASE_DIR, "landing.html")
    return redirect("/dashboard")


@app.route("/dashboard")
@login_required
def dashboard():
    return send_from_directory(BASE_DIR, "index.html")


@app.route("/developer")
def developer_page():
    dev_url = os.environ.get("DEVELOPER_URL")
    if dev_url:
        return redirect(dev_url)
    return send_from_directory(BASE_DIR, "developer.html")


@app.route("/terms")
def terms_page():
    return send_from_directory(BASE_DIR, "terms.html")


@app.route("/privacy")
def privacy_page():
    return send_from_directory(BASE_DIR, "privacy.html")


@app.route("/features-info")
def features_page():
    return send_from_directory(BASE_DIR, "features.html")


@app.route("/docs")
def docs_page():
    return send_from_directory(BASE_DIR, "docs.html")


@app.route("/login")
def login_page():
    return send_from_directory(BASE_DIR, "login.html")


@app.route("/create")
def create_page():
    return send_from_directory(BASE_DIR, "create.html")


@app.route("/admin")
@login_required
def admin_page():
    if not is_admin_session():
        return redirect("/")
    return send_from_directory(BASE_DIR, "admin.html")


@app.route("/logout")
def logout():
    session.pop("user", None)
    return redirect("/login")


@app.route("/api/auth/login", methods=["POST"])
@rate_limited
def api_login():
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""

    if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
        session["user"] = {"username": ADMIN_USERNAME, "is_admin": True}
        session.permanent = True
        return jsonify({"success": True, "is_admin": True})

    db = load_users()
    u = find_user(db, username)
    if not u:
        return jsonify({"success": False, "message": "Invalid username or password"}), 401
    if not u.get("active", True):
        return jsonify({"success": False, "message": "Account is pending or has been suspended"}), 403
    if not check_password_hash(u.get("password_hash", ""), password):
        return jsonify({"success": False, "message": "Invalid username or password"}), 401

    session["user"] = {"username": u.get("username"), "is_admin": False}
    session.permanent = True
    ensure_user_dirs(u.get("username"))
    return jsonify({"success": True, "is_admin": False})


DISPOSABLE_DOMAINS = [
    "tempmail.com", "10minutemail.com", "guerrillamail.com",
    "mailinator.com", "yopmail.com", "dropmail.me", "mohmal.com",
    "maildrop.cc", "dispostable.com", "temp-mail.org", "nada.ltd"
]


def get_client_ip():
    if request.headers.get('X-Forwarded-For'):
        return request.headers.get('X-Forwarded-For').split(',')[0].strip()
    return request.remote_addr or ""


@app.route("/api/auth/register-otp", methods=["POST"])
@rate_limited
def api_register_otp():
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""
    email = (data.get("email") or "").strip()

    if not email or '@' not in email:
        return jsonify({"success": False, "message": "Invalid email address"}), 400

    if len(username) < 3 or len(username) > 20:
        return jsonify({"success": False, "message": "Username must be 3-20 characters"}), 400
    if not re.match(r'^[A-Za-z0-9_]+$', username):
        return jsonify({"success": False, "message": "Username: letters, numbers, underscore only"}), 400
    if len(password) < 6:
        return jsonify({"success": False, "message": "Password must be at least 6 characters"}), 400
    if username.lower() == ADMIN_USERNAME.lower():
        return jsonify({"success": False, "message": "Username not available"}), 400

    db = load_users()
    if find_user(db, username):
        return jsonify({"success": False, "message": "Username already taken"}), 409

    for u in db.get("users", []):
        if u.get("email") == email:
            return jsonify({"success": False, "message": "Email already in use"}), 409

    client_ip = get_client_ip()
    new_user = {
        "username": username,
        "email": email,
        "password_hash": generate_password_hash(password),
        "active": True,
        "plan": "free",
        "ip": client_ip,
        "created_at": time.strftime("%Y-%m-%d %H:%M:%S")
    }
    db.setdefault("users", []).append(new_user)
    save_users(db)
    logger.info(f"New user registered: {username} from IP: {client_ip}")

    session["user"] = {"username": username, "is_admin": False}
    session.permanent = True
    ensure_user_dirs(username)
    return jsonify({"success": True, "skip_otp": True, "message": "Account created successfully. Redirecting to dashboard..."}), 200


@app.route("/api/user/profile")
@login_required
def api_user_profile():
    username = current_username()
    db = load_users()
    u = find_user(db, username)
    plan_name = "admin" if is_admin_session() else (u.get("plan", "free") if u else "free")
    plan_info = PLANS.get(plan_name, PLANS["free"])
    return jsonify({
        "success": True,
        "username": username,
        "is_admin": is_admin_session(),
        "plan": plan_name,
        "plan_label": plan_info.get("label", plan_name.title()),
        "max_bots": get_user_limit(username),
        "max_mem_mb": get_user_mem_limit(username)
    })


@app.route("/api/admin/users")
@admin_required
def api_admin_users():
    db = load_users()
    users = []
    for u in db.get("users", []):
        users.append({
            "username": u.get("username"),
            "active": u.get("active", True),
            "plan": u.get("plan", "free"),
            "created_at": u.get("created_at", "unknown")
        })
    return jsonify({"success": True, "users": users})


@app.route("/api/admin/user/set-plan", methods=["POST"])
@admin_required
def api_admin_set_plan():
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    plan = (data.get("plan") or "free").strip()
    if plan not in PLANS:
        return jsonify({"success": False, "message": "Invalid plan"}), 400
    db = load_users()
    u = find_user(db, username)
    if not u:
        return jsonify({"success": False, "message": "User not found"}), 404
    u["plan"] = plan
    save_users(db)
    return jsonify({"success": True})


@app.route("/api/admin/user/toggle-active", methods=["POST"])
@admin_required
def api_admin_toggle_active():
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    db = load_users()
    u = find_user(db, username)
    if not u:
        return jsonify({"success": False, "message": "User not found"}), 404
    u["active"] = not u.get("active", True)
    save_users(db)
    return jsonify({"success": True, "active": u["active"]})


@app.route("/api/admin/user/delete", methods=["POST"])
@admin_required
def api_admin_delete_user():
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    db = load_users()
    u = find_user(db, username)
    if not u:
        return jsonify({"success": False, "message": "User not found"}), 404
    db["users"] = [x for x in db.get("users", []) if (x.get("username") or "").strip().lower() != username.lower()]
    save_users(db)
    return jsonify({"success": True})


def list_all_servers_for_admin():
    servers = []
    if not os.path.isdir(USERS_ROOT):
        return servers

    for owner in sorted(os.listdir(USERS_ROOT)):
        root = get_user_servers_root(owner)
        if not os.path.isdir(root):
            continue
        for folder in sorted(os.listdir(root)):
            server_dir = get_server_dir(owner, folder)
            if not os.path.isdir(server_dir):
                continue
            meta = read_meta(owner, folder)
            banned = bool(meta.get("banned", False))
            key = f"{owner}::{folder}"
            st = "Banned" if banned else get_state(key)
            servers.append({
                "title": meta.get("display_name", folder),
                "folder": folder,
                "owner": owner,
                "key": key,
                "subtitle": f"Owner: {owner}",
                "startup_file": meta.get("startup_file", ""),
                "status": st,
                "banned": banned
            })
    return servers


def list_servers_for_user(username):
    ensure_user_dirs(username)
    root = get_user_servers_root(username)
    servers = []
    for folder in sorted(os.listdir(root)):
        server_dir = get_server_dir(username, folder)
        if not os.path.isdir(server_dir):
            continue
        meta = read_meta(username, folder)
        banned = bool(meta.get("banned", False))
        key = folder
        st = "Banned" if banned else get_state(key)
        servers.append({
            "title": meta.get("display_name", folder),
            "folder": folder,
            "owner": username,
            "key": key,
            "subtitle": f"Owner: {username}",
            "startup_file": meta.get("startup_file", ""),
            "status": st,
            "banned": banned
        })
    return servers


@app.route("/servers")
@login_required
def servers():
    if is_admin_session():
        return jsonify({"success": True, "servers": list_all_servers_for_admin()})
    return jsonify({"success": True, "servers": list_servers_for_user(current_username())})


@app.route("/add", methods=["POST"])
@login_required
@rate_limited
def add_server():
    data = request.get_json(silent=True) or {}
    name = (data.get("name") or "").strip()
    folder = sanitize_folder_name(name)
    if not folder:
        return jsonify({"success": False, "message": "Invalid server name"}), 400

    if is_admin_session():
        owner = current_username()
    else:
        owner = current_username()

    ensure_user_dirs(owner)

    if not is_admin_session():
        limit = get_user_limit(owner)
        existing = [d for d in os.listdir(get_user_servers_root(owner)) if os.path.isdir(get_server_dir(owner, d))]
        if len(existing) >= limit:
            return jsonify({"success": False, "message": f"Maximum server limit reached ({limit}). Contact support to increase your limit."}), 403

    target = get_server_dir(owner, folder)
    if os.path.exists(target):
        return jsonify({"success": False, "message": "Server already exists"}), 409

    os.makedirs(target, exist_ok=True)
    open(os.path.join(target, "server.log"), "w", encoding="utf-8").close()

    meta = {
        "display_name": name or folder,
        "startup_file": "",
        "owner": owner,
        "banned": False
    }
    write_meta(owner, folder, meta)

    set_state(folder if not is_admin_session() else f"{owner}::{folder}", "Offline")

    if is_admin_session():
        return jsonify({"success": True, "servers": list_all_servers_for_admin()})
    return jsonify({"success": True, "servers": list_servers_for_user(owner)})


@app.route("/server/stats/<path:key>")
@login_required
def server_stats(key):
    if not can_access_key(key):
        return jsonify({"success": False, "message": "Forbidden"}), 403

    owner, folder = parse_server_key(key, allow_admin=True)
    server_dir = get_server_dir(owner, folder)
    if not os.path.isdir(server_dir):
        return jsonify({"status": "Offline", "cpu": "0%", "mem": "0 MB", "logs": "", "ip": get_ip()}), 404

    meta = read_meta(owner, folder)
    if meta.get("banned", False):
        set_state(key, "Banned")

    proc_tuple = running_procs.get(key)
    running = False
    cpu, mem = "0%", "0 MB"

    if proc_tuple:
        proc, _logf = proc_tuple
        if psutil.pid_exists(proc.pid):
            try:
                p = psutil.Process(proc.pid)
                if p.is_running() and p.status() != psutil.STATUS_ZOMBIE:
                    running = True
                    cpu = f"{p.cpu_percent(interval=None)}%"
                    mem = f"{p.memory_info().rss / 1024 / 1024:.1f} MB"
            except Exception:
                pass

    log_path = os.path.join(server_dir, "server.log")
    # Bolt: cached read - unchanged logs skip re-reading on every 2s poll.
    logs = read_server_log(log_path)

    state = get_state(key)
    if meta.get("banned", False):
        state = "Banned"
    elif running:
        state = "Running"
        set_state(key, "Running")
    elif state not in ("Installing", "Starting"):
        state = "Offline"
        set_state(key, "Offline")

    return jsonify({"status": state, "cpu": cpu, "mem": mem, "logs": logs, "ip": get_ip()})


def background_start(key, owner, folder, startup_file):
    log_key = f"{owner}::{folder}"
    try:
        set_state(key, "Installing")
        log_append(log_key, "[SYSTEM] Preparing...\n")
        ensure_requirements_installed(owner, folder)
        set_state(key, "Starting")
        log_append(log_key, "[SYSTEM] Starting...\n")
        proc, logf = start_with_autoinstall(owner, folder, startup_file)
        running_procs[key] = (proc, logf)
        time.sleep(1.0)
        if proc.poll() is None:
            set_state(key, "Running")
        else:
            set_state(key, "Offline")
    except Exception as e:
        log_append(log_key, f"[SYSTEM] Start failed: {e}\n")
        set_state(key, "Offline")


@app.route("/server/action/<path:key>/<act>", methods=["POST"])
@login_required
@rate_limited
def server_action(key, act):
    if not can_access_key(key):
        return jsonify({"success": False, "message": "Forbidden"}), 403

    owner, folder = parse_server_key(key, allow_admin=True)
    server_dir = get_server_dir(owner, folder)
    if not os.path.isdir(server_dir):
        return jsonify({"success": False, "message": "Server not found"}), 404

    meta = read_meta(owner, folder)
    if meta.get("banned", False):
        set_state(key, "Banned")
        return jsonify({"success": False, "message": "Server is banned by admin"}), 403

    days_passed = (time.time() - meta.get("last_renewed", 0)) / (24 * 3600)
    if not is_admin_session() and days_passed > BOT_RENEW_DAYS:
        set_state(key, "Offline")
        return jsonify({"success": False, "expired": True, "message": "Bot expired. Please reactivate it from the dashboard."}), 403

    if act in ("stop", "restart"):
        stop_proc(key)
        set_state(key, "Offline")

    if act == "stop":
        return jsonify({"success": True})

    startup = meta.get("startup_file") or ""
    if not startup:
        return jsonify({"success": False, "message": "No main file set"}), 400

    open(os.path.join(server_dir, "server.log"), "w", encoding="utf-8").close()

    t = threading.Thread(target=background_start, args=(key, owner, folder, startup), daemon=True)
    t.start()
    return jsonify({"success": True})


@app.route("/server/set-startup/<path:key>", methods=["POST"])
@login_required
def set_startup(key):
    if not can_access_key(key):
        return jsonify({"success": False, "message": "Forbidden"}), 403

    owner, folder = parse_server_key(key, allow_admin=True)
    server_dir = get_server_dir(owner, folder)
    if not os.path.isdir(server_dir):
        return jsonify({"success": False, "message": "Server not found"}), 404

    data = request.get_json(silent=True) or {}
    f = (data.get("file") or "").strip()
    meta = read_meta(owner, folder)
    meta["startup_file"] = f
    write_meta(owner, folder, meta)
    return jsonify({"success": True})


@app.route("/server/delete/<path:key>", methods=["POST"])
@login_required
@rate_limited
def server_delete(key):
    if not can_access_key(key):
        return jsonify({"success": False, "message": "Forbidden"}), 403
    stop_proc(key)
    owner, folder = parse_server_key(key, allow_admin=True)
    server_dir = get_server_dir(owner, folder)
    if os.path.isdir(server_dir):
        shutil.rmtree(server_dir)
    return jsonify({"success": True})


@app.route("/files/list/<path:key>")
@login_required
def files_list(key):
    if not can_access_key(key):
        return jsonify({"success": False, "message": "Forbidden", "path": ""}), 403

    rel = request.args.get("path", "") or ""
    try:
        base = safe_join_server_path(key, rel)
    except Exception:
        return jsonify({"success": False, "message": "Invalid path", "path": ""}), 400

    dirs, files = [], []
    if os.path.isdir(base):
        for name in sorted(os.listdir(base), key=lambda x: (not os.path.isdir(os.path.join(base, x)), x.lower())):
            if rel == "" and name in ("meta.json", "server.log"):
                continue
            full = os.path.join(base, name)
            if os.path.isdir(full):
                dirs.append({"name": name})
            elif os.path.isfile(full):
                try:
                    size_kb = os.path.getsize(full) / 1024
                    size = f"{size_kb:.1f} KB"
                except Exception:
                    size = ""
                files.append({"name": name, "size": size})

    return jsonify({"success": True, "path": rel, "dirs": dirs, "files": files})


@app.route("/files/content/<path:key>")
@login_required
def file_content(key):
    if not can_access_key(key):
        return jsonify({"content": ""}), 403
    file_rel = request.args.get("file", "") or ""
    try:
        full = safe_join_server_path(key, file_rel)
    except Exception:
        return jsonify({"content": ""}), 400
    if os.path.isdir(full):
        return jsonify({"content": ""}), 400
    try:
        with open(full, "r", encoding="utf-8", errors="ignore") as f:
            return jsonify({"content": f.read()})
    except Exception:
        return jsonify({"content": ""})


@app.route("/files/save/<path:key>", methods=["POST"])
@login_required
@rate_limited
def file_save(key):
    if not can_access_key(key):
        return jsonify({"success": False, "message": "Forbidden"}), 403

    data = request.get_json(silent=True) or {}
    file_rel = data.get("file", "") or ""
    content = data.get("content", "")

    try:
        full = safe_join_server_path(key, file_rel)
    except Exception:
        return jsonify({"success": False, "message": "Invalid path"}), 400

    owner, folder = parse_server_key(key, allow_admin=True)
    server_dir = get_server_dir(owner, folder)

    current_size_mb = get_dir_size(server_dir) / 1024 / 1024
    disk_limit_mb = get_user_disk_limit(owner)

    if current_size_mb + (len(content.encode('utf-8')) / 1024 / 1024) > disk_limit_mb:
        return jsonify({"success": False, "message": f"Disk limit exceeded ({disk_limit_mb}MB max)"}), 403

    os.makedirs(os.path.dirname(full), exist_ok=True)
    try:
        with open(full, "w", encoding="utf-8") as f:
            f.write(content)
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500


@app.route("/files/mkdir/<path:key>", methods=["POST"])
@login_required
def file_mkdir(key):
    if not can_access_key(key):
        return jsonify({"success": False, "message": "Forbidden"}), 403
    data = request.get_json(silent=True) or {}
    rel = data.get("path", "") or ""
    name = safe_name(data.get("name", ""))
    if not name:
        return jsonify({"success": False, "message": "Bad name"}), 400
    try:
        target = safe_join_server_path(key, os.path.join(rel, name))
        os.makedirs(target, exist_ok=False)
        return jsonify({"success": True})
    except FileExistsError:
        return jsonify({"success": False, "message": "Already exists"}), 409
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500


@app.route("/files/rename/<path:key>", methods=["POST"])
@login_required
def file_rename(key):
    if not can_access_key(key):
        return jsonify({"success": False, "message": "Forbidden"}), 403
    data = request.get_json(silent=True) or {}
    rel = data.get("path", "") or ""
    old = safe_name(data.get("old", ""))
    new = safe_name(data.get("new", ""))
    if not old or not new:
        return jsonify({"success": False, "message": "Bad name"}), 400
    try:
        src = safe_join_server_path(key, os.path.join(rel, old))
        dst = safe_join_server_path(key, os.path.join(rel, new))
        os.rename(src, dst)
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500


@app.route("/files/delete/<path:key>", methods=["POST"])
@login_required
def file_delete(key):
    if not can_access_key(key):
        return jsonify({"success": False, "message": "Forbidden"}), 403
    data = request.get_json(silent=True) or {}
    rel = data.get("path", "") or ""
    name = safe_name(data.get("name", ""))
    kind = (data.get("kind") or "file").lower()
    if not name:
        return jsonify({"success": False, "message": "Bad name"}), 400
    try:
        target = safe_join_server_path(key, os.path.join(rel, name))
        if kind == "dir":
            shutil.rmtree(target)
        else:
            os.remove(target)
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500


@app.route("/files/upload/<path:key>", methods=["POST"])
@login_required
@rate_limited
def file_upload(key):
    if not can_access_key(key):
        return jsonify({"success": False, "message": "Forbidden"}), 403

    rel = request.args.get("path", "") or ""
    try:
        base_dir = safe_join_server_path(key, rel)
    except Exception:
        return jsonify({"success": False, "message": "Invalid path"}), 400
    os.makedirs(base_dir, exist_ok=True)

    owner, folder = parse_server_key(key, allow_admin=True)
    server_dir = get_server_dir(owner, folder)
    current_size_mb = get_dir_size(server_dir) / 1024 / 1024
    disk_limit_mb = get_user_disk_limit(owner)

    files = request.files.getlist("files") or []
    if not files:
        one = request.files.get("file")
        if one:
            files = [one]
    if not files:
        return jsonify({"success": False, "message": "No file"}), 400

    relpaths = request.form.getlist("relpaths")
    saved = 0

    for i, f in enumerate(files):
        if not f or not f.filename:
            continue
        filename = os.path.basename(f.filename)

        rp = ""
        if relpaths and i < len(relpaths):
            rp = (relpaths[i] or "").replace("\\", "/").lstrip("/")

        try:
            if rp:
                target_dir = safe_join_server_path(key, os.path.join(rel, os.path.dirname(rp)))
            else:
                target_dir = base_dir
        except Exception:
            continue

        f.seek(0, os.SEEK_END)
        file_length = f.tell()
        f.seek(0)

        if current_size_mb + (file_length / 1024 / 1024) > disk_limit_mb:
            continue

        current_size_mb += file_length / 1024 / 1024

        os.makedirs(target_dir, exist_ok=True)
        f.save(os.path.join(target_dir, filename))
        saved += 1

    return jsonify({"success": True, "saved": saved})


@app.route("/api/admin/servers")
@admin_required
def admin_servers():
    return jsonify({"success": True, "servers": list_all_servers_for_admin()})


@app.route("/api/admin/server/ban", methods=["POST"])
@admin_required
def admin_server_ban():
    data = request.get_json(silent=True) or {}
    key = (data.get("key") or "").strip()
    banned = bool(data.get("banned", True))

    owner, folder = parse_server_key(key, allow_admin=True)
    server_dir = get_server_dir(owner, folder)
    if not os.path.isdir(server_dir):
        return jsonify({"success": False, "message": "Server not found"}), 404

    meta = read_meta(owner, folder)
    meta["banned"] = banned
    write_meta(owner, folder, meta)

    if banned:
        stop_proc(key)
        set_state(key, "Banned")
        log_append(key, "[ADMIN] Server banned.\n")
    else:
        set_state(key, "Offline")
        log_append(key, "[ADMIN] Server unbanned.\n")

    return jsonify({"success": True})


@app.route("/api/ai/chat", methods=["POST"])
@login_required
@rate_limited
def api_ai_chat():
    client = get_ai_client()
    if client is None:
        return jsonify({"success": False, "message": "AI service currently unavailable"}), 503

    username = current_username()
    db = load_users()
    u = find_user(db, username)

    if not u and not is_admin_session():
        return jsonify({"success": False, "message": "User not found"}), 404

    now_date = time.strftime("%Y-%m-%d")

    if u:
        ai_status = u.setdefault("ai_usage", {"date": "", "count": 0})
    else:
        ai_status = {"date": now_date, "count": 0}

    if ai_status["date"] != now_date:
        ai_status["date"] = now_date
        ai_status["count"] = 0

    if not is_admin_session() and ai_status["count"] >= AI_DAILY_LIMIT:
        return jsonify({"success": False, "message": f"Daily limit reached ({AI_DAILY_LIMIT} requests). Please try again tomorrow."}), 429

    data = request.get_json(silent=True) or {}
    message = data.get("message", "").strip()
    model = data.get("model", "deepseek-r1:latest")

    if not message:
        return jsonify({"success": False, "message": "No message provided"}), 400

    SYSTEM_PROMPT = "You are White Wolf AI, a specialized assistant for the White Wolf Bot Hosting platform. Help users with their bots, code, and platform issues. Be helpful and expert."

    try:
        full_prompt = f"System: {SYSTEM_PROMPT}\nUser: {message}"
        response = client.chat(model=model, prompt=full_prompt)
        ai_status["count"] += 1
        save_users(db)
        return jsonify({"success": True, "response": response})
    except Exception as e:
        logger.error(f"AI Error: {e}")
        return jsonify({"success": False, "message": str(e)}), 500


@app.route("/api/ai/models")
@login_required
def api_ai_models():
    return jsonify({
        "success": True,
        "models": ["llama3.2:3b", "deepseek-r1:latest", "mistral:latest", "gpt-oss:20b"]
    })


@app.route("/api/ads")
def api_get_ads():
    return jsonify(load_ads())


@app.route("/api/server/renew/<path:key>", methods=["POST"])
@login_required
def api_renew_server(key):
    if not can_access_key(key):
        return jsonify({"success": False, "message": "Forbidden"}), 403
    owner, folder = parse_server_key(key, allow_admin=True)
    meta = read_meta(owner, folder)
    meta["last_renewed"] = time.time()
    write_meta(owner, folder, meta)
    return jsonify({"success": True})


@app.route("/api/admin/quickstats")
@admin_required
def admin_quickstats():
    total_servers = 0
    running = 0
    installing = 0
    banned = 0

    for s in list_all_servers_for_admin():
        total_servers += 1
        if s.get("status") == "Banned":
            banned += 1
        elif s.get("status") == "Running":
            running += 1
        elif s.get("status") in ("Installing", "Starting"):
            installing += 1

    db = load_users()
    total_users = len(db.get("users", []))
    active_users = sum(1 for u in db.get("users", []) if u.get("active", True))
    premium_users = sum(1 for u in db.get("users", []) if u.get("premium", False))

    return jsonify({"success": True, "stats": {
        "servers_total": total_servers,
        "servers_running": running,
        "servers_installing": installing,
        "servers_banned": banned,
        "users_total": total_users,
        "users_active": active_users,
        "users_premium": premium_users
    }})


def run_keep_alive():
    port = int(os.environ.get("SERVER_PORT", 30170))
    url = f"http://127.0.0.1:{port}/health"
    time.sleep(15)
    while True:
        try:
            requests.get(url, timeout=10)
            with lock:
                for key in list(running_procs.keys()):
                    proc, logf = running_procs[key]
                    if not psutil.pid_exists(proc.pid) or proc.poll() is not None:
                        logger.info(f"Process dead for '{key}', cleaning up")
                        try:
                            logf.close()
                        except Exception:
                            pass
                        running_procs.pop(key, None)
                        server_states[key] = "Offline"
                    else:
                        try:
                            p = psutil.Process(proc.pid)
                            mem_mb = p.memory_info().rss / 1024 / 1024
                            if mem_mb > MAX_PROCESS_MEMORY_MB:
                                logger.warning(f"Process '{key}' using {mem_mb:.0f}MB, killing")
                                for child in p.children(recursive=True):
                                    child.kill()
                                p.kill()
                                running_procs.pop(key, None)
                                server_states[key] = "Offline"
                                log_append(key, f"[SYSTEM] Killed: memory limit exceeded ({mem_mb:.0f}MB)\n")
                        except Exception:
                            pass
                for key, state in list(server_states.items()):
                    if state == "Running" and key not in running_procs:
                        logger.info(f"Auto-Recovery: restarting '{key}'")
                        try:
                            owner, folder = key.split("::", 1) if "::" in key else (ADMIN_USERNAME, key)
                            meta = read_meta(owner, folder)
                            startup = meta.get("startup_file")
                            if startup and not meta.get("banned", False):
                                t = threading.Thread(target=background_start, args=(key, owner, folder, startup), daemon=True)
                                t.start()
                            else:
                                server_states[key] = "Offline"
                        except Exception as e:
                            logger.error(f"Recovery failed for '{key}': {e}")
                            server_states[key] = "Offline"
        except Exception as e:
            logger.error(f"Keep-Alive Error: {e}")
        time.sleep(300)


def run_git_sync():
    if os.environ.get("SPACE_ID"):
        logger.info("Git Auto-Sync disabled in Hugging Face Space")
        return

    logger.info("Git Auto-Sync system started")
    while True:
        try:
            cwd = os.getcwd()
            subprocess.run(["git", "add", "."], cwd=cwd, capture_output=True)
            msg = f"Auto-Sync: {time.strftime('%Y-%m-%d %H:%M:%S')}"
            subprocess.run(["git", "commit", "-m", msg], cwd=cwd, capture_output=True)
            subprocess.run(["git", "push", "origin", "main"], cwd=cwd, capture_output=True)
            subprocess.run(["git", "push", "hf", "main"], cwd=cwd, capture_output=True)
            logger.info("Auto-Sync: Platform synced with GitHub & Hugging Face")
        except Exception as e:
            logger.error(f"Auto-Sync Error: {e}")
        time.sleep(3600)


def truncate_large_logs():
    if not os.path.isdir(USERS_ROOT):
        return
    for owner in os.listdir(USERS_ROOT):
        root = get_user_servers_root(owner)
        if not os.path.isdir(root):
            continue
        for folder in os.listdir(root):
            log_path = os.path.join(get_server_dir(owner, folder), "server.log")
            try:
                if os.path.exists(log_path) and os.path.getsize(log_path) > MAX_LOG_SIZE:
                    with open(log_path, 'r', encoding='utf-8', errors='ignore') as f:
                        f.seek(os.path.getsize(log_path) - MAX_LOG_SIZE // 2)
                        content = f.read()
                    with open(log_path, 'w', encoding='utf-8') as f:
                        f.write("[SYSTEM] Log truncated\n" + content)
            except Exception:
                pass


def run_log_cleaner():
    while True:
        time.sleep(600)
        truncate_large_logs()


@app.route("/health")
def health_check():
    return jsonify({"status": "ok", "uptime": time.time()})


@app.route("/api/system/status")
@admin_required
def system_status():
    try:
        cpu = psutil.cpu_percent(interval=0.5)
        mem = psutil.virtual_memory()
        disk = psutil.disk_usage('/')
        procs = len(running_procs)
        return jsonify({
            "success": True,
            "cpu_percent": cpu,
            "memory_used_mb": round(mem.used / 1024 / 1024),
            "memory_total_mb": round(mem.total / 1024 / 1024),
            "memory_percent": mem.percent,
            "disk_used_gb": round(disk.used / 1024 / 1024 / 1024, 1),
            "disk_total_gb": round(disk.total / 1024 / 1024 / 1024, 1),
            "disk_percent": round(disk.percent, 1),
            "running_processes": procs
        })
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500


def graceful_shutdown(signum, frame):
    logger.info("Shutting down gracefully...")
    with lock:
        for key in list(running_procs.keys()):
            stop_proc(key)
    logger.info("All processes stopped.")
    sys.exit(0)


signal.signal(signal.SIGTERM, graceful_shutdown)
signal.signal(signal.SIGINT, graceful_shutdown)

if __name__ == "__main__":
    port = int(os.environ.get("SERVER_PORT", 7860))
    logger.info(f"--- SYSTEM INITIALIZATION: Port {port} ---")

    threading.Thread(target=run_keep_alive, daemon=True).start()
    threading.Thread(target=run_log_cleaner, daemon=True).start()
    threading.Thread(target=run_git_sync, daemon=True).start()

    try:
        from gunicorn.app.wsgiapp import run as gunicorn_run
        logger.info("Launching Production WSGI Engine (Gunicorn)...")
        sys.argv = [
            'gunicorn',
            '--bind', f'0.0.0.0:{port}',
            '--worker-class', 'sync',
            '--workers', '1',
            '--timeout', '600',
            'app:app'
        ]
        gunicorn_run()
    except Exception as e:
        logger.error(f"Gunicorn failed: {e}. Falling back to development server.")
        app.run(host="0.0.0.0", port=port, threaded=True)
