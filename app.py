import re, json, sqlite3, os, time, base64, traceback, threading, shutil, hmac, hashlib, secrets
import smtplib
import logging
from logging.handlers import RotatingFileHandler
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from functools import wraps
from threading import Lock
from flask import Flask, render_template, request, jsonify, session, redirect, url_for, send_from_directory, Response, abort, g
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from werkzeug.exceptions import HTTPException
from cryptography.fernet import Fernet
from werkzeug.middleware.proxy_fix import ProxyFix

from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from cachetools import TTLCache

log_handler = RotatingFileHandler('fortigrid.log', maxBytes=5_000_000, backupCount=5)
logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s', handlers=[log_handler])

app = Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)
limiter = Limiter(get_remote_address, app=app, storage_uri="memory://")

DB_PATH = 'data/fortigrid.db'
for d in ['data', 'data/uploads', 'data/screens', 'data/downloads', 'backup']: os.makedirs(d, exist_ok=True)

# 🔐 1. ENTERPRISE SECRETS MANAGEMENT (No Hardcoded Fallbacks)
def get_or_create_secret(filename, length=32):
    path = os.path.join('data', filename)
    if os.path.exists(path):
        with open(path, 'r') as f: return f.read().strip()
    else:
        val = secrets.token_hex(length)
        with open(path, 'w') as f: f.write(val)
        return val

app.secret_key = os.getenv("SECRET_KEY") or get_or_create_secret('.secret_key')
COMMAND_SECRET_STR = os.getenv("COMMAND_SECRET") or get_or_create_secret('.command_secret')
COMMAND_SECRET = COMMAND_SECRET_STR.encode()
REGISTRATION_KEY = os.getenv("REGISTRATION_KEY") or get_or_create_secret('.registration_key', 16)
FERNET_KEY = os.getenv("FERNET_KEY") or get_or_create_secret('.fernet_key')

# Output BOTH keys to the console so the Admin can copy them to the Agent
print("================================================================")
print(f"🔐 AGENT ENROLLMENT KEY: {REGISTRATION_KEY}")
print(f"🔐 COMMAND SECRET KEY:   {COMMAND_SECRET_STR}")
print("================================================================")

cipher_suite = Fernet(FERNET_KEY.encode() if len(FERNET_KEY) == 44 else Fernet.generate_key())

# 🔐 2. SECURE COOKIES
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=True, # Enforced for Cloudflare ProxyFix
    SESSION_COOKIE_SAMESITE='Lax',
    MAX_CONTENT_LENGTH=50 * 1024 * 1024
)

USED_NONCES = TTLCache(maxsize=10000, ttl=300)
NONCE_LOCK = Lock()

# 🔐 3. BRUTE FORCE LOCKOUT CACHE
FAILED_LOGINS = TTLCache(maxsize=1000, ttl=900) # 15 minute ban

alerted_states = set()
AGENT_CACHE = TTLCache(maxsize=1000, ttl=300)

@app.before_request
def enforce_security():
    g.nonce = secrets.token_urlsafe(16)
    if request.headers.get('X-Forwarded-Proto', 'http') == 'http' \
      and not request.is_secure \
      and app.config.get("ENV") != "development" \
      and not app.testing:

       return redirect(request.url.replace("http://", "https://"))


    if request.is_json and request.content_length and request.content_length > 15 * 1024 * 1024:
      return jsonify({"error": "Payload too large"}), 413

@app.after_request
def set_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    
    # 🔐 4. STRICT CSP (Removed unsafe-inline from scripts)
    csp = (
        f"default-src 'self'; "
        f"img-src 'self' data: https: blob:; "
        f"script-src 'self' 'nonce-{g.nonce}' https://cdnjs.cloudflare.com https://cdn.jsdelivr.net https://static.cloudflareinsights.com; "
        f"style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://cdnjs.cloudflare.com; "
        f"font-src 'self' https://fonts.gstatic.com data: https://cdnjs.cloudflare.com; "
        f"connect-src 'self' https: wss:;"
    )
    response.headers['Content-Security-Policy'] = csp
    return response

@app.errorhandler(Exception)
def handle_exception(e):
    if isinstance(e, HTTPException): return jsonify({"error": e.description}), e.code
    logging.error(f"Unhandled Exception: {e}")
    return jsonify({"error": "Internal server error"}), 500

def get_db(): return sqlite3.connect(DB_PATH, timeout=30)

def init_db():
    try:
        with get_db() as conn:
            c = conn.cursor()
            c.execute("PRAGMA journal_mode=WAL;"); c.execute("PRAGMA synchronous=NORMAL;")
            c.execute('''CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE, password TEXT, role TEXT, last_active INTEGER)''')
            c.execute('''CREATE TABLE IF NOT EXISTS tickets (id INTEGER PRIMARY KEY AUTOINCREMENT, hostname TEXT, severity TEXT, message TEXT, status TEXT, created_at DATETIME DEFAULT CURRENT_TIMESTAMP)''')
            c.execute('''CREATE TABLE IF NOT EXISTS agents_store (hostname TEXT PRIMARY KEY, last_seen INTEGER, payload TEXT, command_queue TEXT)''')
            c.execute('''CREATE TABLE IF NOT EXISTS perf_history (hostname TEXT PRIMARY KEY, history_json TEXT)''')
            c.execute('''CREATE TABLE IF NOT EXISTS terminal_store (hostname TEXT PRIMARY KEY, cmd TEXT, output TEXT)''')
            c.execute('''CREATE TABLE IF NOT EXISTS explorer_store (hostname TEXT PRIMARY KEY, path TEXT, result TEXT)''')
            c.execute('''CREATE TABLE IF NOT EXISTS services_store (hostname TEXT PRIMARY KEY, result TEXT)''')
            c.execute('''CREATE TABLE IF NOT EXISTS scripts_store (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, description TEXT, code TEXT, created_by TEXT, created_at DATETIME DEFAULT CURRENT_TIMESTAMP)''')
            c.execute('''CREATE TABLE IF NOT EXISTS script_logs (id INTEGER PRIMARY KEY AUTOINCREMENT, script_id INTEGER, script_name TEXT, hostname TEXT, output TEXT, executed_at DATETIME DEFAULT CURRENT_TIMESTAMP)''')
            c.execute('''CREATE TABLE IF NOT EXISTS settings (id INTEGER PRIMARY KEY, cpu_alert INTEGER, ram_alert INTEGER, disk_alert INTEGER, offline_alert INTEGER, email_to TEXT, smtp_server TEXT, smtp_user TEXT, smtp_pass TEXT)''')
            c.execute('''CREATE TABLE IF NOT EXISTS eventlog_store (hostname TEXT PRIMARY KEY, result TEXT)''')
            c.execute('''CREATE TABLE IF NOT EXISTS agents_auth (hostname TEXT PRIMARY KEY, token TEXT)''') 
            c.execute('''CREATE TABLE IF NOT EXISTS processes_store (hostname TEXT PRIMARY KEY, result TEXT)''')
            c.execute('''CREATE TABLE IF NOT EXISTS audit_logs (id INTEGER PRIMARY KEY AUTOINCREMENT, user TEXT, action TEXT, target TEXT, timestamp DATETIME DEFAULT CURRENT_TIMESTAMP)''')
            c.execute("INSERT OR IGNORE INTO settings (id, cpu_alert, ram_alert, disk_alert, offline_alert, email_to, smtp_server, smtp_user, smtp_pass) VALUES (1, 95, 90, 5, 10, '', 'smtp.gmail.com:587', '', '')")
            conn.commit()
    except Exception as e: logging.error(f"Init DB: {e}")
init_db()

# 🔐 5. DATABASE AUDIT TRAIL
def audit_log(user, action, target):
    logging.info(f"[AUDIT] user={user} action={action} target={target}")
    try:
        with get_db() as conn:
            conn.cursor().execute("INSERT INTO audit_logs (user, action, target) VALUES (?, ?, ?)", (user, action, target))
            conn.commit()
    except Exception as e:
        logging.error(f"audit_log failed: {e}")

def get_host_from_data(data):
    if not data or not isinstance(data, dict): return "UNKNOWN"
    for key in ['hostname', 'Hostname', 'HOST', 'host', 'ComputerName']:
        if key in data and data[key]: return str(data[key]).strip().upper()
    return "UNKNOWN"

def get_clean_host(h): 
    val = str(h).strip().upper() if h else "UNKNOWN"
    if val != "UNKNOWN" and not re.match(r'^[A-Z0-9\-]{1,50}$', val): return "UNKNOWN"
    return val

def csrf_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if request.method == "GET": return f(*args, **kwargs)
        token = request.headers.get("X-CSRF-Token")
        if not token or token != session.get("csrf_token"): abort(403)
        return f(*args, **kwargs)
    return decorated_function

def verify_agent(req):
    api_key = req.headers.get("X-API-KEY")
    signature = req.headers.get("X-SIGNATURE")
    timestamp = req.headers.get("X-TIMESTAMP")
    nonce = req.headers.get("X-NONCE")

    if not api_key or not signature or not timestamp or not nonce: return None
    try:
        if abs(time.time() - int(timestamp)) > 300: return None
    except Exception: return None

    with NONCE_LOCK:
        if nonce in USED_NONCES: return None
        USED_NONCES[nonce] = True

    body = req.get_data()
    host = None
    
    try:
        with get_db() as conn:
            row = conn.cursor().execute("SELECT hostname FROM agents_auth WHERE token=?", (api_key,)).fetchone()
            if row: 
                host = row[0]
            else:
                if req.headers.get("X-REGISTER-KEY") != REGISTRATION_KEY: return None
                try:
                    payload = json.loads(body)
                    req_host = get_host_from_data(payload)
                    if req_host != "UNKNOWN":
                        c = conn.cursor()
                        c.execute("DELETE FROM agents_auth WHERE hostname=?", (req_host,))
                        c.execute("INSERT INTO agents_auth (hostname, token) VALUES (?, ?)", (req_host, api_key))
                        conn.commit()
                        host = req_host
                        AGENT_CACHE[host] = api_key
                        logging.info(f"[AUTO-REGISTER] Secure connection established for new host: {host}")
                except Exception:
                    logging.exception("Auto-register logging failed")
    except Exception as _: return None

    if not host: return None

    data_to_sign = body + timestamp.encode() + nonce.encode()
    expected_sig = hmac.new(api_key.encode(), data_to_sign, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected_sig, signature): return None

    return host

def agent_hmac_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        verified_host = verify_agent(request)
        if not verified_host: return jsonify({"error": "Unauthorized"}), 401
            
        data = request.get_json(silent=True) or {}
        declared_host = get_host_from_data(data)
        if declared_host == "UNKNOWN" and request.args.get('hostname'):
            declared_host = str(request.args.get('hostname')).strip().upper()
            
        if declared_host != "UNKNOWN" and declared_host != verified_host: return jsonify({"error": "Identity mismatch"}), 403
            
        request.verified_host = verified_host
        return f(*args, **kwargs)
    return decorated_function

def agent_limit_key():
    return request.headers.get("X-API-KEY", get_remote_address())

def cleanup_files():
    while True:
        try:
            for folder in ['data/screens', 'data/downloads']:
                for f in os.listdir(folder):
                    path = os.path.join(folder, f)
                    if os.path.isfile(path) and os.path.getmtime(path) < time.time() - 7*86400: os.remove(path)
        except Exception:
            app.logger.exception("Cleanup failed")
        time.sleep(3600)
threading.Thread(target=cleanup_files, daemon=True).start()

def backup_db():
    while True:
        try: 
            shutil.copy(DB_PATH, f"backup/fortigrid_{int(time.time())}.db")
            files = sorted([f for f in os.listdir('backup') if f.endswith('.db')])
            if len(files) > 10:
                for f in files[:-10]: os.remove(os.path.join('backup', f))
        except Exception:
            app.logger.exception("Backup cleanup failed")
        time.sleep(86400)
threading.Thread(target=backup_db, daemon=True).start()

def send_custom_email(to_email, smtp_server, smtp_user, smtp_pass, subject, body):
    server = None
    try:
        msg = MIMEMultipart()
        msg['From'] = smtp_user; msg['To'] = to_email; msg['Subject'] = subject
        msg.attach(MIMEText(body, 'plain'))
        host, port = smtp_server.split(':')
        server = smtplib.SMTP(host, int(port), timeout=10)
        server.ehlo(); server.starttls(); server.ehlo()
        server.login(smtp_user, smtp_pass)
        server.send_message(msg)
    except Exception:
        app.logger.exception(f"Failed to send email to {msg['To']}")
    finally:
        if server is not None:  # <-- only quit if server exists
            server.quit()

def alert_monitor_daemon():
    global alerted_states
    while True:
        try:
            with get_db() as conn:
                c = conn.cursor()
                c.execute("SELECT * FROM settings WHERE id=1"); row = c.fetchone()
                if not row: time.sleep(60); continue
                
                _, _, _, s_off, s_to, s_srv, s_user, enc_pass = row[1], row[2], row[3], row[4], row[5], row[6], row[7], row[8]
                
                # smtp_password = None
                if enc_pass:
                    try:
                        s_pass = cipher_suite.decrypt(enc_pass).decode()  # ✅ remove .encode()
                    except Exception:
                        time.sleep(60)
                        continue
                else:
                    time.sleep(60)
                    continue

                if not s_to or not s_user or not s_pass: time.sleep(60); continue
                
                c.execute("SELECT hostname, last_seen, payload FROM agents_store")
                agents = c.fetchall(); now = int(time.time())
                
                for a in agents:
                    host, last_seen, payload_str = a[0], a[1], a[2]
                    try: payload = json.loads(payload_str)
                    except Exception: payload = {}
                    
                    sys_info = payload.get('systemInfo', {})
                    if (now - last_seen) > (s_off * 60):
                        alert_key = f"{host}_offline"
                        if alert_key not in alerted_states:
                            send_custom_email(s_to, s_srv, s_user, s_pass, f"🚨 OFFLINE ALERT: {host}", f"Endpoint {host} unreachable for {s_off} mins.\nSystem Info: {sys_info}")
                            alerted_states.add(alert_key)
                    else: alerted_states.discard(f"{host}_offline")
        except Exception as _:
            app.logger.exception(f"Monitor loop error for host={host}")
        time.sleep(60)
threading.Thread(target=alert_monitor_daemon, daemon=True).start()

def extract_clean_string(val):
    if not val: return "-"
    if isinstance(val, dict):
        for k in ['IP', 'IPAddress', 'MAC', 'MacAddress', 'ip', 'mac']:
            if k in val:
                inner = val[k]
                if isinstance(inner, list): return str(inner[0])
                return str(inner)
        return "-"
    if isinstance(val, list): return extract_clean_string(val[0]) if val else "-"
    s = str(val).strip()
    if s == '[object Object]' or 'Unknown' in s or s == '127.0.0.1' or s == '00-00-00-00-00-00': return "-"
    return s

def update_agent_data(hostname, new_data, is_full=False):
    try:
        with get_db() as conn:
            c = conn.cursor()
            c.execute("SELECT last_seen, payload FROM agents_store WHERE hostname=?", (hostname,))
            row = c.fetchone(); now = int(time.time()); payload = {}
            if row:
                last_seen_db = row[0]
                if row[1]:
                    try:
                        payload = json.loads(row[1]) if row[1] else {}
                    except Exception as _:
                        app.logger.exception("Failed to parse payload JSON")
                        payload = {}
                if (now - last_seen_db) > 120: payload['last_logout'] = last_seen_db; payload['last_login'] = now
                elif 'last_login' not in payload or not payload['last_login']: payload['last_login'] = now; payload['last_logout'] = 0
            else: payload['last_login'] = now; payload['last_logout'] = 0

            if is_full:
                old_login, old_logout = payload.get('last_login'), payload.get('last_logout')
                payload.update(new_data)
                if old_login: payload['last_login'] = old_login
                if old_logout: payload['last_logout'] = old_logout
                if 'ip' in new_data: payload['ip'] = extract_clean_string(new_data['ip'])
                if 'mac' in new_data: payload['mac'] = extract_clean_string(new_data['mac'])
            else:
                if 'systemInfo' not in payload: payload['systemInfo'] = {}
                if 'cpu' in new_data: payload['systemInfo']['CpuLoad'] = new_data['cpu']
                if 'ram' in new_data: payload['systemInfo']['RamUsage'] = new_data['ram']
                if 'idle' in new_data: payload['systemInfo']['UserIdleTime'] = new_data['idle']

            if row: c.execute("UPDATE agents_store SET last_seen=?, payload=? WHERE hostname=?", (now, json.dumps(payload), hostname))
            else: c.execute("INSERT INTO agents_store (hostname, last_seen, payload, command_queue) VALUES (?, ?, ?, '[]')", (hostname, now, json.dumps(payload)))
            conn.commit()
    except Exception as _:
        app.logger.exception("Database operation failed")

def queue_cmd(hostname, cmd):
    try:
        with get_db() as conn:
            c = conn.cursor()
            signature = hmac.new(COMMAND_SECRET, cmd.encode(), hashlib.sha256).hexdigest()
            signed_cmd = f"{cmd}::{signature}"

            c.execute("SELECT command_queue FROM agents_store WHERE hostname=?", (hostname,))
            row = c.fetchone(); cmds = []
            if row and row[0]:
                try:
                    cmds = json.loads(row[0]) if row and row[0] else []
                except Exception as _:
                    app.logger.exception("Failed to parse cmds JSON from DB")
                    cmds = []
            
            if len(cmds) == 0 or cmds[-1] != signed_cmd: cmds.append(signed_cmd)
            if len(cmds) > 50: cmds = cmds[-50:]

            if row: c.execute("UPDATE agents_store SET command_queue=? WHERE hostname=?", (json.dumps(cmds), hostname))
            else: c.execute("INSERT INTO agents_store (hostname, last_seen, payload, command_queue) VALUES (?, ?, '{}', ?)", (hostname, int(time.time()), json.dumps(cmds)))
            conn.commit()
    except Exception as _:
        app.logger.exception("Database commit failed")

@app.route('/setup', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def setup():
    error = None
    with get_db() as conn:
        c = conn.cursor()
        c.execute("SELECT COUNT(*) FROM users")
        if c.fetchone()[0] > 0: return redirect(url_for('login'))
            
        if request.method == 'POST':
            username = request.form.get('username', '').strip()
            password = request.form.get('password', '')
            
            if not username or len(password) < 8: error = "Username required and password > 8 characters."
            else:
                c.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)", (username, generate_password_hash(password), 'admin'))
                conn.commit()
                audit_log(username, "system_setup", "system")
                session['user'] = username; session['role'] = 'admin'; session['csrf_token'] = secrets.token_hex(16)
                return redirect(url_for('dashboard'))
    return render_template('setup.html', error=error)

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("15 per minute")
def login():
    error = None
    with get_db() as conn:
        if conn.cursor().execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0:
            return redirect(url_for('setup'))

    if request.method == 'POST':
        ip = get_remote_address()
        if FAILED_LOGINS.get(ip, 0) >= 5:
            return render_template('login.html', error="IP locked out for 15 minutes due to too many failed attempts.")

        try:
            with get_db() as conn:
                c = conn.cursor()
                username = request.form.get('username', '')
                password = request.form.get('password', '')
                c.execute("SELECT password, role FROM users WHERE username=?", (username,))
                user = c.fetchone()
                if user:
                    db_pass = user[0] or ""
                    try: is_valid = check_password_hash(db_pass, password)
                    except Exception: is_valid = (db_pass == password)
                    
                    if is_valid:
                        FAILED_LOGINS.pop(ip, None) # Clear lockout
                        session['user'] = username; session['role'] = user[1]; session['csrf_token'] = secrets.token_hex(16)
                        c.execute("UPDATE users SET last_active=? WHERE username=?", (int(time.time()), username))
                        conn.commit()
                        audit_log(username, "login", "system")
                        return redirect(url_for('dashboard'))
                
                FAILED_LOGINS[ip] = FAILED_LOGINS.get(ip, 0) + 1
                error = "Invalid credentials"
                audit_log("unknown", "failed_login", ip)
        except Exception: error = "Database Error"
            
    return render_template('login.html', error=error)

@app.route('/logout')
def logout(): 
    audit_log(session.get('user', 'unknown'), "logout", "system")
    session.clear(); return redirect(url_for('login'))

@app.route('/')
def dashboard():
    if 'user' not in session: return redirect(url_for('login'))
    return render_template('dashboard.html', user=session['user'], role=session['role'], csrf_token=session.get('csrf_token'))

@app.route('/api/data', methods=['GET'])
def get_data():
    if 'user' not in session: return jsonify([]), 403
    safe_agents = []
    try:
        with get_db() as conn:
            c = conn.cursor()
            c.execute("SELECT hostname, last_seen, payload FROM agents_store ORDER BY hostname COLLATE NOCASE ASC")
            now = int(time.time())
            for row in c.fetchall():
                host, last_seen, payload_str = row
                try: agent = json.loads(payload_str)
                except Exception: agent = {}
                agent['hostname'] = host; agent['last_seen'] = last_seen; agent['status'] = 'ONLINE' if (now - last_seen) <= 120 else 'OFFLINE'
                agent['ip'] = extract_clean_string(agent.get('ip', ''))
                safe_agents.append(agent)
    except Exception as e:
        app.logger.error(f"Failed to process agent: {str(e)}")
    return jsonify(safe_agents)

@app.route('/api/reports', methods=['POST'])
@agent_hmac_required
@limiter.limit("60 per minute", key_func=agent_limit_key)
def receive_report():
    try:
        data = request.get_json(silent=True) or {}
        if request.verified_host != "UNKNOWN": update_agent_data(request.verified_host, data, is_full=True)
    except Exception as _:
        app.logger.exception("Failed to update agent data")
    return jsonify({"status": "success"})

@app.route('/api/heartbeat', methods=['POST'])
@agent_hmac_required
@limiter.limit("60 per minute", key_func=agent_limit_key)
def receive_heartbeat():
    try:
        data = request.get_json(silent=True) or {}
        host = request.verified_host
        if host != "UNKNOWN": 
            update_agent_data(host, data, is_full=False)
            with get_db() as conn:
                c = conn.cursor()
                c.execute("SELECT history_json FROM perf_history WHERE hostname=?", (host,))
                h_row = c.fetchone()
                hist = json.loads(h_row[0]) if h_row else []
                hist.append({"time": time.strftime("%H:%M:%S"), "cpu": data.get('cpu', 0), "ram": data.get('ram', 0)})
                if len(hist) > 20: hist.pop(0)
                c.execute("REPLACE INTO perf_history (hostname, history_json) VALUES (?, ?)", (host, json.dumps(hist)))
                conn.commit()
    except Exception as _:
        app.logger.exception("Database operation failed")
    return jsonify({"status": "success"}), 200

@app.route('/api/commands/get', methods=['POST'])
@agent_hmac_required
@limiter.limit("60 per minute", key_func=agent_limit_key)
def get_commands():
    try:
        host = request.verified_host
        if host == "UNKNOWN": return jsonify({"commands": []})
        with get_db() as conn:
            c = conn.cursor()
            c.execute("SELECT command_queue FROM agents_store WHERE hostname=?", (host,))
            row = c.fetchone(); cmds = []; now = int(time.time())
            if row:
                try: cmds = json.loads(row[0])
                except Exception as e:
                    app.logger.error(f"Invalid JSON in command_queue: {str(e)}")
                    cmds = []
                if cmds: c.execute("UPDATE agents_store SET command_queue='[]', last_seen=? WHERE hostname=?", (now, host))
                else: c.execute("UPDATE agents_store SET last_seen=? WHERE hostname=?", (now, host))
            else: c.execute("INSERT INTO agents_store (hostname, last_seen, payload, command_queue) VALUES (?, ?, '{}', '[]')", (host, now))
            conn.commit()
            return jsonify({"commands": cmds})
    except Exception: return jsonify({"commands": []})

@app.route('/api/screen/upload', methods=['POST'])
@agent_hmac_required
@limiter.limit("60 per minute", key_func=agent_limit_key)
def upload_screen():
    try:
        data = request.get_json(silent=True) or {}
        host = request.verified_host
        img = data.get('image', '')

        if len(img) > 15_000_000:
            return jsonify({"error": "Payload too large"}), 400

        if host != "UNKNOWN" and img:
            val = str(img).strip()
            if ',' in val:
                val = val.split(',', 1)[1]

            try:
                img_data = base64.b64decode(val)
                filepath = os.path.join('data/screens', f"{host}.jpg")
                temp_filepath = os.path.join('data/screens', f"{host}_tmp.jpg")

                with open(temp_filepath, 'wb') as f:
                    f.write(img_data)

                os.replace(temp_filepath, filepath)

            except Exception as _:
                return jsonify({"error": "Image processing failed"}), 400

        return jsonify({"status": "success"})

    except Exception:
        return jsonify({"status": "error"}), 200

@app.route('/api/terminal/agent_poll', methods=['POST'])
@agent_hmac_required
def term_agent_poll():
    try:
        host = request.verified_host
        cmd = ""
        with get_db() as conn:
            c = conn.cursor()
            c.execute("SELECT cmd FROM terminal_store WHERE hostname=?", (host,))
            row = c.fetchone()
            if row and row[0]:
                cmd = row[0]; c.execute("UPDATE terminal_store SET cmd=NULL WHERE hostname=?", (host,)); conn.commit()
            return jsonify({"command": cmd})
    except Exception: return jsonify({"command": ""}), 200

@app.route('/api/terminal/agent_push', methods=['POST'])
@agent_hmac_required
def term_agent_push():
    try:
        data = request.get_json(silent=True) or {}
        host = request.verified_host
        out = data.get('output', '')
        with get_db() as conn:
            c = conn.cursor()
            c.execute("SELECT output FROM terminal_store WHERE hostname=?", (host,))
            row = c.fetchone(); current_out = row[0] if (row and row[0]) else ""
            new_out = (current_out + out + "\n")[-10000:]
            if row: c.execute("UPDATE terminal_store SET output=? WHERE hostname=?", (new_out, host))
            else: c.execute("INSERT INTO terminal_store (hostname, cmd, output) VALUES (?, NULL, ?)", (host, new_out))
            conn.commit()
    except Exception as _:
         app.logger.exception("Database commit failed")
    return jsonify({"status": "saved"})

@app.route('/api/explorer/update', methods=['POST'])
@agent_hmac_required
def explorer_push():
    try:
        data = request.get_json(silent=True) or {}
        host = request.verified_host
        result = data.get('result', '')
        with get_db() as conn:
            c = conn.cursor()
            c.execute("SELECT hostname FROM explorer_store WHERE hostname=?", (host,))
            if c.fetchone(): c.execute("UPDATE explorer_store SET result=? WHERE hostname=?", (result, host))
            else: c.execute("INSERT INTO explorer_store (hostname, path, result) VALUES (?, '', ?)", (host, result))
            conn.commit()
    except Exception as _:
         app.logger.exception("Database commit failed")
    return jsonify({"status": "saved"})

@app.route('/api/services/update', methods=['POST'])
@agent_hmac_required
def services_push():
    try:
        data = request.get_json(silent=True) or {}
        host = request.verified_host
        result = data.get('result', '')
        with get_db() as conn:
            c = conn.cursor()
            c.execute("SELECT hostname FROM services_store WHERE hostname=?", (host,))
            if c.fetchone(): c.execute("UPDATE services_store SET result=? WHERE hostname=?", (result, host))
            else: c.execute("INSERT INTO services_store (hostname, result) VALUES (?, ?)", (host, result))
            conn.commit()
    except Exception as _:
         app.logger.exception("Database commit failed")
    return jsonify({"status": "saved"})

@app.route('/api/eventlog/update', methods=['POST'])
@agent_hmac_required
def eventlog_push():
    try:
        data = request.get_json(silent=True) or {}
        host = request.verified_host
        result = data.get('result', '')
        with get_db() as conn:
            c = conn.cursor()
            c.execute("SELECT hostname FROM eventlog_store WHERE hostname=?", (host,))
            if c.fetchone(): c.execute("UPDATE eventlog_store SET result=? WHERE hostname=?", (result, host))
            else: c.execute("INSERT INTO eventlog_store (hostname, result) VALUES (?, ?)", (host, result))
            conn.commit()
    except Exception as _:
         app.logger.exception("Database commit failed")
    return jsonify({"status": "saved"})

@app.route('/api/scripts/log', methods=['POST'])
@agent_hmac_required
def log_script():
    try:
        data = request.get_json(silent=True) or {}
        host = request.verified_host
        script_id = data.get('script_id'); output = data.get('output', '')
        with get_db() as conn:
            c = conn.cursor()
            c.execute("SELECT name FROM scripts_store WHERE id=?", (script_id,))
            s_row = c.fetchone(); s_name = s_row[0] if s_row else "Unknown Script"
            c.execute("INSERT INTO script_logs (script_id, script_name, hostname, output) VALUES (?, ?, ?, ?)", (script_id, s_name, host, output))
            conn.commit()
            return jsonify({"status": "success"})
    except Exception as e: return jsonify({"error": f"DB Error: {e}"}), 500

@app.route('/api/processes/update', methods=['POST'])
@agent_hmac_required
def update_processes():
    try:
        data = request.get_json(silent=True) or {}
        host = request.verified_host
        result = data.get('result', '')
        with get_db() as conn:
            c = conn.cursor()
            c.execute("SELECT hostname FROM processes_store WHERE hostname=?", (host,))
            if c.fetchone(): c.execute("UPDATE processes_store SET result=? WHERE hostname=?", (result, host))
            else: c.execute("INSERT INTO processes_store (hostname, result) VALUES (?, ?)", (host, result))
            conn.commit()
    except Exception as _:
         app.logger.exception("Database commit failed")
    return jsonify({"status": "saved"})

@app.route('/api/tickets/create', methods=['POST'])
@agent_hmac_required
def create_ticket():
    try:
        data = request.get_json(silent=True) or {}
        host = request.verified_host
        severity = data.get('severity', 'Info'); message = data.get('message', '')
        if host != "UNKNOWN" and message:
            with get_db() as conn:
                c = conn.cursor()
                c.execute("INSERT INTO tickets (hostname, severity, message, status) VALUES (?, ?, ?, 'Open')", (host, severity, message))
                conn.commit()
    except Exception as _:
         app.logger.exception("Database commit failed")
         return jsonify({"error": "Operation failed"}), 500
    return jsonify({"status": "success"})

# 🔐 7. COMMAND POLICY ENGINE (RBAC)
ROLE_PERMISSIONS = {
    "viewer": [],
    "helpdesk": ["ping", "ipconfig", "systeminfo", "netstat", "tasklist", "get-process", "get-service", "get-eventlog", "restart", "explore:", "get_services", "get_eventlogs", "get_processes", "capture_screen", "start_stream"],
    "manager": ["deploy:", "run_saved_script:", "kill_process:", "service_restart:", "service_start:", "service_stop:", "uninstall:", "install_updates:"],
    "admin": ["*"]
}

@app.route('/api/commands/queue', methods=['POST'])
@csrf_required
@limiter.limit("30 per minute")
def queue_command():
    role = session.get('role', 'viewer')
    if role == 'viewer': return jsonify({"error": "Unauthorized"}), 403
    try:
        data = request.get_json(silent=True) or {}
        host = get_host_from_data(data)
        cmd = data.get('command')
        
        if not isinstance(cmd, str) or len(cmd) > 500: return jsonify({"error": "Invalid command"}), 400
        cmd = cmd.strip()

        if host != "UNKNOWN" and cmd:
            base_cmd = cmd.split(':')[0]
            if not base_cmd.endswith(':'): base_cmd += ':' if ':' in cmd else ''
            
            allowed = False
            if role == 'admin': allowed = True
            elif role == 'manager':
                allowed = base_cmd in ROLE_PERMISSIONS['manager'] or base_cmd.replace(':', '') in ROLE_PERMISSIONS['helpdesk'] or base_cmd in ROLE_PERMISSIONS['helpdesk']
            elif role == 'helpdesk':
                allowed = base_cmd in ROLE_PERMISSIONS['helpdesk'] or base_cmd.replace(':', '') in ROLE_PERMISSIONS['helpdesk']

            if not allowed:
                audit_log(session.get('user'), f"blocked_command_{base_cmd}", host)
                return jsonify({"error": "Insufficient permissions for this command."}), 403
            
            queue_cmd(host, cmd)
            audit_log(session.get('user'), f"queued_command_{base_cmd}", host)
        return jsonify({"status": "queued"})
    except Exception as _: return jsonify({"status": "error"}), 500

@app.route('/api/settings', methods=['GET', 'POST'])
@csrf_required
def handle_settings():
    if session.get('role') != 'admin': return jsonify({"error": "Unauthorized"}), 403
    try:
        with get_db() as conn:
            c = conn.cursor()
            if request.method == 'POST':
                data = request.get_json(silent=True) or {}
                raw_pass = data.get('smtp_pass', '')
                enc_pass = cipher_suite.encrypt(raw_pass.encode()).decode() if raw_pass else ''
                c.execute("UPDATE settings SET cpu_alert=?, ram_alert=?, disk_alert=?, offline_alert=?, email_to=?, smtp_server=?, smtp_user=?, smtp_pass=? WHERE id=1", 
                          (data.get('cpu_alert'), data.get('ram_alert'), data.get('disk_alert'), data.get('offline_alert'), data.get('email_to'), data.get('smtp_server'), data.get('smtp_user'), enc_pass))
                conn.commit()
                audit_log(session.get('user'), "updated_settings", "system")
                return jsonify({"status": "success"})
            else:
                c.execute("SELECT cpu_alert, ram_alert, disk_alert, offline_alert, email_to, smtp_server, smtp_user FROM settings WHERE id=1")
                r = c.fetchone()
                if r: return jsonify({"cpu_alert": r[0], "ram_alert": r[1], "disk_alert": r[2], "offline_alert": r[3], "email_to": r[4], "smtp_server": r[5], "smtp_user": r[6]})
                return jsonify({})
    except Exception as e: return jsonify({"error": str(e)}), 500
    
    # ✅ FIX: Added the missing route to fetch script execution logs for the dashboard
@app.route('/api/scripts/logs', methods=['GET'])
def get_script_logs():
    if 'role' not in session: return jsonify([])
    try:
        with get_db() as conn:
            c = conn.cursor()
            c.execute("SELECT script_id, script_name, hostname, output, executed_at FROM script_logs ORDER BY id DESC LIMIT 100")
            logs = [{"script_id": r[0], "script_name": r[1], "hostname": r[2], "output": r[3], "executed_at": r[4]} for r in c.fetchall()]
            return jsonify(logs)
    except Exception: return jsonify([])

@app.route('/api/scripts/list', methods=['GET'])
def list_scripts():
    if 'role' not in session: return jsonify([])
    try:
        with get_db() as conn:
            c = conn.cursor()
            c.execute("SELECT id, name, description, code, created_by, created_at FROM scripts_store ORDER BY id DESC")
            scripts = [{"id": r[0], "name": r[1], "description": r[2], "code": r[3], "created_by": r[4], "created_at": r[5]} for r in c.fetchall()]
            return jsonify(scripts)
    except Exception: return jsonify([])

@app.route('/api/scripts/add', methods=['POST'])
@csrf_required
def add_script():
    if session.get('role') not in ['admin', 'manager']: return jsonify({"error": "Unauthorized"}), 403
    data = request.get_json(silent=True) or {}
    if not data.get('name') or not data.get('code'): return jsonify({"error": "Missing parameters"}), 400
    try:
        with get_db() as conn:
            c = conn.cursor()
            c.execute("INSERT INTO scripts_store (name, description, code, created_by) VALUES (?, ?, ?, ?)", (data.get('name'), data.get('description', ''), data.get('code'), session['user']))
            conn.commit()
            audit_log(session.get('user'), f"added_script", data.get('name'))
            return jsonify({"status": "success"})
    except Exception as e: return jsonify({"error": str(e)}), 500

@app.route('/api/scripts/delete', methods=['POST'])
@csrf_required
def delete_script():
    if session.get('role') not in ['admin', 'manager']: return jsonify({"error": "Unauthorized"}), 403
    try:
        data = request.get_json(silent=True) or {}
        script_id = data.get('id')
        with get_db() as conn:
            c = conn.cursor()
            c.execute("DELETE FROM scripts_store WHERE id=?", (script_id,))
            c.execute("DELETE FROM script_logs WHERE script_id=?", (script_id,))
            conn.commit()
            audit_log(session.get('user'), f"deleted_script_id", str(script_id))
            return jsonify({"status": "success"})
    except Exception as e: return jsonify({"error": str(e)}), 500

@app.route('/api/scripts/run', methods=['POST'])
@csrf_required
def run_script():
    if session.get('role') not in ['admin', 'manager']: return jsonify({"error": "Unauthorized"}), 403
    data = request.get_json(silent=True) or {}
    if not data.get('script_id') or not data.get('hosts', []): return jsonify({"error": "Missing parameters"}), 400
    try:
        with get_db() as conn:
            c = conn.cursor()
            c.execute("SELECT code FROM scripts_store WHERE id=?", (data.get('script_id'),))
            row = c.fetchone()
            if not row: return jsonify({"error": "Script not found"}), 404
            cmd = f"run_saved_script:{data.get('script_id')}:{base64.b64encode(row[0].encode('utf-8')).decode('utf-8')}"
            for h in data.get('hosts', []): queue_cmd(get_clean_host(h), cmd)
            audit_log(session.get('user'), f"ran_script_id_{data.get('script_id')}", f"hosts_count_{len(data.get('hosts', []))}")
            return jsonify({"status": "success", "queued": len(data.get('hosts', []))})
    except Exception as e: return jsonify({"error": str(e)}), 500

@app.route('/api/services/request', methods=['POST'])
@csrf_required
def services_req():
    if 'role' not in session or session['role'] == 'viewer': return jsonify({"error": "Unauthorized"}), 403
    try:
        data = request.get_json(silent=True) or {}
        host = get_clean_host(data.get('hostname')); queue_cmd(host, "get_services")
        with get_db() as conn:
            c = conn.cursor()
            c.execute("SELECT hostname FROM services_store WHERE hostname=?", (host,))
            if c.fetchone(): c.execute("UPDATE services_store SET result='' WHERE hostname=?", (host,))
            else: c.execute("INSERT INTO services_store (hostname, result) VALUES (?, '')", (host,))
            conn.commit()
    except Exception as _:
        app.logger.exception("Database commit failed")
    return jsonify({"status": "sent"})

@app.route('/api/services/read', methods=['GET'])
def services_read():
    out = ""
    try:
        with get_db() as conn:
            c = conn.cursor()
            c.execute("SELECT result FROM services_store WHERE hostname=?", (get_clean_host(request.args.get('hostname')),))
            row = c.fetchone(); out = row[0] if row and row[0] else ""
    except Exception as e:
        app.logger.error(f"Failed to fetch result: {str(e)}")
    return jsonify({"result": out})

@app.route('/api/explorer/request', methods=['POST'])
@csrf_required
def explorer_req():
    if 'role' not in session or session['role'] == 'viewer': return jsonify({"error": "Unauthorized"}), 403
    try:
        data = request.get_json(silent=True) or {}
        host = get_clean_host(data.get('hostname')); path = data.get('path', 'C:\\')
        queue_cmd(host, f"explore:{path}")
        with get_db() as conn:
            c = conn.cursor()
            c.execute("SELECT hostname FROM explorer_store WHERE hostname=?", (host,))
            if c.fetchone(): c.execute("UPDATE explorer_store SET path=?, result='' WHERE hostname=?", (path, host))
            else: c.execute("INSERT INTO explorer_store (hostname, path, result) VALUES (?, ?, '')", (host, path))
            conn.commit()
    except Exception as _:
        app.logger.exception("Database commit failed")
    return jsonify({"status": "sent"})

@app.route('/api/explorer/read', methods=['GET'])
def explorer_read():
    out = ""
    try:
        with get_db() as conn:
            c = conn.cursor()
            c.execute("SELECT result FROM explorer_store WHERE hostname=?", (get_clean_host(request.args.get('hostname')),))
            row = c.fetchone(); out = row[0] if row and row[0] else ""
    except Exception as _:
        app.logger.exception("Database fetch failed")  # Logs the full traceback
    return jsonify({"result": out})

@app.route('/api/eventlog/request', methods=['POST'])
@csrf_required
def eventlog_req():
    if 'role' not in session or session['role'] == 'viewer': return jsonify({"error": "Unauthorized"}), 403
    try:
        data = request.get_json(silent=True) or {}
        host = get_clean_host(data.get('hostname')); queue_cmd(host, "get_eventlogs")
        with get_db() as conn:
            c = conn.cursor()
            c.execute("SELECT hostname FROM eventlog_store WHERE hostname=?", (host,))
            if c.fetchone(): c.execute("UPDATE eventlog_store SET result='' WHERE hostname=?", (host,))
            else: c.execute("INSERT INTO eventlog_store (hostname, result) VALUES (?, '')", (host,))
            conn.commit()
    except Exception as _:
        app.logger.exception("Database commit failed")
    return jsonify({"status": "sent"})

@app.route('/api/eventlog/read', methods=['GET'])
def eventlog_read():
    out = ""
    try:
        with get_db() as conn:
            c = conn.cursor()
            c.execute("SELECT result FROM eventlog_store WHERE hostname=?", (get_clean_host(request.args.get('hostname')),))
            row = c.fetchone(); out = row[0] if row and row[0] else ""
    except Exception as _:
        app.logger.exception("Database fetch failed")
    return jsonify({"result": out})

@app.route('/api/files/upload', methods=['POST'])
@csrf_required
def upload_deploy_file():
    if session.get('role') not in ['admin', 'manager']: return jsonify({"error": "Unauthorized"}), 403
    if 'file' not in request.files or request.files['file'].filename == '': return jsonify({"error": "Empty filename"}), 400
    
    f = request.files['file']; filename = secure_filename(f.filename)
    SAFE_UPLOADS = [".txt", ".log", ".json", ".jpg", ".png"]; DEPLOY_UPLOADS = [".exe", ".msi"]
    ext = os.path.splitext(filename)[1].lower()
    
    if ext in DEPLOY_UPLOADS and session.get('role') != 'admin': return jsonify({"error": "Admin clearance required for executables."}), 403
    elif ext not in SAFE_UPLOADS and ext not in DEPLOY_UPLOADS: return jsonify({"error": "Invalid file type."}), 400
        
    f.save(os.path.join('data/uploads', f"{int(time.time())}_{filename}"))
    audit_log(session.get('user'), "uploaded_file", filename)
    return jsonify({"status": "success"})

@app.route('/api/files/list', methods=['GET'])
def list_deploy_files():
    if 'role' not in session: return jsonify([])
    files = []
    try:
        for f in os.listdir('data/uploads'):
            filepath = os.path.join('data/uploads', f)
            if os.path.isfile(filepath): files.append({"name": f, "size": os.path.getsize(filepath)})
    except Exception as _:
        app.logger.exception("File access failed")
    return jsonify(files)

@app.route('/api/files/delete', methods=['POST'])
@csrf_required
def delete_deploy_file():
    if session.get('role') not in ['admin', 'manager']: return jsonify({"error": "Unauthorized"}), 403
    try: 
        data = request.get_json(silent=True) or {}
        filename = secure_filename(data.get('name', ''))
        os.remove(os.path.join('data/uploads', filename))
        audit_log(session.get('user'), "deleted_file", filename)
    except Exception as _:
        app.logger.exception("Audit log failed for file deletion")
    return jsonify({"status": "success"})

@app.route('/api/transfer/get/<filename>', methods=['GET'])
@agent_hmac_required
def download_deploy_file(filename):
    return send_from_directory('data/uploads', secure_filename(filename))

@app.route('/api/deploy/bulk', methods=['POST'])
@csrf_required
def bulk_deploy():
    if session.get('role') not in ['admin', 'manager']: return jsonify({"error": "Unauthorized"}), 403
    data = request.get_json(silent=True) or {}
    if not data.get('hosts', []) or not data.get('filename', ''): return jsonify({"error": "Missing parameters"}), 400
    
    target_file = os.path.join('data/uploads', secure_filename(data.get('filename', '')))
    file_hash = ""
    
    if os.path.exists(target_file):
        h = hashlib.sha256()
        with open(target_file, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""): h.update(chunk)
        file_hash = h.hexdigest()

    cmd = f"deploy:{data.get('filename')}:::{data.get('args', '')}:::{file_hash}"
    for h in data.get('hosts'): queue_cmd(get_clean_host(h), cmd)
    audit_log(session.get('user'), f"bulk_deployed_{data.get('filename')}", f"hosts_count_{len(data.get('hosts'))}")
    return jsonify({"status": "success", "queued": len(data.get('hosts'))})

@app.route('/api/terminal/execute', methods=['POST'])
@csrf_required
def term_exec():
    if 'role' not in session or session['role'] in ['viewer', 'helpdesk']: return jsonify({"error": "Unauthorized"}), 403
    try:
        data = request.get_json(silent=True) or {}
        host = get_clean_host(data.get('hostname'))
        cmd_type = str(data.get('command', '')).strip()
        
        base_cmd = cmd_type.split(' ')[0].lower()
        allowed_cmds = ["ping", "ipconfig", "systeminfo", "netstat", "tracert", "tasklist", "nslookup", "get-service", "get-process", "get-eventlog", "dir", "whoami", "echo", "cd"]
        
        # ✅ FIX: Admins bypass the strict command filter. Others get blocked.
        if session.get('role') != 'admin' and base_cmd not in allowed_cmds: 
            return jsonify({"error": "Command not permitted by security policy."}), 403

        with get_db() as conn:
            c = conn.cursor()
            c.execute("SELECT hostname FROM terminal_store WHERE hostname=?", (host,))
            if c.fetchone(): c.execute("UPDATE terminal_store SET cmd=? WHERE hostname=?", (cmd_type, host))
            else: c.execute("INSERT INTO terminal_store (hostname, cmd, output) VALUES (?, ?, '')", (host, cmd_type))
            conn.commit()
            audit_log(session.get('user'), f"terminal_execute_{base_cmd}", host)
    except Exception as _:
        app.logger.exception(f"Audit log failed for command: {base_cmd} on host: {host}")
    return jsonify({"status": "sent"})

@app.route('/api/terminal/read', methods=['GET'])
def term_read():
    out = ""
    try:
        host = get_clean_host(request.args.get('hostname'))
        with get_db() as conn:
            c = conn.cursor()
            c.execute("SELECT output FROM terminal_store WHERE hostname=?", (host,))
            row = c.fetchone()
            if row and row[0]:
                out = row[0]; c.execute("UPDATE terminal_store SET output='' WHERE hostname=?", (host,)); conn.commit()
    except Exception as _:
        app.logger.exception(f"Failed to process terminal_store update for host: {host}")
    return jsonify({"output": out})

@app.route('/api/screen/get/<hostname>', methods=['GET'])
def get_screen(hostname):
    if 'user' not in session: return jsonify({"error": "Unauthorized"}), 403
    host = get_clean_host(hostname)
    filepath = os.path.join('data/screens', f"{host}.jpg")
    
    try:
        if not os.path.exists(filepath): return "", 204
        response = send_from_directory(directory=os.path.abspath('data/screens'), path=f"{host}.jpg", mimetype='image/jpeg')
        response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, post-check=0, pre-check=0, max-age=0'
        return response
    except Exception: return jsonify({"error": "Internal Server Error"}), 500

@app.route('/api/screen/clear/<hostname>', methods=['POST'])
@csrf_required
def clear_screen(hostname):
    if 'user' not in session: return "Unauthorized", 403
    try:
        filepath = os.path.join('data/screens', f"{get_clean_host(hostname)}.jpg")
        if os.path.exists(filepath): os.remove(filepath)
    except Exception as _:
        app.logger.exception(f"Failed to delete file: {filepath}")
    return jsonify({"status": "success"})

@app.route('/api/agents/revive-all', methods=['POST'])
@csrf_required
def revive_all_agents():
    if 'role' not in session or session['role'] == 'viewer': return jsonify({"error": "Unauthorized"}), 403
    try:
        with get_db() as conn:
            c = conn.cursor(); c.execute("SELECT hostname FROM agents_store")
            count = 0
            for row in c.fetchall(): queue_cmd(row[0], "trigger_full_sync"); count += 1
            audit_log(session.get('user'), "revived_all_agents", "system")
            return jsonify({"status": "revival_queued", "agents_revived": count})
    except Exception as e: return jsonify({"error": f"DB Error: {e}"}), 500

@app.route('/api/commands/force-sync/<hostname>', methods=['POST'])
@csrf_required
def force_sync_agent(hostname):
    if 'role' not in session or session['role'] == 'viewer': return jsonify({"error": "Unauthorized"}), 403
    host = get_clean_host(hostname); queue_cmd(host, "trigger_full_sync")
    return jsonify({"status": "sync_requested", "hostname": host})

@app.route('/api/history/<hostname>', methods=['GET'])
def get_history(hostname):
    try:
        with get_db() as conn:
            c = conn.cursor()
            c.execute("SELECT history_json FROM perf_history WHERE hostname=?", (get_clean_host(hostname),))
            row = c.fetchone()
            return jsonify(json.loads(row[0]) if row else [])
    except Exception: return jsonify([])

@app.route('/api/agents/delete', methods=['POST'])
@csrf_required
def delete_agent():
    if 'role' not in session or session['role'] != 'admin': return jsonify({"error": "Unauthorized"}), 403
    data = request.get_json(silent=True) or {}
    host = get_clean_host(data.get('hostname'))
    if host == "UNKNOWN": return jsonify({"error": "Invalid host"}), 400
    try:
        with get_db() as conn:
            c = conn.cursor()
            c.execute("DELETE FROM agents_store WHERE hostname=?", (host,))
            c.execute("DELETE FROM perf_history WHERE hostname=?", (host,))
            c.execute("DELETE FROM terminal_store WHERE hostname=?", (host,))
            c.execute("DELETE FROM explorer_store WHERE hostname=?", (host,))
            c.execute("DELETE FROM services_store WHERE hostname=?", (host,))
            c.execute("DELETE FROM eventlog_store WHERE hostname=?", (host,))
            c.execute("DELETE FROM agents_auth WHERE hostname=?", (host,))
            conn.commit()
            if host in AGENT_CACHE: del AGENT_CACHE[host]
            filepath = os.path.join('data/screens', f"{host}.jpg")
            if os.path.exists(filepath): os.remove(filepath)
            audit_log(session.get('user'), "deleted_agent", host)
            return jsonify({"status": "success"})
    except Exception as e: return jsonify({"error": f"DB Error: {e}"}), 500

@app.route('/api/processes/get/<hostname>', methods=['GET'])
def get_processes(hostname):
    out = []
    try:
        with get_db() as conn:
            c = conn.cursor()
            c.execute("SELECT result FROM processes_store WHERE hostname=?", (get_clean_host(hostname),))
            row = c.fetchone()
            if row and row[0]: 
                out = json.loads(base64.b64decode(row[0]).decode('utf-8'))
                c.execute("UPDATE processes_store SET result='' WHERE hostname=?", (get_clean_host(hostname),))
                conn.commit()
    except Exception as _:
        app.logger.exception("Database commit failed")
    return jsonify(out)

@app.route('/api/users/list', methods=['GET'])
def list_users():
    if 'role' not in session or session['role'] != 'admin': return jsonify([]), 403
    try:
        with get_db() as conn:
            c = conn.cursor(); c.execute("SELECT username, role, last_active FROM users")
            users = [{"username": r[0], "role": r[1], "last_active": r[2]} for r in c.fetchall()]
            return jsonify(users)
    except Exception: return jsonify([])

@app.route('/api/users/add', methods=['POST'])
@csrf_required
def add_user():
    if session.get('role') != 'admin': return jsonify({"error": "Unauthorized"}), 403
    try:
        data = request.get_json(silent=True) or {}
        username, password, role = str(data.get('username', '')).strip(), str(data.get('password', '')), str(data.get('role', 'viewer')).strip()
        if not username or len(password) < 8: return jsonify({"error": "Missing/invalid fields"}), 400

        with get_db() as conn:
            c = conn.cursor()
            c.execute("SELECT username FROM users WHERE username=?", (username,))
            if c.fetchone(): return jsonify({"error": f"User '{username}' exists."}), 400
            c.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)", (username, generate_password_hash(password), role))
            conn.commit()
            audit_log(session.get('user'), "added_user", username)
            return jsonify({"status": "success"})
    except Exception as e: return jsonify({"error": str(e)}), 500

@app.route('/api/users/delete', methods=['POST'])
@csrf_required
def delete_user():
    if session.get('role') != 'admin': return jsonify({"error": "Unauthorized"}), 403
    try:
        data = request.get_json(silent=True) or {}
        username = str(data.get('username', '')).strip()
        if username == 'admin': return jsonify({"error": "Cannot delete admin"}), 400
        with get_db() as conn:
            c = conn.cursor()
            c.execute("DELETE FROM users WHERE username=?", (username,)); conn.commit()
            audit_log(session.get('user'), "deleted_user", username)
            return jsonify({"status": "success"})
    except Exception as e: return jsonify({"error": str(e)}), 500

@app.route('/api/users/change_password', methods=['POST'])
@csrf_required
def change_password():
    if session.get('role') != 'admin': return jsonify({"error": "Unauthorized"}), 403
    try:
        data = request.get_json(silent=True) or {}
        username, password = str(data.get('username', '')).strip(), str(data.get('password', ''))
        if not username or len(password) < 8: return jsonify({"error": "Missing/invalid fields"}), 400

        with get_db() as conn:
            c = conn.cursor()
            c.execute("UPDATE users SET password=? WHERE username=?", (generate_password_hash(password), username))
            conn.commit()
            audit_log(session.get('user'), "changed_password", username)
            return jsonify({"status": "success"})
    except Exception as e: return jsonify({"error": str(e)}), 500

@app.route('/api/tickets', methods=['GET'])
def get_tickets():
    try:
        with get_db() as conn:
            c = conn.cursor()
            c.execute("SELECT id, hostname, severity, message, status, created_at FROM tickets ORDER BY id DESC LIMIT 50")
            t = [{"id": r[0], "hostname": r[1], "severity": r[2], "message": r[3], "status": r[4], "created_at": r[5]} for r in c.fetchall()]
            return jsonify(t)
    except Exception: return jsonify([])

@app.route('/api/tickets/close', methods=['POST'])
@csrf_required
def close_ticket():
    if 'role' not in session or session['role'] == 'viewer': return jsonify({"error": "Unauthorized"}), 403
    try:
        data = request.get_json(silent=True) or {}
        ticket_id = data.get('id')
        with get_db() as conn:
            c = conn.cursor()
            c.execute("UPDATE tickets SET status='Resolved' WHERE id=?", (ticket_id,))
            conn.commit()
            audit_log(session.get('user'), "closed_ticket", str(ticket_id))
            return jsonify({"status": "success"})
    except Exception as e: return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080)