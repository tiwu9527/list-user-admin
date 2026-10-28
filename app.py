#!/usr/bin/env python3
import os, json, html, sqlite3, secrets, string, urllib.request, urllib.error, http.cookies, hashlib, hmac, threading, time, re
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs, urlsplit
from datetime import datetime, timedelta

BASE = os.path.dirname(os.path.abspath(__file__))
DB = os.path.join(BASE, 'data.db')
HOST = os.environ.get('OPENLIST_ADMIN_HOST', '0.0.0.0')
PORT = int(os.environ.get('OPENLIST_ADMIN_PORT', '19100'))
INVITE_HOST = os.environ.get('OPENLIST_INVITE_HOST', 'in.tiwunb.xyz').lower()
LOCAL_ADMIN_TOKEN = os.environ.get('OPENLIST_ADMIN_TOKEN') or secrets.token_urlsafe(32)
SESSIONS = set()
DB_LOCK = threading.RLock()
REGISTER_LOCK = threading.Lock()


def db():
    # SQLite 只能单写入；所有后台写请求由 do_POST 串行化，健康检查不受业务请求阻塞。
    c = sqlite3.connect(DB, timeout=10, check_same_thread=False)
    c.row_factory = sqlite3.Row
    c.execute('PRAGMA busy_timeout=10000')
    c.execute('PRAGMA journal_mode=WAL')
    c.execute('PRAGMA synchronous=NORMAL')
    with DB_LOCK:
        c.execute('''CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL)''')
    c.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT, openlist_id INTEGER, username TEXT UNIQUE NOT NULL,
        base_path TEXT NOT NULL, disabled INTEGER NOT NULL DEFAULT 0,
        plan TEXT NOT NULL DEFAULT 'custom', expires_at TEXT, created TEXT NOT NULL, updated TEXT NOT NULL)''')
    cols = {r['name'] for r in c.execute('PRAGMA table_info(users)').fetchall()}
    if 'plan' not in cols: c.execute("ALTER TABLE users ADD COLUMN plan TEXT NOT NULL DEFAULT 'custom'")
    if 'expires_at' not in cols: c.execute('ALTER TABLE users ADD COLUMN expires_at TEXT')
    c.execute('CREATE INDEX IF NOT EXISTS idx_users_expiry ON users(disabled, expires_at)')
    c.execute('''CREATE TABLE IF NOT EXISTS invites (
        id INTEGER PRIMARY KEY AUTOINCREMENT, code TEXT UNIQUE NOT NULL,
        plan TEXT NOT NULL, uses INTEGER NOT NULL DEFAULT 0,
        max_uses INTEGER NOT NULL DEFAULT 1, expires_at TEXT,
        created TEXT NOT NULL, used_at TEXT, registered_username TEXT)''')
    cols = {r['name'] for r in c.execute('PRAGMA table_info(invites)').fetchall()}
    if 'used_at' not in cols: c.execute("ALTER TABLE invites ADD COLUMN used_at TEXT")
    if 'registered_username' not in cols: c.execute("ALTER TABLE invites ADD COLUMN registered_username TEXT")
    if 'archived' not in cols: c.execute("ALTER TABLE invites ADD COLUMN archived INTEGER NOT NULL DEFAULT 0")
    if 'exported' not in cols: c.execute("ALTER TABLE invites ADD COLUMN exported INTEGER NOT NULL DEFAULT 0")
    if 'exported_at' not in cols: c.execute("ALTER TABLE invites ADD COLUMN exported_at TEXT")
    # 已使用链接保留在历史归档中，避免删除后无法追溯来源和对账。
    c.commit()
    return c


def esc(v): return html.escape(str(v or ''))
def now(): return datetime.now().strftime('%Y-%m-%d %H:%M:%S')
def expired(expires_at): return bool(expires_at and expires_at <= now())
PLAN_LABELS={'day':'天卡','week':'周卡','month':'月卡','quarter':'季卡','halfyear':'半年','year':'年卡'}
PLAN_DAYS={'day':1,'week':7,'month':30,'quarter':90,'halfyear':180,'year':365}
def plan_for_duration_days(days):
    # 按续费后的总有效期，显示已达到的最高套餐档位。
    if days >= 365: return 'year'
    if days >= 180: return 'halfyear'
    if days >= 90: return 'quarter'
    if days >= 30: return 'month'
    if days >= 7: return 'week'
    return 'day'
def plan_expiry(plan, start=None):
    if plan not in PLAN_DAYS: raise RuntimeError('套餐类型无效')
    return ((start or datetime.now()) + timedelta(days=PLAN_DAYS[plan])).strftime('%Y-%m-%d %H:%M:%S')
def invalid_username(username):
    return not bool(re.fullmatch(r'[a-z0-9]{4,8}', (username or '').strip()))
def forbidden_username(username):
    value=(username or '').strip().casefold()
    if not value: return False
    keywords=('admin','administrator','manager','root','superuser','moderator','管理员','管理','超级用户')
    if any(k in value for k in keywords): return True
    configured=(setting('local_user',''), setting('openlist_user',''))
    return any(v and v.casefold() in value for v in configured)

def expire_users_once():
    # Snapshot eligible IDs under the lock; never hold DB_LOCK during remote API calls.
    with DB_LOCK:
        c=db()
        try:
            rows=c.execute("SELECT id,username,openlist_id FROM users WHERE expires_at IS NOT NULL AND expires_at <= ? AND openlist_id IS NOT NULL ORDER BY expires_at LIMIT 100", (now(),)).fetchall()
            pending=[dict(r) for r in rows]
        finally:
            c.close()
    for r in pending:
        try:
            api('POST',f"/api/admin/user/delete?id={r['openlist_id']}")
        except Exception:
            continue
        # Only update local mapping after remote deletion succeeds.
        with DB_LOCK:
            c=db()
            try:
                c.execute('UPDATE users SET openlist_id=NULL,disabled=1,updated=? WHERE id=? AND openlist_id=?',(now(),r['id'],r['openlist_id']))
                c.commit()
            finally:
                c.close()

def expiry_worker():
    while True:
        try: expire_users_once()
        except Exception: pass
        time.sleep(300)
def setting(key, default=''):
    c = db()
    try:
        row = c.execute('SELECT value FROM settings WHERE key=?', (key,)).fetchone()
        return row['value'] if row else default
    finally:
        c.close()

def save_setting(key, value):
    c = db()
    try:
        c.execute('INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value', (key, value)); c.commit()
    finally:
        c.close()

def local_hash(value, salt='openlist-user-admin'):
    return hashlib.sha256((salt + value).encode()).hexdigest()

def ensure_local_admin():
    # Never silently provision a known default password. A fresh database must
    # complete the explicit first-run setup flow before admin access is granted.
    return bool(setting('local_user') and setting('local_pass_hash'))

def setup_required():
    return not ensure_local_admin()

def setup_page(error=''):
    error_html = '<div class="login-error">'+html.escape(error)+'</div>' if error else ''
    return '''<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>首次设置</title><style>body{margin:0;background:linear-gradient(135deg,#0b1020,#111b35);color:#eef3ff;font:15px system-ui,-apple-system,"Microsoft YaHei",sans-serif}.wrap{max-width:440px;margin:12vh auto;padding:24px;background:#121a2d;border:1px solid #273452;border-radius:18px}label{display:block;color:#cbd7ff;margin:14px 0 5px}input{width:100%;box-sizing:border-box;border:1px solid #273452;background:#0c1427;color:#eef3ff;border-radius:8px;padding:11px;font:inherit}button{width:100%;border:0;border-radius:8px;background:#6d8cff;color:#fff;padding:12px;font-weight:700;cursor:pointer;margin-top:22px}.hint{color:#9eacc8;line-height:1.6}.login-error{margin:14px 0;padding:11px;border:1px solid #c45165;border-radius:9px;background:#3b202c;color:#ffc4cc}</style></head><body><main class="wrap"><h2>首次设置管理后台</h2><p class="hint">请设置新的后台账号和密码。密码至少 12 位；此步骤完成前后台管理功能不可用。</p>'''+error_html+'''<form method="post" action="/setup"><label>后台账号</label><input name="username" required minlength="4" maxlength="64" autocomplete="username"><label>新密码（至少 12 位）</label><input type="password" name="password" required minlength="12" autocomplete="new-password"><label>确认新密码</label><input type="password" name="confirm_password" required minlength="12" autocomplete="new-password"><button>保存并进入管理后台</button></form></main></body></html>'''

def check_local_login(username, passwd):
    ensure_local_admin()
    return hmac.compare_digest(username, setting('local_user')) and hmac.compare_digest(local_hash(passwd), setting('local_pass_hash'))

def password():
    alphabet = string.ascii_letters + string.digits + '!@#$%_-'
    return ''.join(secrets.choice(alphabet) for _ in range(16))

def openlist_login(username, password):
    base = setting('openlist_url').rstrip('/')
    if not base: raise RuntimeError('请先设置 OpenList 地址')
    data = json.dumps({'username': username, 'password': password}).encode()
    req = urllib.request.Request(base + '/api/auth/login', data=data, method='POST', headers={'Content-Type':'application/json'})
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            result = json.loads(r.read().decode('utf-8', 'replace'))
        token = result.get('data', {}).get('token') or result.get('token')
        if not token: raise RuntimeError('OpenList 登录返回中没有 Token')
        save_setting('openlist_token', token)
        return token
    except urllib.error.HTTPError as e:
        raise RuntimeError(f'管理员账号或密码错误（HTTP {e.code}）')

def find_openlist_user(username):
    # Avoid one huge slow response; page through users and only report absent
    # after every page has been successfully fetched.
    page_no = 1
    per_page = 100
    while True:
        result = api('GET', f'/api/admin/user/list?page={page_no}&per_page={per_page}')
        data = result.get('data') or {}
        rows = data.get('content', []) if isinstance(data, dict) else []
        for user in rows:
            if user.get('username') == username and user.get('id') is not None:
                return user
        total = data.get('total') if isinstance(data, dict) else None
        if not rows or (total is not None and page_no * per_page >= int(total)) or len(rows) < per_page:
            return None
        page_no += 1

def result_user_id(result):
    def walk(value):
        if isinstance(value, dict):
            if value.get('id') is not None and value.get('username'):
                return value.get('id')
            for child in value.values():
                found = walk(child)
                if found is not None: return found
        elif isinstance(value, list):
            for child in value:
                found = walk(child)
                if found is not None: return found
        return None
    return walk(result)

def api(method, path, payload=None):
    base = setting('openlist_url').rstrip('/')
    if not base: raise RuntimeError('请先在“设置”中配置 OpenList 地址')
    data = None if payload is None else json.dumps(payload).encode()
    for attempt in range(2):
        token = setting('openlist_token')
        if not token:
            ouser, opass = setting('openlist_user'), setting('openlist_pass')
            if not ouser or not opass: raise RuntimeError('请先在后台设置 OpenList 管理员账号和密码')
            token = openlist_login(ouser, opass)
        req = urllib.request.Request(base + path, data=data, method=method, headers={'Authorization': token, 'Content-Type': 'application/json', 'Accept': 'application/json'})
        try:
            with urllib.request.urlopen(req, timeout=15) as r:
                raw = r.read().decode('utf-8', 'replace')
                if not raw.strip(): raise RuntimeError(f'OpenList 返回空响应（HTTP {r.status}）')
                try: result = json.loads(raw)
                except json.JSONDecodeError: raise RuntimeError(f'OpenList 返回非 JSON（HTTP {r.status}）：{raw[:200]}')
            code = result.get('code') if isinstance(result, dict) else None
            if code not in (None, 0, 200):
                message = result.get('message') or result.get('msg') or f'业务错误码 {code}'
                if (code == 401 or 'token' in str(message).lower() or 'expired' in str(message).lower()) and attempt == 0:
                    save_setting('openlist_token', '')
                    continue
                raise RuntimeError(f'OpenList API 错误（{code}）：{message}')
            return result
        except urllib.error.HTTPError as e:
            body = e.read().decode('utf-8', 'replace')
            if e.code in (401, 403) and attempt == 0:
                save_setting('openlist_token', '')
                continue
            raise RuntimeError(f'OpenList 返回 HTTP {e.code}: {body[:300]}')
        except urllib.error.URLError as e: raise RuntimeError(f'无法连接 OpenList：{e.reason}')
        except RuntimeError: raise
        except Exception as e: raise RuntimeError(str(e))
    raise RuntimeError('OpenList 登录失败')

def page(body, title='OpenList 用户管理', public=False):
    css = ':root{--bg:#080d1c;--panel:#111a2e;--panel2:#16223b;--line:#2a3b62;--text:#f3f6ff;--muted:#91a2c4;--pri:#6f8cff;--pri2:#526fe0;--ok:#35c98a;--bad:#e56b7b;--gold:#e4ad4f}*{box-sizing:border-box}body{margin:0;min-height:100vh;background:radial-gradient(circle at 15% 0%,#1d3566 0,#0c1429 34%,#080d1c 75%);color:var(--text);font:15px system-ui,-apple-system,"Microsoft YaHei",sans-serif}main{max-width:1080px;margin:auto;padding:34px 20px 70px}h1{font-size:30px;letter-spacing:.4px;margin:0 0 6px}.sub,.muted{color:var(--muted)}nav{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:10px;margin:24px 0}nav a{display:flex;align-items:center;justify-content:center;min-height:44px;color:#d9e2ff;text-decoration:none;background:linear-gradient(135deg,#172849,#101a31);border:1px solid var(--line);border-radius:12px;padding:10px 15px;font-weight:700;transition:.18s;box-shadow:0 5px 14px #0002}nav a:hover{background:linear-gradient(135deg,#526fe0,#3852b4);border-color:#91a7ff;transform:translateY(-2px);box-shadow:0 8px 20px #253e9c66}nav a:first-child{border-color:#536fbf}nav a:nth-child(2){border-color:#3f806e}nav a:nth-child(3){border-color:#85653c}.card{background:linear-gradient(145deg,rgba(20,31,55,.96),rgba(13,21,39,.96));border:1px solid var(--line);border-radius:18px;padding:24px;margin:18px 0;box-shadow:0 16px 45px #0004}label{display:block;color:#d5def5;margin:13px 0 6px;font-weight:600}input{width:100%;border:1px solid var(--line);background:#0b1428;color:var(--text);border-radius:10px;padding:12px;font:inherit;transition:.18s}.dashboard-head{display:flex;align-items:flex-end;justify-content:space-between;gap:18px;margin:24px 0 14px}.dashboard-head h2{margin:0}.dashboard-head .hint{margin:5px 0 0}.stats{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:12px;margin:18px 0}.stat{padding:16px 18px;border:1px solid var(--line);border-radius:14px;background:linear-gradient(135deg,#172849,#101a31);box-shadow:0 8px 22px #0002}.stat-label{color:var(--muted);font-size:13px}.stat-value{display:block;margin-top:5px;font-size:25px;font-weight:800;letter-spacing:.3px}.stat-value.ok{color:#7ee7b7}.stat-value.bad{color:#ff9eaa}.user-pager{display:flex;align-items:center;justify-content:space-between;gap:12px;margin-top:20px;padding:12px 14px;border:1px solid #2f4675;border-radius:12px;background:#0d1c38;color:#aebfe5;font-size:13px}.user-pager>div{display:flex;align-items:center;gap:6px}.user-pager a,.user-pager .disabled{display:inline-flex;align-items:center;justify-content:center;min-width:34px;height:32px;padding:0 10px;border:1px solid #3b568a;border-radius:8px;color:#dce7ff;text-decoration:none;background:#14284c;font-weight:700}.user-pager a:hover,.user-pager a.current{border-color:#91a7ff;background:#3852b4;color:#fff}.user-pager .disabled{opacity:.45;cursor:not-allowed}.user-stats{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:10px;margin:18px 0 6px}.user-stat{display:block;padding:13px 14px;border:1px solid #2f4675;border-radius:13px;background:linear-gradient(135deg,#172f5b,#0d1c38);box-shadow:0 7px 18px #0002;color:inherit;text-decoration:none;cursor:pointer;transition:.18s}.user-stat:hover,.user-stat.active{border-color:#91a7ff;background:linear-gradient(135deg,#244782,#12284e);transform:translateY(-2px);box-shadow:0 10px 24px #253e9c55}.user-stat-label{display:block;color:#aebfe5;font-size:12px;white-space:nowrap}.user-stat strong{display:block;margin-top:5px;color:#f3f6ff;font-size:24px;line-height:1}.user-stat-day{border-color:#64748b}.user-stat-week{border-color:#0d9488}.user-stat-month{border-color:#2563eb}.user-stat-quarter{border-color:#7c3aed}.user-stat-halfyear{border-color:#be185d}.user-stat-year{border-color:#d97706}.user-stat-expired{border-color:#a94458}.user-stat-expired strong{color:#ff9eaa}.search-tools{display:flex;width:100%;gap:10px;align-items:center}.search-tools .search-form{flex:1;min-width:0;margin-top:0;align-items:center}.search-tools .search-form input{min-width:0;height:42px}.search-tools .search-form button{align-self:stretch}.search-tools .search-form button,.clear-search{height:42px;min-width:76px;margin:0;padding:0 15px;border-radius:10px;display:inline-flex;align-items:center;justify-content:center;font:inherit;font-weight:700;white-space:nowrap}.clear-search{border:1px solid #9a7842;background:#3a2c19;color:#ffe09a;text-decoration:none;transition:.18s;align-self:stretch}.clear-search:hover{border-color:#e4ad4f;background:#55401f;color:#fff0bd;transform:translateY(-1px)}.clear-search:hover{border-color:#718cff;background:#142346}.empty-state{text-align:center;padding:30px 15px;border:1px dashed #40557f;border-radius:14px;background:#0c162b}.empty-state strong{display:block;margin-bottom:6px}.empty-state a{display:inline-flex;align-items:center;justify-content:center;gap:6px;margin-top:18px;min-width:138px;padding:11px 18px;border:1px solid #718cff;border-radius:10px;background:linear-gradient(135deg,#526fe0,#3852b4);color:#fff;text-decoration:none;font-weight:700;box-shadow:0 8px 18px #253e9c55;transition:.18s}.empty-state a:hover{background:linear-gradient(135deg,#718cff,#526fe0);border-color:#aabaff;transform:translateY(-2px);box-shadow:0 11px 24px #253e9c88}.empty-state a:active{transform:translateY(0);box-shadow:0 5px 12px #253e9c55}.card{background:linear-gradient(145deg,rgba(20,31,55,.96),rgba(13,21,39,.96));border:1px solid var(--line);border-radius:18px;padding:24px;margin:18px 0;box-shadow:0 16px 45px #0004}input:focus{outline:none;border-color:var(--pri);box-shadow:0 0 0 3px #6f8cff33}.plan-options{display:grid;grid-template-columns:repeat(4,1fr);gap:10px;margin-top:7px}.plan-option{display:flex;align-items:center;gap:9px;margin:0;padding:13px 12px;border:1px solid var(--line);border-radius:12px;background:#0b1428;cursor:pointer;transition:.18s}.plan-option:hover{border-color:#718cff;background:#142346;transform:translateY(-1px)}.plan-option:has(input:checked){border-color:var(--pri);background:linear-gradient(135deg,#213b78,#172b54);box-shadow:0 0 0 2px #6f8cff33}.plan-option-day:has(input:checked){border:2px solid #64748b;background:#0b1428;color:var(--text);box-shadow:none}.plan-option-day .plan-icon{background:#475569;color:#f8fafc}.plan-option-day:has(input:checked) .plan-icon{background:#64748b}.plan-option-week:has(input:checked){border:2px solid #0d9488;background:#0b1428;color:var(--text);box-shadow:0 0 12px #0d948855}.plan-option-month:has(input:checked){border:2px solid #2563eb;background:#0b1428;color:var(--text);box-shadow:none}.plan-option-quarter:has(input:checked){border:2px solid #7c3aed;background:#0b1428;color:var(--text);box-shadow:none}.plan-option-halfyear:has(input:checked){border:2px solid #be185d;background:#0b1428;color:var(--text);box-shadow:none}.plan-option-halfyear .plan-icon{background:#be185d;color:#fce7f3}.plan-option-halfyear:has(input:checked) .plan-icon{background:#be185d}.plan-option-year:has(input:checked){border:2px solid #d97706;background:#0b1428;color:var(--text);box-shadow:none}.plan-option-week:has(input:checked) small,.plan-option-month:has(input:checked) small,.plan-option-quarter:has(input:checked) small,.plan-option-year:has(input:checked) small{color:inherit;opacity:.82}.plan-option-week .plan-icon{background:#2563eb;color:#eff6ff}.plan-option-month .plan-icon{background:#2563eb;color:#eff6ff}.plan-option-quarter .plan-icon{background:#7c3aed;color:#f5f3ff}.plan-option-year .plan-icon{background:#d97706;color:#0f172a}.plan-option-week:has(input:checked) .plan-icon{background:#2563eb}.plan-option-month:has(input:checked) .plan-icon{background:#2563eb}.plan-option-quarter:has(input:checked) .plan-icon{background:#7c3aed}.plan-option-year:has(input:checked) .plan-icon{background:#d97706}.plan-option input{display:none}.plan-icon{display:grid;place-items:center;width:28px;height:28px;border-radius:9px;background:#263d79;color:#aebeff;font-size:16px}.plan-option b,.plan-option small{display:block}.plan-option small{margin-top:3px;color:var(--muted);font-size:12px}.plan-option:has(input:checked) small{color:#d8e2ff}select{width:100%;appearance:none;border:1px solid #3b4f7a;background:#0b1428;color:var(--text);border-radius:10px;padding:12px 40px 12px 13px;font:inherit;font-weight:600;cursor:pointer;background-image:linear-gradient(45deg,transparent 50%,#9db3ff 50%),linear-gradient(135deg,#9db3ff 50%,transparent 50%);background-position:calc(100% - 18px) 52%,calc(100% - 12px) 52%;background-size:6px 6px;background-repeat:no-repeat}select:focus{outline:none;border-color:var(--pri);box-shadow:0 0 0 3px #6d8cff33}option{background:#121a2d;color:var(--text)}button{border:0;border-radius:8px;background:var(--pri);color:white;padding:10px 15px;font-weight:700;cursor:pointer;margin-top:14px}button:disabled{opacity:.65;cursor:wait}.is-busy{position:relative}.card form[action="/new"]>button[type="submit"],.card form[action="/new"]>button:not([type]){width:100%;margin-top:20px;min-height:44px}.danger{background:var(--bad)}.delete-btn{background:#d95768;color:#fff}.pause{background:#65738f;color:#fff}.renew{background:#d49b3f;color:#241707}.ok{background:var(--ok);color:#062b20}.grid{display:grid;grid-template-columns:1fr 1fr;gap:0 16px}.full{grid-column:1/-1}.user-list{display:grid;gap:0;margin-top:24px;padding-top:2px}.row{display:flex;justify-content:space-between;gap:18px;align-items:center;border:1px solid #2b3b60;border-radius:14px;padding:17px 18px;margin:0 0 14px;background:linear-gradient(135deg,rgba(22,34,61,.9),rgba(14,23,43,.95));box-shadow:0 6px 18px #0002}.user-list .row:last-child{margin-bottom:0}.row:hover{border-color:#526da8;transform:translateY(-1px);transition:.15s}.user-main{min-width:0;flex:1}.user-name{font-size:17px;letter-spacing:.2px}.user-meta{display:grid;grid-template-columns:minmax(0,1fr) auto;align-items:center;column-gap:16px;width:max-content;max-width:100%}.user-title-row{display:contents}.user-badges{display:flex;align-items:center;justify-content:flex-end;gap:8px;white-space:nowrap;grid-column:2}.user-badges .badge{border-radius:999px;padding:4px 9px}.user-info{grid-column:1/-1;margin-top:8px;line-height:1.7;text-align:left;white-space:nowrap}.user-info br{display:block}.user-info br{display:block}.actions{display:flex;flex-wrap:nowrap;justify-content:flex-end;align-items:stretch;gap:8px}.actions form{display:flex;margin:0!important;padding:0;flex:0 0 76px;height:40px}.actions>button{flex:0 0 76px}.actions button{margin:0!important;min-width:76px;width:76px;height:40px;padding:9px 8px;display:inline-flex;align-items:center;justify-content:center;white-space:nowrap;vertical-align:top}.search-form{display:flex;gap:10px;margin-top:14px}.search-form input{flex:1}.search-form button{width:auto;margin:0}.plan-badge{display:inline-flex;align-items:center;justify-content:center;min-height:28px;padding:4px 12px;border-radius:999px;font-size:12px;font-weight:700;line-height:1;letter-spacing:.2px;white-space:nowrap;box-shadow:inset 0 1px 1px #ffffff40,0 5px 14px #0003}.plan-day{background:linear-gradient(180deg,#475569,#1e293b);color:#f1f5f9;border:1px solid #64748b}.plan-week{background:linear-gradient(90deg,#0f766e,#14b8a6,#0f766e);color:#ecfeff;border:1px solid #5eead4;box-shadow:inset 0 1px 1px #ccfbf166,0 7px 18px #0f766e55}.plan-month{background:linear-gradient(90deg,#1d4ed8,#2563eb,#1d4ed8);color:#eff6ff;border:1px solid #60a5fa;box-shadow:inset 0 1px 1px #bfdbfe66,0 7px 18px #2563eb55}.plan-quarter{background:linear-gradient(90deg,#6d28d9,#7c3aed,#9333ea);color:#f5f3ff;border:1px solid #c084fc;box-shadow:inset 0 1px 1px #e9d5ff73,0 7px 18px #7c3aed66}.plan-halfyear{background:linear-gradient(90deg,#9d174d,#db2777,#9d174d);color:#fff1f2;border:1px solid #f9a8d4;box-shadow:inset 0 1px 1px #fbcfe866,0 7px 18px #9d174d55}.plan-year{background:linear-gradient(90deg,#d97706,#f59e0b,#d97706);color:#0f172a;border:1px solid #fcd34d;box-shadow:inset 0 1px 2px #fef3c799,0 8px 20px #d977065c}.plan-custom{background:linear-gradient(135deg,#4c1d95,#312e81);color:#f5f3ff;border:1px solid #8b5cf6}.badge{font-weight:600}.row:first-child{border-top:1px solid #2b3b60}.badge{border-radius:20px;padding:4px 9px;background:#263557;color:#cbd7ff;font-size:12px}.badge.ok{background:#164d3d;color:#9ff0c9}.badge.bad{background:#552b37;color:#ffc0c8}.err{border:1px solid #7d3947;background:#321c28;padding:12px;border-radius:9px;color:#ffc0c8}.hint{font-size:13px;color:var(--muted)}.invite-summary{margin:18px 0 20px;padding:18px;border:1px solid #36558f;border-radius:16px;background:linear-gradient(145deg,#14284c,#0d1931);box-shadow:0 10px 28px #0003}.invite-summary textarea{display:block;width:100%;min-height:150px;margin:0 0 14px;padding:14px;border:1px solid #4867a5;border-radius:11px;background:#081326;color:#dce7ff;font:14px ui-monospace,SFMono-Regular,Menlo,monospace;line-height:1.7;resize:vertical}.invite-summary .register-submit{width:100%;margin:0;background:linear-gradient(135deg,#35c98a,#159a72);color:#062b20;box-shadow:0 8px 20px #159a7255}.invite-summary .register-submit:hover{filter:brightness(1.12);transform:translateY(-1px)}.invite-generate-btn{display:inline-flex;align-items:center;justify-content:center;gap:6px;min-height:48px;padding:12px 24px;border-radius:12px;background:linear-gradient(135deg,#718cff,#3852b4);border:1px solid #aabaff;color:#fff;box-shadow:0 10px 24px #3852b466;font-size:15px}.invite-generate-btn:hover{background:linear-gradient(135deg,#91a7ff,#526fe0);transform:translateY(-2px);box-shadow:0 13px 28px #3852b488}.invite-row{display:flex;align-items:center;gap:12px;margin:10px 0;padding:13px 15px;border:1px solid #2f4675;border-radius:12px;background:linear-gradient(135deg,#122342,#0c172d)}.invite-row>input[type=checkbox]{width:18px;min-width:18px;height:18px;margin:0;accent-color:var(--pri)}.invite-row>div{flex:1;min-width:0}.invite-row input[readonly]{margin-top:8px;font-size:13px}.invite-row button{margin:0;padding:8px 12px;white-space:nowrap;background:#263d79}.invite-row button:hover{background:#4162b4;transform:translateY(-1px)}@media(max-width:650px){nav{grid-template-columns:repeat(4,minmax(0,1fr));gap:6px}nav a{padding:9px 3px;font-size:12px;min-height:42px}.dashboard-head{display:block}.stats{grid-template-columns:repeat(4,minmax(0,1fr));gap:8px}.stat{padding:12px 9px}.stat-label{font-size:12px;white-space:nowrap}.stat-value{font-size:20px}.stat-value{font-size:20px}.search-tools{align-items:stretch}.search-tools input{min-width:0}.clear-search{padding:0 10px}.grid{display:block}.row{display:block}.user-meta{display:block;width:100%;max-width:100%}.user-title-row{display:flex;align-items:flex-start;justify-content:space-between;gap:10px}.user-badges{flex-wrap:wrap}.user-info{text-align:left;white-space:normal}.row form{margin-top:10px}.actions{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:8px;margin-top:14px;width:100%;align-items:stretch}.actions form,.actions>button{width:100%;min-width:0;flex:initial;height:42px;margin:0!important}.actions form{display:flex;padding:0}.actions button{width:100%;min-width:0;height:42px;margin:0!important;padding:9px 4px}.plan-options{grid-template-columns:repeat(2,1fr)}.user-pager{display:block;text-align:center}.user-pager>div{justify-content:center;flex-wrap:wrap;margin-top:10px}.user-stats{grid-template-columns:repeat(4,minmax(0,1fr));gap:8px}.user-stat{padding:11px 9px}.user-stat-label{font-size:11px}.user-stat strong{font-size:20px}}.modal-mask{position:fixed;inset:0;background:#050914cc;display:flex;align-items:center;justify-content:center;padding:20px;z-index:10}.modal-card{width:min(400px,100%);background:var(--card);border:1px solid var(--line);border-radius:18px;padding:28px;box-shadow:0 24px 80px #0008}.modal-logo{text-align:center;font-size:42px}.modal-card h2{text-align:center;margin:10px 0}.modal-card .hint{text-align:center}.register-error-card{text-align:center;max-width:440px;margin:42px auto 0;border-top:4px solid #e56b7b;padding:30px 28px 28px;background:linear-gradient(145deg,rgba(30,35,61,.98),rgba(15,22,43,.98));box-shadow:0 20px 55px #0006}.register-error-icon{width:58px;height:58px;margin:0 auto 14px;border-radius:50%;display:grid;place-items:center;background:linear-gradient(145deg,#e56b7b,#a9364b);color:#fff;font-size:32px;font-weight:800;box-shadow:0 10px 24px #a9364b66}.register-error-card h2{margin:0 0 8px;color:#fff}.register-error-message{font-size:15px;margin:0 0 6px}.register-error-card .register-submit{width:100%;margin-top:20px;background:linear-gradient(135deg,#e56b7b,#b43f55);box-shadow:0 8px 20px #a9364b55}.register-error-card .register-submit:hover{filter:brightness(1.1);transform:translateY(-1px)}.register-error-card .renew-back-link{display:flex;align-items:center;justify-content:center;gap:9px;width:100%;min-height:50px;margin:24px auto 0;padding:0 20px;border:1px solid #aabaff;border-radius:13px;background:linear-gradient(135deg,#718cff 0%,#526fe0 55%,#3852b4 100%);color:#fff;text-decoration:none;font-size:15px;font-weight:800;letter-spacing:.2px;box-shadow:0 10px 24px #3852b466,inset 0 1px 0 #ffffff55;transition:.2s}.register-error-card .renew-back-link:before{content:&quot;↩&quot;;font-size:20px;line-height:1}.register-error-card .renew-back-link:hover{border-color:#c2ccff;background:linear-gradient(135deg,#91a7ff,#627bea 52%,#4660c7);transform:translateY(-2px);box-shadow:0 14px 28px #3852b488}.register-error-card .renew-back-link:active{transform:translateY(0);box-shadow:0 7px 16px #3852b455}.register-error-card .err{max-width:360px;margin:0 auto;text-align:center;line-height:1.7}.register-duplicate-card{border-top-color:#d49b3f}.register-duplicate-card .register-error-icon{background:linear-gradient(145deg,#e4ad4f,#a96d18);box-shadow:0 10px 24px #a96d1866}.register-duplicate-card h2{color:#fff0bd}.register-duplicate-card .duplicate-message{margin:0 auto;max-width:350px;color:#dce7ff;line-height:1.8}.register-duplicate-card .renew-back-link{margin-top:24px}.register-error-card .error-help{max-width:360px;margin:14px auto 0;color:#91a2c4;font-size:13px;line-height:1.7}.register-title{text-align:center!important;font-size:26px;margin:4px 0 8px!important;color:#f3f6ff;letter-spacing:1px}.register-card{max-width:460px;margin:50px auto;border-top:4px solid var(--plan-color);background:linear-gradient(145deg,rgba(20,31,55,.98),rgba(13,21,39,.98));box-shadow:0 20px 60px var(--plan-shadow)}.register-plan-icon{display:grid;place-items:center;width:58px;height:58px;margin:0 auto 10px;border-radius:18px;background:var(--plan-color);color:var(--plan-icon);font-size:30px;font-weight:800;box-shadow:0 8px 22px var(--plan-shadow)}.register-slogan{text-align:center;margin:0 0 22px;color:var(--plan-color);font-weight:700;font-size:13px}.register-card form{margin-top:0}.register-submit{width:100%;margin-top:22px;min-height:46px;background:linear-gradient(135deg,var(--plan-color),var(--plan-dark));box-shadow:0 8px 20px var(--plan-shadow)}.register-submit:hover{filter:brightness(1.15);transform:translateY(-1px)}.plan-theme-day{--plan-color:#94a3b8;--plan-dark:#475569;--plan-icon:#f8fafc;--plan-shadow:#64748b55}.plan-theme-week{--plan-color:#14b8a6;--plan-dark:#0f766e;--plan-icon:#ecfeff;--plan-shadow:#0d948855}.plan-theme-month{--plan-color:#3b82f6;--plan-dark:#1d4ed8;--plan-icon:#eff6ff;--plan-shadow:#2563eb55}.plan-theme-quarter{--plan-color:#a855f7;--plan-dark:#6d28d9;--plan-icon:#faf5ff;--plan-shadow:#7c3aed55}.plan-theme-halfyear{--plan-color:#ec4899;--plan-dark:#9d174d;--plan-icon:#fff1f2;--plan-shadow:#db277755}.plan-theme-year{--plan-color:#f59e0b;--plan-dark:#b45309;--plan-icon:#fffbeb;--plan-shadow:#d9770655}.modal-button{width:100%;margin-top:22px}.username-label{display:flex;align-items:center;gap:8px}.username-field{position:relative}.username-status{font-size:13px;font-weight:500}.username-status.available{color:var(--ok)}.username-status.exists{color:var(--bad)}.delete-modal-card{text-align:center}.delete-modal-icon{display:grid;place-items:center;width:48px;height:48px;margin:0 auto 10px;border-radius:50%;background:#5a2b37;color:#ffc0c8;font-size:28px;font-weight:800}.renew-success-icon{width:72px;height:72px;background:linear-gradient(135deg,#35c98a,#159a72);color:#ecfff7;box-shadow:0 8px 24px #1fa97966,0 0 0 7px #35c98a18}.renew-success-icon svg{width:48px;height:48px;display:block}.delete-warning{padding:10px 12px;border-radius:9px;background:#3a222c;color:#ffc0c8;font-size:13px;text-align:left}.delete-confirm{background:#d95768!important}.delete-modal-card .secondary-link{display:block;width:100%;margin-top:10px;text-align:center;cursor:pointer}.copy-modal{position:fixed;inset:0;display:flex;align-items:center;justify-content:center;pointer-events:none;opacity:0;transition:opacity .2s;z-index:20}.copy-modal.show{opacity:1}.copy-modal-card{display:flex;flex-direction:column;align-items:center;gap:7px;min-width:190px;padding:24px 30px;border:1px solid #4b79c9;border-radius:16px;background:rgba(17,29,53,.97);box-shadow:0 18px 55px #0008;color:var(--text);font-size:15px}.copy-modal-card span{color:var(--muted);font-size:13px}.copy-modal-icon{display:grid;place-items:center;width:42px;height:42px;border-radius:50%;background:var(--ok);color:#062b20;font-size:25px;font-weight:800}.save-confirm-mask{position:fixed;inset:0;z-index:30;background:#080d1c;display:flex;align-items:center;justify-content:center;padding:20px}.save-confirm-card{width:min(430px,100%);padding:30px 26px;background:#121a2d;border:1px solid #d49b3f;border-radius:18px;box-shadow:0 24px 80px #000c;text-align:center}.save-confirm-icon{font-size:42px;margin-bottom:8px}.save-confirm-card h2{margin:8px 0 12px;color:#fff0bd}.save-confirm-card p{color:#d9e2ff;line-height:1.7;margin:0}.save-confirm-button{width:100%;margin-top:24px;background:linear-gradient(135deg,#d49b3f,#a96d18);color:#241707}.copy-locked{opacity:.6;cursor:not-allowed!important}.invite-page{margin-top:20px}.pending-table .invite-link{color:#dce7ff;font-weight:700}.invite-status.unused{background:#284c45;color:#b8f2dc}.export-btn{margin:0;background:linear-gradient(135deg,#35c98a,#159a72);color:#062b20}.export-confirm-mask{background:#050914dc}.export-confirm-card{max-width:470px;text-align:center;border:1px solid #4d73c7;padding:30px 28px}.export-confirm-icon{font-size:46px;margin-bottom:8px}.export-confirm-card h2{margin:6px 0 12px;color:#edf3ff}.export-confirm-message{color:#b8c9ef;line-height:1.75;margin:0}.export-confirm-actions{display:flex;gap:10px;margin-top:24px}.export-confirm-actions button{flex:1;margin:0;min-height:44px}.export-confirm-actions .secondary-link{background:#263557;color:#dbe6ff}.export-confirm-ok{background:linear-gradient(135deg,#35c98a,#159a72)!important;color:#062b20}.invite-generate-bar{display:flex;align-items:end;gap:14px;flex-wrap:wrap;padding:18px 20px;margin:12px 0 24px;background:linear-gradient(135deg,#172f5b,#0d1c38);border:1px solid #4265a2;border-radius:16px;box-shadow:0 10px 28px #0003}.invite-generate-bar label{display:flex;flex-direction:column;gap:7px;margin:0;color:#dce7ff;font-size:13px;font-weight:700;letter-spacing:.2px}.invite-generate-bar select,.invite-generate-bar input{display:block;width:auto;min-width:190px;height:44px;margin:0;padding:10px 42px 10px 14px;border:1px solid #4867a5;border-radius:11px;background-color:#0a162d;color:#f3f6ff;font:inherit;font-weight:600;box-shadow:inset 0 1px 2px #0004,0 4px 12px #0002;transition:.18s}.invite-generate-bar input{min-width:120px;padding:10px 14px;text-align:center}.invite-generate-bar select:hover,.invite-generate-bar input:hover{border-color:#718cff;background-color:#0e1e3d}.invite-generate-bar select:focus,.invite-generate-bar input:focus{outline:none;border-color:#91a7ff;box-shadow:0 0 0 3px #6f8cff33,0 6px 16px #0003}.invite-generate-bar input[type=number]::-webkit-inner-spin-button,.invite-generate-bar input[type=number]::-webkit-outer-spin-button{opacity:1;height:28px}.invite-generate-bar button{height:44px;margin:0;padding:0 20px;border:1px solid #91a7ff;border-radius:11px;background:linear-gradient(135deg,#718cff,#3852b4);box-shadow:0 7px 18px #3852b466;font-size:14px}.invite-generate-bar button:hover{background:linear-gradient(135deg,#91a7ff,#526fe0);transform:translateY(-1px);box-shadow:0 10px 22px #3852b488}.invite-used-title{margin:0 0 10px}.invite-used-title h3{margin:0}.invite-used-title .export-btn{white-space:nowrap;padding:10px 16px;border-radius:9px}.invite-count{color:#bcd0ff;background:#182b50;border:1px solid #36558f;border-radius:999px;padding:8px 13px;font-size:13px}.invite-filters{display:flex;align-items:center;gap:10px;flex-wrap:wrap;padding:14px 0 18px}.invite-filters input,.invite-filters select{width:auto;min-width:180px;height:40px;padding:9px 12px}.invite-filters label{display:flex;align-items:center;gap:8px;margin:0;color:var(--muted);font-size:13px}.invite-filters label input{min-width:145px}.invite-filters button,.invite-filters a{height:40px;margin:0;padding:9px 16px;border-radius:8px}.invite-filters a{display:inline-flex;align-items:center;border:1px solid #40557f;background:#182640;color:#d6e0fa;text-decoration:none}.date-sep{color:var(--muted)}.table-wrap{overflow:auto;border:1px solid #2b3b60;border-radius:12px;background:#0d172c}.invite-table{width:100%;border-collapse:collapse;min-width:900px}.invite-table th{background:#162849;color:#b8c9ef;text-align:left;font-size:12px;font-weight:700;white-space:nowrap}.invite-table th,.invite-table td{padding:11px 12px;border-bottom:1px solid #243858}.invite-table tbody tr:hover{background:#142444}.invite-table tbody tr:last-child td{border-bottom:0}.invite-table th:first-child,.invite-table td:first-child{width:38px;text-align:center}.invite-plan,.invite-status{display:inline-flex;padding:4px 9px;border-radius:999px;font-size:12px;font-weight:700;white-space:nowrap}.invite-plan-day{background:#4c3a82;color:#e9ddff}.invite-plan-week{background:#174a91;color:#cfe3ff}.invite-plan-month{background:#145b76;color:#d0f5ff}.invite-plan-quarter{background:#58358c;color:#f0ddff}.invite-plan-halfyear{background:#7b315f;color:#ffd9ec}.invite-plan-year{background:#805715;color:#ffe9a8}.invite-status.used{background:#4d2938;color:#ffc7d1}.invite-link{display:inline-block;max-width:260px;overflow:hidden;text-overflow:ellipsis;vertical-align:middle;color:#a9c5ff;font-family:ui-monospace,monospace;font-size:12px;white-space:nowrap}.icon-copy{border:0;background:transparent;color:#bcd0ff;padding:3px 5px;margin:0;font-size:16px;cursor:pointer}.invite-user{color:#8fb2ff;text-decoration:none;font-weight:700}.invite-user:hover{text-decoration:underline}.detail-link{color:#9fb9ff;text-decoration:none}.detail-link:hover{text-decoration:underline}.table-empty{text-align:center!important;color:var(--muted);padding:34px!important}.table-footer{display:flex;align-items:center;gap:12px;padding-top:14px}.archive-btn{margin:0;background:#6b4050;color:#ffd4dd}.invite-filters+form{margin-top:0}.config-textarea{display:block;width:100%;max-width:560px;min-height:270px;resize:vertical;margin:18px auto;padding:16px 18px;border:1px solid var(--line);border-radius:12px;background:#0b1428;color:#f3f6ff;font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:15px;line-height:1.9;white-space:pre-wrap}.config-textarea:focus{outline:none;border-color:var(--pri);box-shadow:0 0 0 3px #6f8cff33}.config-actions{display:flex;gap:12px}.config-actions button,.continue-btn{flex:1;width:auto;margin:0;text-align:center}.continue-btn{display:flex;align-items:center;justify-content:center;border-radius:8px;background:var(--ok);color:#062b20;padding:10px 15px;font-weight:700;text-decoration:none}.guide-card{max-width:560px;margin:22px auto;background:linear-gradient(145deg,#142647,#0b162d);border:1px solid #3d5d99;border-radius:16px;text-align:left;padding:8px 20px;box-shadow:0 12px 28px #0004,inset 0 1px #ffffff12}.guide-card h3{margin-top:0}.guide-row{display:flex;align-items:center;justify-content:space-between;gap:18px;border-top:1px solid #304a78;padding:15px 2px}.guide-row:first-child{border-top:0}.guide-row span{display:flex;align-items:center;gap:8px;color:#aebfe5;font-size:13px;font-weight:600}.guide-row span:before{content:&quot;✦&quot;;display:grid;place-items:center;width:22px;height:22px;border-radius:7px;background:#263f77;color:#9fb2ff;font-size:11px}.guide-row b{word-break:break-all;color:#f4f7ff;font-size:16px;letter-spacing:.2px}.guide-row:first-child b{color:#aebeff}.guide-row:last-child b{color:#8eeac1}.guide-plan-row b{display:flex;align-items:center;justify-content:flex-end}.guide-plan-row .plan-badge{font-size:14px;min-height:30px;padding:5px 13px}.success-wrap{text-align:center;padding:28px 10px}.success-icon{width:64px;height:64px;line-height:64px;margin:0 auto 14px;border-radius:50%;background:#164d3d;color:#9ff0c9;font-size:38px;font-weight:700}.success-sub{color:var(--muted)}.credential-card{max-width:560px;margin:25px auto;background:#0c1427;border:1px solid var(--line);border-radius:14px;text-align:left;padding:4px 18px}.credential-row{display:flex;align-items:center;gap:14px;border-bottom:1px solid var(--line);padding:17px 0}.credential-row:last-child{border-bottom:0}.credential-row span{color:var(--muted);min-width:70px}.credential-row strong{flex:1;word-break:break-all}.copy-btn{margin:0;padding:6px 10px;background:#263557;font-size:12px}.notice{max-width:560px;margin:16px auto;padding:12px;border-radius:9px;background:#3a2d16;color:#ffd98a;text-align:left;font-size:13px}.success-actions{display:flex;justify-content:center;align-items:stretch;gap:14px;margin:26px auto 4px;max-width:440px}.success-actions .primary-link,.success-actions .secondary-link{display:inline-flex;align-items:center;justify-content:center;flex:1 1 0;width:0;min-width:0;height:48px;min-height:48px;margin:0!important;padding:0 14px;border:1px solid transparent;border-radius:11px;box-sizing:border-box;text-decoration:none;font:inherit;font-weight:700;line-height:1;white-space:nowrap;transition:.18s;box-shadow:0 7px 18px #0003}.success-actions .primary-link{border:1px solid #9fb2ff;background:linear-gradient(135deg,#718cff 0%,#526fe0 48%,#3852b4 100%);color:#fff}.success-actions .primary-link:hover{filter:brightness(1.1);transform:translateY(-2px);box-shadow:0 11px 24px #3852b488}.success-actions .secondary-link{border:1px solid #5874aa;background:linear-gradient(135deg,#263d6b,#182640);color:#e2eaff}.success-actions .secondary-link:hover{border-color:#91a7ff;background:linear-gradient(135deg,#385681,#263b68);color:#fff;transform:translateY(-2px);box-shadow:0 11px 24px #263b6866}.modal-card .secondary-link{width:100%;margin-top:10px;cursor:pointer;font:inherit;font-weight:700}.contact-modal{position:fixed;inset:0;z-index:50;display:flex;align-items:center;justify-content:center;padding:20px;background:#050914cc;opacity:0;visibility:hidden;transition:opacity .2s,visibility .2s}.contact-modal.show{opacity:1;visibility:visible}.contact-modal-card{position:relative;width:min(410px,100%);padding:30px 26px 24px;border:1px solid #5d7fd0;border-radius:20px;background:linear-gradient(145deg,#1a2f58,#0c172e);box-shadow:0 24px 80px #000b;text-align:center;transform:translateY(12px) scale(.97);transition:transform .22s}.contact-modal.show .contact-modal-card{transform:translateY(0) scale(1)}.contact-modal-close{position:absolute;top:10px;right:12px;width:34px;height:34px;margin:0;padding:0;border:1px solid #45649d;border-radius:50%;background:#14284c;color:#bcd0ff;font-size:25px;font-weight:400;line-height:30px}.contact-modal-close:hover{background:#263f77;color:#fff}.contact-modal-icon{display:grid;place-items:center;width:62px;height:62px;margin:0 auto 12px;border:1px solid #9fb2ff;border-radius:18px;background:linear-gradient(135deg,#718cff,#3852b4);font-size:30px;box-shadow:0 10px 25px #3852b466}.contact-modal-card h2{margin:4px 0 10px;color:#fff;font-size:22px}.contact-modal-card p{margin:0;color:#b8c9ef;line-height:1.7}.contact-modal-link{display:flex;align-items:center;justify-content:center;gap:8px;margin-top:22px;min-height:48px;border:1px solid #76e0b2;border-radius:12px;background:linear-gradient(135deg,#35c98a,#159a72);color:#062b20;text-decoration:none;font-weight:800;box-shadow:0 9px 22px #159a7255}.contact-modal-link:hover{filter:brightness(1.1);transform:translateY(-1px)}.contact-modal-link span{font-size:18px}.contact-modal-empty{margin-top:20px;padding:13px;border:1px solid #7d6839;border-radius:10px;background:#3a2d16;color:#ffd98a}.contact-modal-cancel{width:100%;margin-top:12px;border:1px solid #5874aa;background:#182b50;color:#dce7ff}.contact-modal-cancel:hover{background:#263d6b}.modal-card form button{width:100%;min-height:40px}.modal-card form .secondary-link{margin-top:10px}.duplicate-popup{position:fixed;inset:0;z-index:80;display:flex;align-items:center;justify-content:center;padding:20px;background:#050914d9;opacity:0;visibility:hidden;transition:opacity .2s,visibility .2s}.duplicate-popup.show{opacity:1;visibility:visible}.duplicate-popup-card{width:min(400px,100%);padding:30px 26px 24px;border:1px solid #d49b3f;border-radius:20px;background:linear-gradient(145deg,#26304f,#111a31);box-shadow:0 24px 80px #000b;text-align:center;transform:translateY(12px) scale(.96);transition:transform .22s}.duplicate-popup.show .duplicate-popup-card{transform:translateY(0) scale(1)}.duplicate-popup-icon{display:grid;place-items:center;width:64px;height:64px;margin:0 auto 14px;border:1px solid #f7d27c;border-radius:20px;background:linear-gradient(145deg,#e4ad4f,#a96d18);color:#241707;font-size:32px;font-weight:900;box-shadow:0 10px 26px #a96d1866}.duplicate-popup-card h2{margin:0 0 10px;color:#fff0bd;font-size:22px}.duplicate-popup-card p{margin:0;color:#dce7ff;line-height:1.8}.duplicate-popup-card .duplicate-popup-button{width:100%;min-height:48px;margin-top:24px;border:1px solid #f7d27c;border-radius:12px;background:linear-gradient(135deg,#e4ad4f,#a96d18);color:#241707;font-weight:800;box-shadow:0 9px 22px #a96d1855}.duplicate-popup-card .duplicate-popup-button:hover{filter:brightness(1.1);transform:translateY(-1px)}'
    if public: return '<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>'+esc(title)+'</title><style>'+css+'</style></head><body><main>'+body+'</main></body></html>'
    return '<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>'+esc(title)+'</title><style>'+css+'</style></head><body><main><h1>OpenList 用户管理</h1><div class="sub">仅 WebDAV 读取 · 权限值 256 · 停用不删除</div><nav><a href="/">☷　用户列表</a><a href="/new">＋　新增用户</a><a href="/invites">🔗　邀请注册</a><a href="/settings">⚙　系统设置</a></nav>'+body+'</main></body></html>'

def form_body(title, action, fields, msg=''):
    inputs = ''.join(f'<label>{esc(label)}</label><input name="{esc(name)}" value="{esc(value)}" {"required" if required else ""}>' for name,label,value,required in fields)
    return page(f'<div class="card"><h2>{esc(title)}</h2>{msg}<form method="post" action="{esc(action)}">{inputs}<button>保存</button></form></div>', title)

def login_modal(error=''):
    error_html = '<div class="login-error">'+esc(error)+'</div>' if error else ''
    login_html = '''<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>后台登录</title><style>body{margin:0;background:linear-gradient(135deg,#0b1020,#111b35);color:#eef3ff;font:15px system-ui,-apple-system,"Microsoft YaHei",sans-serif}.modal-mask{position:fixed;inset:0;background:#050914cc;display:flex;align-items:center;justify-content:center;padding:20px}.modal-card{width:min(400px,100%);background:#121a2d;border:1px solid #273452;border-radius:18px;padding:28px;box-shadow:0 24px 80px #0008}.modal-logo{text-align:center;font-size:42px}.modal-card h2{text-align:center;margin:10px 0}.hint{color:#9eacc8;text-align:center}label{display:block;color:#cbd7ff;margin:11px 0 5px}input{width:100%;box-sizing:border-box;border:1px solid #273452;background:#0c1427;color:#eef3ff;border-radius:8px;padding:10px;font:inherit}button{width:100%;border:0;border-radius:8px;background:#6d8cff;color:#fff;padding:10px 15px;font-weight:700;cursor:pointer;margin-top:22px}.login-error{margin:14px 0;padding:11px 13px;border:1px solid #c45165;border-radius:9px;background:#3b202c;color:#ffc4cc;text-align:center;font-weight:600}</style></head><body><div class="modal-mask"><div class="modal-card"><div class="modal-logo">🔐</div><h2>管理后台登录</h2><p class="hint">请输入本系统后台账号和密码</p>''' + error_html + '''<form method="post" action="/login"><label>后台账号</label><input name="username" required autocomplete="username"><label>后台密码</label><input type="password" name="password" required autocomplete="current-password"><button>登录后台</button></form></div></div></body></html>'''
    return login_html

def registered_info_page(inv, user):
    username = user['username']
    base = user['base_path'] or '/'
    configured = setting('openlist_url')
    parsed = urlsplit(configured)
    protocol = (parsed.scheme or 'http').upper()
    address = parsed.hostname or configured
    port = str(parsed.port or (443 if parsed.scheme == 'https' else 80))
    expiry = user['expires_at'] or '永久'
    plan = PLAN_LABELS.get(user['plan'], user['plan'])
    plan_cls = 'plan-'+user['plan'] if user['plan'] in PLAN_LABELS else 'plan-custom'
    template = '推荐使用网易爆米花\n应用里面找到 WebDav 这个选项\n协议:%s\n地址:%s\n端口:%s\n账号:%s\n密码:注册时设置的密码\n路径:/dav\n添加全部导入\n导入的时候不要退后台和熄屏' % (protocol, address, port, username)
    contact = setting('contact_url', '').strip()
    contact_html = '<button type="button" class="primary-link" onclick="openContactModal()">联系客服</button>'
    back_url = '/register/'+esc(inv['code']) if inv else '/query'
    contact_url = esc(contact)
    contact_modal = '<div id="contact-modal" class="contact-modal" role="dialog" aria-modal="true" aria-labelledby="contact-modal-title" onclick="if(event.target===this)closeContactModal()"><div class="contact-modal-card"><button type="button" class="contact-modal-close" aria-label="关闭" onclick="closeContactModal()">×</button><div class="contact-modal-icon">💬</div><h2 id="contact-modal-title">联系客服</h2><p>如需找回密码或咨询会员服务，请通过以下方式联系我们。</p>'+('<a class="contact-modal-link" href="'+contact_url+'" target="_blank" rel="noopener">打开客服入口 <span>↗</span></a>' if contact else '<div class="contact-modal-empty">暂未配置客服入口，请联系管理员。</div>')+'<button type="button" class="contact-modal-cancel" onclick="closeContactModal()">稍后处理</button></div></div><script>function openContactModal(){var m=document.getElementById("contact-modal");if(m){m.classList.add("show");document.body.style.overflow="hidden"}}function closeContactModal(){var m=document.getElementById("contact-modal");if(m){m.classList.remove("show");document.body.style.overflow=""}}document.addEventListener("keydown",function(e){if(e.key==="Escape")closeContactModal()})</script>'
    content = '<div class="card"><div class="success-wrap"><div class="success-icon">✓</div><h2>注册信息查询</h2><p class="success-sub">以下信息与注册成功后展示的配置说明一致</p></div><div class="guide-card"><div class="guide-row"><span>用户名</span><b>'+esc(username)+'</b></div><div class="guide-row guide-plan-row"><span>套餐</span><b><span class="plan-badge '+plan_cls+'">'+esc(plan)+'</span></b></div><div class="guide-row"><span>会员到期时间</span><b>'+esc(expiry)+'</b></div></div><textarea class="config-textarea" readonly>'+esc(template)+'</textarea><p class="notice">出于安全原因，系统不会保存或回显注册时设置的明文密码。密码请使用注册时设置的密码；如遗失，请联系客服处理。</p><div class="success-actions">'+contact_html+'<a class="secondary-link" href="'+back_url+'">返回查询页面</a></div></div>'+contact_modal
    return page(content, '注册信息查询', public=True)

def success_page(username, pwd, base, public=False):
    configured = setting('openlist_url')
    parsed = urlsplit(configured)
    protocol = (parsed.scheme or 'http').upper()
    address = parsed.hostname or configured
    port = str(parsed.port or (443 if parsed.scheme == 'https' else 80))
    template = '推荐使用网易爆米花\n应用里面找到 WebDav 这个选项\n协议:%s\n地址:%s\n端口:%s\n账号:%s\n密码:%s\n路径:/dav\n添加全部导入\n导入的时候不要退后台和熄屏' % (protocol, address, port, username, pwd)
    save_notice = '<div class="save-config-warning" role="alert"><strong>⚠️ 请立即保存配置</strong><span>这份配置包含登录密码，请务必复制并妥善保存。离开此页面后将无法再次查看完整密码。</span></div>' if public else ''
    copy_button = '<button type="button" class="copy-template-btn copy-locked" id="copy-config-button" disabled>请先确认已保存提示</button>' if public else '<button type="button" class="copy-template-btn" onclick="copyConfig(this)">复制配置</button>'
    content = '<div class="card"><h2>配置说明</h2>%s<textarea class="config-textarea" id="copy-template" readonly>%s</textarea><div class="config-actions">%s<span id="copy-status" class="copy-status" aria-live="polite"></span>%s</div></div>' % (save_notice, esc(template), copy_button, '' if public else '<a class="continue-btn" href="/new">继续新增</a>')
    content += '<div id="copy-modal" class="copy-modal" role="status" aria-live="polite"><div class="copy-modal-card"><div class="copy-modal-icon">✓</div><b>复制成功</b><span>配置已复制到剪贴板</span></div></div><script>function copyConfig(btn){var box=document.getElementById(\'copy-template\'),text=box.value;function done(){var modal=document.getElementById(\'copy-modal\');modal.classList.add(\'show\');setTimeout(function(){modal.classList.remove(\'show\')},1600)}function fallback(){box.focus();box.select();box.setSelectionRange(0,text.length);try{if(document.execCommand(\'copy\')){done()}else{showCopyError()}}catch(e){showCopyError()}}function showCopyError(){var modal=document.getElementById(\'copy-modal\');modal.querySelector(\'b\').textContent=\'请手动复制\';modal.querySelector(\'span\').textContent=\'请长按文本框选择并复制\';modal.classList.add(\'show\');setTimeout(function(){modal.classList.remove(\'show\');modal.querySelector(\'b\').textContent=\'复制成功\';modal.querySelector(\'span\').textContent=\'配置已复制到剪贴板\'},2200)}if(navigator.clipboard&&window.isSecureContext){navigator.clipboard.writeText(text).then(done).catch(fallback)}else{fallback()}}</script>'
    if public:
        content += '<div id="save-confirm-modal" class="save-confirm-mask" role="dialog" aria-modal="true" aria-labelledby="save-confirm-title"><div class="save-confirm-card"><div class="save-confirm-icon">⚠️</div><h2 id="save-confirm-title">重要提醒</h2><p>请先妥善保存注册信息。确认已保存后，才能继续复制配置。</p><button type="button" class="save-confirm-button" onclick="confirmSaved()">我已确认，继续</button></div></div><script>function confirmSaved(){var m=document.getElementById(\'save-confirm-modal\'),b=document.getElementById(\'copy-config-button\');if(m)m.remove();if(b){b.disabled=false;b.classList.remove(\'copy-locked\');b.textContent=\'复制配置\';b.onclick=function(){copyConfig(b)}}}document.getElementById(\'save-confirm-modal\').querySelector(\'button\').focus();</script>'
    return page(content, '配置说明', public=public)

class Handler(BaseHTTPRequestHandler):
    def auth(self):
        cookies = http.cookies.SimpleCookie(self.headers.get('Cookie', ''))
        sid = cookies.get('openlist_session')
        return bool(sid and sid.value in SESSIONS)
    def send(self, code, content, ctype='text/html; charset=utf-8', headers=None):
        b=content.encode(); self.send_response(code); self.send_header('Content-Type',ctype); self.send_header('Content-Length',str(len(b))); self.send_header('Cache-Control','no-store, no-cache, must-revalidate'); self.send_header('Pragma','no-cache')
        if getattr(self, 'auth_cookie', False): self.send_header('Set-Cookie', 'openlist_admin='+LOCAL_ADMIN_TOKEN+'; Path=/; HttpOnly; SameSite=Lax')
        for k,v in (headers or {}).items(): self.send_header(k,v)
        self.end_headers(); self.wfile.write(b)
    def deny(self): self.send(303, '', headers={'Location':'/login'})
    def ajax(self): return self.headers.get('X-Requested-With') == 'XMLHttpRequest'
    def done(self, location='/'):
        if self.ajax(): return self.send(204, '')
        return self.send(303, '', headers={'Location':location})
    def do_GET(self):
        p=urlparse(self.path); q=parse_qs(p.query)
        if p.path == '/health': return self.send(200,'ok','text/plain')
        if p.path == '/setup':
            return self.send(200, setup_page()) if setup_required() else self.send(303, '', headers={'Location':'/login'})
        if setup_required() and p.path not in ('/setup', '/health'):
            return self.send(200, setup_page())
        host=self.headers.get('Host','').split(':',1)[0].lower()
        if host == INVITE_HOST and p.path == '/login': return self.send(403,'forbidden','text/plain')
        if p.path == '/api/check-username' and host == INVITE_HOST:
            username=q.get('username',[''])[0].strip()
            exists=bool(username and db().execute('SELECT 1 FROM users WHERE username=?',(username,)).fetchone())
            forbidden=forbidden_username(username)
            invalid=invalid_username(username)
            return self.send(200,json.dumps({'exists':exists,'forbidden':forbidden,'invalid':invalid},ensure_ascii=False),'application/json; charset=utf-8')
        if p.path == '/login':
            return self.send(200, login_modal())
        if host == INVITE_HOST and p.path not in ('/query',) and not p.path.startswith('/register/'):
            return self.send(403,'forbidden','text/plain')
        if p.path == '/query':
            if host != INVITE_HOST: return self.send(404,'not found','text/plain')
            body='<div class="card register-card query-card"><h2 class="register-title">查询注册信息</h2><p class="register-slogan">请输入注册时使用的用户名和密码</p><form method="post" action="/query"><label>用户名</label><input name="username" required autocomplete="username"><label>密码</label><input name="password" type="password" required autocomplete="current-password"><button class="register-submit query-submit"><span class="query-submit-icon">🔎</span><span>查询信息</span></button></form><p class="query-security-hint"><span>🔒</span> 密码仅用于验证账号，不会被系统保存。</p></div><style>.query-card{max-width:520px;margin:28px auto}.query-submit{display:flex;align-items:center;justify-content:center;gap:9px;width:100%;min-height:50px;margin-top:22px;border:1px solid #9fb2ff;background:linear-gradient(135deg,#718cff 0%,#526fe0 48%,#3852b4 100%);box-shadow:0 10px 24px #3852b466, inset 0 1px 1px #ffffff55;font-size:16px;letter-spacing:.5px;transition:transform .18s,box-shadow .18s,filter .18s}.query-submit:hover{filter:brightness(1.1);transform:translateY(-2px);box-shadow:0 14px 30px #3852b488, inset 0 1px 1px #ffffff66}.query-submit:active{transform:translateY(0);box-shadow:0 6px 14px #3852b455}.query-submit-icon{font-size:18px;line-height:1}.query-security-hint{display:flex;align-items:center;justify-content:center;gap:6px;margin:18px auto 0;padding:11px 14px;border:1px solid #41619a;border-radius:10px;background:linear-gradient(135deg,#122b55,#0d1c38);color:#dce7ff;text-align:center;font-size:14px;font-weight:700;line-height:1.6;box-shadow:0 6px 16px #0003}.query-security-hint span{font-size:16px}</style>'
            return self.send(200,page(body,'查询注册信息',public=True))
        if p.path.startswith('/register/'):
            if host != INVITE_HOST: return self.send(404,'not found','text/plain')
            code=p.path.split('/')[-1]
            inv=db().execute('SELECT * FROM invites WHERE code=?',(code,)).fetchone()
            if not inv:
                return self.send(404,page('<div class="card empty-state"><strong>邀请链接不存在</strong><span class="muted">请检查链接是否完整，或联系管理员。</span></div>','邀请链接不存在', public=True))
            if inv['uses']>=inv['max_uses']:
                user = db().execute('SELECT * FROM users WHERE username=?',(inv['registered_username'],)).fetchone() if inv['registered_username'] else None
                if user and q.get('info',[''])[0] == '1':
                    return self.send(200, registered_info_page(inv, user))
                contact = setting('contact_url', '').strip()
                contact_button = '<button type="button" class="primary-link" onclick="openContactModal()">联系客服</button>'
                contact_modal = '<div id="contact-modal" class="contact-modal" role="dialog" aria-modal="true" aria-labelledby="contact-modal-title" onclick="if(event.target===this)closeContactModal()"><div class="contact-modal-card"><button type="button" class="contact-modal-close" aria-label="关闭" onclick="closeContactModal()">×</button><div class="contact-modal-icon">💬</div><h2 id="contact-modal-title">联系客服</h2><p>如需找回密码或咨询会员服务，请通过以下方式联系我们。</p>'+('<a class="contact-modal-link" href="'+esc(contact)+'" target="_blank" rel="noopener">打开客服入口 <span>↗</span></a>' if contact else '<div class="contact-modal-empty">暂未配置客服入口，请联系管理员。</div>')+'<button type="button" class="contact-modal-cancel" onclick="closeContactModal()">稍后处理</button></div></div><script>function openContactModal(){var m=document.getElementById("contact-modal");if(m){m.classList.add("show");document.body.style.overflow="hidden"}}function closeContactModal(){var m=document.getElementById("contact-modal");if(m){m.classList.remove("show");document.body.style.overflow=""}}document.addEventListener("keydown",function(e){if(e.key==="Escape")closeContactModal()})</script>'
                # 只要卡密记录带有注册用户名，就显示查询入口；不要因为本地映射暂时缺失而隐藏按钮。
                # 查询页仍会要求用户名和密码验证，不会直接暴露账号信息。
                info_button = '<a class="secondary-link" href="/query">查询注册信息</a>' if inv['registered_username'] else ''
                return self.send(200,page('<div class="card empty-state"><strong>该邀请链接已使用</strong><span class="muted">如需查看配置说明，请点击“查询注册信息”。</span><div class="success-actions">'+contact_button+info_button+'</div></div>'+contact_modal,'链接已使用', public=True))
            if inv['expires_at'] and inv['expires_at']<=now():
                return self.send(404,page('<div class="card empty-state"><strong>邀请链接已过期</strong><span class="muted">请联系管理员获取新的邀请链接。</span></div>','链接已过期', public=True))
            label=PLAN_LABELS.get(inv['plan'],inv['plan'])
            themes={'day':('plan-theme-day','☀','简洁轻盈'),'week':('plan-theme-week','⚡','活力清新'),'month':('plan-theme-month','●','稳定可靠'),'quarter':('plan-theme-quarter','◆','进阶紫韵'),'halfyear':('plan-theme-halfyear','♥','品质粉彩'),'year':('plan-theme-year','★','尊享金色')}
            theme,icon,slogan=themes.get(inv['plan'],('plan-theme-month','●','稳定可靠'))
            body='''<div class="card register-card '''+theme+'''"><div class="register-plan-icon">'''+icon+'''</div><h2 class="register-title">会员服务兑换</h2><p class="register-slogan">卡密已就绪：'''+esc(code)+'''（'''+esc(label)+'''·'''+str(PLAN_DAYS[inv['plan']])+'''天）</p><div class="redeem-tabs"><button type="button" class="redeem-tab active" id="tab-new" onclick="switchMode(\'new\')">● 我是新用户</button><button type="button" class="redeem-tab" id="tab-old" onclick="switchMode(\'old\')">○ 老用户充值</button></div><form method="post" id="redeem-form" onsubmit="return validateRedeem()"><input type="hidden" name="mode" id="redeem-mode" value="new"><div id="new-user-fields"><label>用户名</label><input name="username" id="register-username" required minlength="1" minlength="4" maxlength="8" pattern="[a-z0-9]{4,8}" placeholder="小写字母或数字，4-8位" autocomplete="off" oninput="checkRegisterUsername()"><span id="register-username-status" class="username-status" aria-live="polite"></span><label>设置密码</label><input name="password" id="new-password" type="password" required autocomplete="new-password"><label>确认密码</label><input name="confirm_password" id="confirm-password" type="password" required autocomplete="new-password"></div><div id="old-user-fields" style="display:none"><label>续费账号</label><input name="old_username" id="old-username" autocomplete="username" disabled><label>账户密码</label><input name="old_password" id="old-password" type="password" autocomplete="current-password" disabled></div><button class="register-submit" id="register-submit">立即开通</button></form></div><style>.redeem-tabs{display:grid;grid-template-columns:1fr 1fr;gap:8px;margin:16px 0}.redeem-tab{margin:0;background:#0b1428;border:1px solid var(--line);color:#d9e2ff;border-radius:10px}.redeem-tab.active{background:#213b78;border-color:var(--plan-color)}.username-status{display:block;font-size:12px;color:var(--muted);margin-top:5px}.username-status.available{color:#7ee7b7}.username-status.exists{color:#ff9eaa}</style><script>var registerTimer,registerAvailable=false;function switchMode(mode){var isNew=mode==='new';document.getElementById('redeem-mode').value=mode;document.getElementById('new-user-fields').style.display=isNew?'block':'none';document.getElementById('old-user-fields').style.display=isNew?'none':'block';document.getElementById('tab-new').classList.toggle('active',isNew);document.getElementById('tab-old').classList.toggle('active',!isNew);['register-username','new-password','confirm-password'].forEach(function(id){var x=document.getElementById(id);x.disabled=!isNew;x.required=isNew});['old-username','old-password'].forEach(function(id){var x=document.getElementById(id);x.disabled=isNew;x.required=!isNew});document.getElementById('register-submit').textContent=isNew?'立即开通':'立即延长时长'}function checkRegisterUsername(){clearTimeout(registerTimer);var i=document.getElementById('register-username'),s=document.getElementById('register-username-status'),v=i.value.trim();registerAvailable=false;s.textContent='';if(!v)return;s.textContent='检查中…';registerTimer=setTimeout(function(){fetch('/api/check-username?username='+encodeURIComponent(v)).then(function(r){return r.json()}).then(function(x){if(i.value.trim()!==v)return;registerAvailable=!x.exists&&!x.forbidden&&!x.invalid;s.className='username-status '+(registerAvailable?'available':'exists');s.textContent=x.invalid?'仅支持小写字母和数字，长度4-8位':(x.forbidden?'用户名不可用':(x.exists?'用户名已存在，请更换':'用户名可用'))}).catch(function(){registerAvailable=false;s.textContent='暂时无法检查'})},250)}function showDuplicatePopup(message){var old=document.getElementById('duplicate-popup');if(old)old.remove();var m=document.createElement('div');m.id='duplicate-popup';m.className='duplicate-popup';m.innerHTML='<div class="duplicate-popup-card"><div class="duplicate-popup-icon">!</div><h2>用户名已存在</h2><p></p><button type="button" class="duplicate-popup-button">返回修改用户名</button></div>';m.querySelector('p').textContent=message||'这个用户名已经被注册了，请更换一个新的用户名。';var close=function(){m.classList.remove('show');setTimeout(function(){m.remove()},200);var u=document.getElementById('register-username');if(u){u.focus();u.select()}};m.querySelector('button').onclick=close;m.addEventListener('click',function(e){if(e.target===m)close()});document.body.appendChild(m);requestAnimationFrame(function(){m.classList.add('show')})}function validateRedeem(){if(document.getElementById('redeem-mode').value==='old')return true;var u=document.getElementById('register-username'),p=document.getElementById('new-password'),c=document.getElementById('confirm-password');if(!registerAvailable){showDuplicatePopup('这个用户名已经被注册了，请更换一个新的用户名。');return false}if(p.value!==c.value){showDuplicatePopup('两次输入的密码不一致，请重新确认密码。');c.focus();return false}return true}</script>'''
            return self.send(200,page(body,'用户注册', public=True))
        if not self.auth():
            if p.path == '/': return self.send(200, login_modal())
            return self.deny()
        if p.path == '/logout':
            cookies = http.cookies.SimpleCookie(self.headers.get('Cookie', '')); sid=cookies.get('openlist_session')
            if sid: SESSIONS.discard(sid.value)
            return self.send(303,'',headers={'Location':'/login'})
        p=urlparse(self.path); q=parse_qs(p.query)
        if p.path == '/api/check-username':
            username=q.get('username',[''])[0].strip()
            exists=bool(username and db().execute('SELECT 1 FROM users WHERE username=?',(username,)).fetchone())
            forbidden=forbidden_username(username)
            invalid=invalid_username(username)
            return self.send(200,json.dumps({'exists':exists,'forbidden':forbidden,'invalid':invalid},ensure_ascii=False),'application/json; charset=utf-8')
        if p.path == '/':
            keyword=q.get('q',[''])[0].strip()
            plan_filter=q.get('plan',[''])[0].strip()
            if plan_filter not in ('total','day','week','month','quarter','halfyear','year','expired'): plan_filter='total'
            try: page_no=max(1,int(q.get('page',['1'])[0]))
            except (TypeError,ValueError): page_no=1
            page_size=20
            filters=[]; user_params=[]
            if keyword:
                filters.append('username LIKE ?'); user_params.append('%'+keyword+'%')
            if plan_filter!='total':
                if plan_filter=='expired': filters.append("expires_at IS NOT NULL AND expires_at<=?")
                else: filters.append('plan=?')
                user_params.append(now() if plan_filter=='expired' else plan_filter)
            user_where=' AND '.join(filters) if filters else '1=1'
            user_params=tuple(user_params)
            user_total=db().execute('SELECT COUNT(*) FROM users WHERE '+user_where,user_params).fetchone()[0]
            total_pages=max(1,(user_total+page_size-1)//page_size)
            page_no=min(page_no,total_pages)
            rows=db().execute('SELECT * FROM users WHERE '+user_where+' ORDER BY id DESC LIMIT ? OFFSET ?',(*user_params,page_size,(page_no-1)*page_size)).fetchall()
            all_users=db().execute('SELECT plan,expires_at FROM users').fetchall()
            summary=[('总用户',len(all_users),'total'),('天卡用户',sum(1 for r in all_users if r['plan']=='day'),'day'),('周卡用户',sum(1 for r in all_users if r['plan']=='week'),'week'),('月卡用户',sum(1 for r in all_users if r['plan']=='month'),'month'),('季卡用户',sum(1 for r in all_users if r['plan']=='quarter'),'quarter'),('半年卡用户',sum(1 for r in all_users if r['plan']=='halfyear'),'halfyear'),('年卡用户',sum(1 for r in all_users if r['plan']=='year'),'year'),('过期用户',sum(1 for r in all_users if r['expires_at'] and r['expires_at']<=now()),'expired')]
            summary_html='<div class="user-stats">'+''.join('<a class="user-stat user-stat-'+kind+(' active' if plan_filter==kind else '')+'" href="/?plan='+kind+'"><span class="user-stat-label">'+label+'</span><strong>'+str(value)+'</strong></a>' for label,value,kind in summary)+'</div>'
            out='<div class="dashboard-head"><div><h2>用户列表</h2><p class="hint">管理 WebDAV 用户、套餐与访问状态</p></div></div><div class="card">'+summary_html+'<div class="search-tools"><form class="search-form" method="get" action="/"><input name="q" value="'+esc(keyword)+'" placeholder="按用户名查询"><button>查询</button></form>'+('<a class="clear-search" href="/">清除</a>' if keyword else '')+'</div><div class="user-list">'
            if keyword: out += '<p class="hint search-result-count">查询“'+esc(keyword)+'”，找到 <strong>'+str(user_total)+'</strong> 个用户</p>'
            if not rows: out += '<div class="empty-state"><strong>没有找到匹配用户</strong><span class="muted">试试其他用户名关键词，或直接新增用户。</span><br><a href="/new">＋ 新增用户</a></div>'
            for r in rows:
                expired=bool(r['expires_at'] and r['expires_at']<=now())
                state='已停用' if r['disabled'] else ('已过期' if expired else '正常'); cls='bad' if r['disabled'] or expired else 'ok'; action='enable' if r['disabled'] else 'disable'; text='恢复' if r['disabled'] else '停用'
                plan={'day':'天卡','week':'周卡','month':'月卡','quarter':'季卡','halfyear':'半年','year':'年卡','custom':'自定义'}.get(r['plan'],r['plan']); plan_cls={'day':'plan-day','week':'plan-week','month':'plan-month','quarter':'plan-quarter','halfyear':'plan-halfyear','year':'plan-year','custom':'plan-custom'}.get(r['plan'],'plan-custom'); expiry=r['expires_at'] or '永久'
                renew = f'<button type="button" class="renew" onclick="openRenew({r["id"]},\'{esc(r["username"])}\')">续费</button>'
                out += f'''<div class="row" data-user-id="{r['id']}"><div class="user-main"><div class="user-meta"><div class="user-title-row"><div class="user-name"><b>{esc(r['username'])}</b></div><div class="user-badges"><span class="badge {cls}">{state}</span><span class="plan-badge {plan_cls}">{esc(plan)}</span></div></div><div class="muted user-info">注册日期：{esc(r['created'])}<br>到期日期：{esc(expiry)}</div></div></div><div class="actions">{renew}<form method="post" action="/user/{r['id']}/{action}"{' onsubmit="return openDisable(this)" data-user="'+esc(r['username'])+'"' if not r['disabled'] else ' onsubmit="return submitInlineAction(this)"'}><button class="{'ok' if r['disabled'] else 'pause'}">{text}</button></form><form method="post" action="/user/{r['id']}/delete" onsubmit="return openDelete(this)" data-user="{esc(r['username'])}"><button class="delete-btn">删除</button></form></div></div>'''
            if user_total>page_size:
                def page_url(n):
                    parts=(['q='+__import__('urllib.parse').parse.quote(keyword)] if keyword else [])+(['plan='+plan_filter] if plan_filter!='total' else [])+['page='+str(n)]
                    return '/?'+'&'.join(parts)
                pager='<div class="user-pager"><span>第 '+str(page_no)+' / '+str(total_pages)+' 页，共 '+str(user_total)+' 个用户</span><div>'
                if page_no>1: pager+='<a href="'+page_url(page_no-1)+'">‹ 上一页</a>'
                else: pager+='<span class="disabled">‹ 上一页</span>'
                for n in range(max(1,page_no-2),min(total_pages,page_no+2)+1):
                    pager+=('<a class="current" href="'+page_url(n)+'">'+str(n)+'</a>' if n==page_no else '<a href="'+page_url(n)+'">'+str(n)+'</a>')
                if page_no<total_pages: pager+='<a href="'+page_url(page_no+1)+'">下一页 ›</a>'
                else: pager+='<span class="disabled">下一页 ›</span>'
                pager+='</div></div>'
                out += pager
            out += '''</div></div><div id="disable-modal" class="modal-mask" style="display:none"><div class="modal-card delete-modal-card"><div class="delete-modal-icon">!</div><h2>确认停用用户？</h2><p id="disable-name" class="hint"></p><p class="delete-warning">停用后该用户将无法访问 WebDAV，但用户资料不会被删除，之后可以恢复。</p><form id="disable-form" method="post" onsubmit="return submitDisable(this)"><button class="pause">确认停用</button><button type="button" class="secondary-link" onclick="closeDisable()">取消</button></form></div></div><div id="renew-modal" class="modal-mask" style="display:none"><div class="modal-card"><div class="delete-modal-icon" style="background:#5a4420;color:#ffe09a">＋</div><h2>选择续费套餐</h2><p id="renew-name" class="hint"></p><p class="delete-warning" style="background:#2d281b;color:#ffe09a">续费时可选择与注册时一致的套餐类型。</p><form id="renew-form" method="post" onsubmit="return submitRenew(this)"><div class="plan-options" style="grid-template-columns:repeat(2,1fr)"><label class="plan-option plan-option-day"><input type="radio" name="plan" value="day"><span class="plan-icon">☀</span><span><b>天卡</b><small>+1 天</small></span></label><label class="plan-option plan-option-week"><input type="radio" name="plan" value="week"><span class="plan-icon">⚡</span><span><b>周卡</b><small>+7 天</small></span></label><label class="plan-option plan-option-month"><input type="radio" name="plan" value="month" checked><span class="plan-icon">●</span><span><b>月卡</b><small>+30 天</small></span></label><label class="plan-option plan-option-quarter"><input type="radio" name="plan" value="quarter"><span class="plan-icon">◆</span><span><b>季卡</b><small>+90 天</small></span></label><label class="plan-option plan-option-halfyear"><input type="radio" name="plan" value="halfyear"><span class="plan-icon">♥</span><span><b>半年</b><small>+180 天</small></span></label><label class="plan-option plan-option-year"><input type="radio" name="plan" value="year"><span class="plan-icon">★</span><span><b>年卡</b><small>+365 天</small></span></label></div><button type="submit" name="confirm" value="1" class="renew">确认续费</button><button type="button" class="secondary-link" onclick="closeRenew()">取消操作</button></form></div></div><div id="delete-modal" class="modal-mask" style="display:none"><div class="modal-card delete-modal-card"><div class="delete-modal-icon">!</div><h2>确认删除用户？</h2><p id="delete-name" class="hint"></p><p class="delete-warning">删除后无法恢复，同时会从 OpenList 中删除该用户。</p><form id="delete-form" method="post" onsubmit="return submitDelete(this)"><button class="delete-confirm">确认删除</button><button type="button" class="secondary-link" onclick="closeDelete()">取消</button></form></div></div><script>function postWithoutReload(form, done){var buttons=form.querySelectorAll('button');buttons.forEach(function(b){b.disabled=true;b.classList.add('is-busy')});fetch(form.action,{method:'POST',body:new URLSearchParams(new FormData(form)),credentials:'same-origin',headers:{'X-Requested-With':'XMLHttpRequest'}}).then(function(r){if(!r.ok)return r.text().then(function(t){throw new Error('HTTP '+r.status)});done()}).catch(function(e){buttons.forEach(function(b){b.disabled=false;b.classList.remove('is-busy')});alert('操作失败：'+(e.message||'请重试'))});return false}function submitInlineAction(form){return postWithoutReload(form,function(){var row=form.closest('.row'),badge=row&&row.querySelector('.badge'),button=form.querySelector('button');if(badge){badge.textContent='正常';badge.className='badge ok'}if(button){button.disabled=false;button.textContent='停用';button.className='pause'}form.action=form.action.replace('/enable','/disable');form.setAttribute('onsubmit','return openDisable(this)');form.dataset.user=row.querySelector('.user-name').textContent.trim();showActionSuccess('用户已恢复','该用户现在可以正常访问。')})}function openDisable(form){document.getElementById('disable-name').textContent='用户：'+form.dataset.user;document.getElementById('disable-form').action=form.action;document.getElementById('disable-form').dataset.rowId=form.closest('.row').querySelector('.user-name').textContent;document.getElementById('disable-modal').style.display='flex';return false}function closeDisable(){document.getElementById('disable-modal').style.display='none'}function submitDisable(form){return postWithoutReload(form,function(){var name=document.getElementById('disable-form').dataset.rowId;var row=[].find.call(document.querySelectorAll('.row'),function(x){return x.querySelector('.user-name').textContent===name}),badge=row&&row.querySelector('.badge'),actionForm=row&&row.querySelector('.actions form[action*="/user/"]'),button=actionForm&&actionForm.querySelector('button');if(badge){badge.textContent='已停用';badge.className='badge bad'}if(button){button.disabled=false;button.textContent='恢复';button.className='ok'}if(actionForm){actionForm.action=actionForm.action.replace('/disable','/enable');actionForm.setAttribute('onsubmit','return submitInlineAction(this)')}closeDisable();showActionSuccess('用户已停用','该用户已停止访问，但资料仍保留。')})}function showActionSuccess(title,message,reload){var old=document.getElementById('action-success-modal');if(old)old.remove();var m=document.createElement('div');m.id='action-success-modal';m.className='modal-mask';var box=document.createElement('div');box.className='modal-card delete-modal-card renew-success-card';box.innerHTML='<div class="delete-modal-icon renew-success-icon"><svg viewBox="0 0 64 64" aria-hidden="true"><circle cx="32" cy="32" r="29" fill="none" stroke="currentColor" stroke-width="4" opacity=".28"/><path d="M18 33.5 27 42l19-21" fill="none" stroke="currentColor" stroke-width="6" stroke-linecap="round" stroke-linejoin="round"/></svg></div><h2></h2><p class="hint" style="font-size:16px;color:#dbe7ff"></p>';var h=box.querySelector('h2');h.textContent=title;box.querySelector('p').textContent=message;var b=document.createElement('button');b.className='ok';b.style='width:100%;margin-top:22px';b.textContent='确定';b.onclick=function(){if(reload)window.location.reload();else m.remove()};box.appendChild(b);m.appendChild(box);document.body.appendChild(m)}function showRenewSuccess(plan){var old=document.getElementById('renew-success-modal');if(old)old.remove();var m=document.createElement('div');m.id='renew-success-modal';m.className='modal-mask';m.innerHTML='<div class="modal-card delete-modal-card renew-success-card"><div class="delete-modal-icon renew-success-icon"><svg viewBox="0 0 64 64" aria-hidden="true"><circle cx="32" cy="32" r="29" fill="none" stroke="currentColor" stroke-width="4" opacity=".28"/><path d="M18 33.5 27 42l19-21" fill="none" stroke="currentColor" stroke-width="6" stroke-linecap="round" stroke-linejoin="round"/></svg></div><h2>续费成功</h2><p class="hint" style="font-size:16px;color:#dbe7ff">'+plan+'续费成功</p><button class="ok" style="width:100%;margin-top:22px" onclick="window.location.reload()">确定</button></div></div>';document.body.appendChild(m)}function submitRenew(form){var button=form.querySelector('button[type=submit]');var selected=form.querySelector('input[name=plan]:checked');var names={day:'天卡',week:'周卡',month:'月卡',quarter:'季卡',halfyear:'半年',year:'年卡'};var plan=names[selected?selected.value:'month']||'套餐';if(button){button.disabled=true;button.textContent='续费中…'}return postWithoutReload(form,function(){closeRenew();showRenewSuccess(plan)})}function openRenew(id,name){var current=document.querySelector('.row[data-user-id="'+id+'"] .plan-badge');var selected=current&&({'天卡':'day','周卡':'week','月卡':'month','季卡':'quarter','半年':'halfyear','年卡':'year'}[current.textContent.trim()]||'month');document.querySelectorAll('#renew-form input[name=plan]').forEach(function(x){x.checked=x.value===selected});document.getElementById('renew-name').textContent='用户：'+name;document.getElementById('renew-form').action='/user/'+id+'/renew';document.getElementById('renew-form').dataset.userId=id;var rows=document.querySelectorAll('.row');for(var i=0;i<rows.length;i++){if(rows[i].querySelector('.renew')&&rows[i].querySelector('.renew').getAttribute('onclick').indexOf('openRenew('+id+',')===0){rows[i].setAttribute('data-user-id',id);break}}document.getElementById('renew-modal').style.display='flex'}function closeRenew(){document.getElementById('renew-modal').style.display='none'}function submitDelete(form){return postWithoutReload(form,function(){showActionSuccess('用户已删除','用户资料已从系统中移除。',true)})}function openDelete(form){document.getElementById('delete-name').textContent='用户：'+form.dataset.user;document.getElementById('delete-form').action=form.action;document.getElementById('delete-modal').style.display='flex';return false}function closeDelete(){document.getElementById('delete-modal').style.display='none'}</script>'''
            return self.send(200,page(out))
        if p.path == '/new':
            default=setting('default_path','/')
            return self.send(200, page('''<div class="card"><h2>新增用户</h2><p class="hint">新用户固定为普通用户，仅 WebDAV 读取。</p><form method="post" action="/new"><label class="username-label">用户名 <span id="username-status" class="username-status" aria-live="polite"></span></label><div class="username-field"><input name="username" id="username" required autocomplete="off" oninput="checkUsername()"></div><label>OpenList 目录</label><p class="hint">无特殊需求请保持默认 /</p><input name="base_path" value="%s" placeholder="/"><label>初始密码（留空自动生成）</label><input name="password"><label>套餐类型</label><div class="plan-options"><label class="plan-option plan-option-day"><input type="radio" name="plan" value="day" checked><span class="plan-icon">☀</span><span><b>天卡</b><small>有效期 1 天</small></span></label><label class="plan-option plan-option-week"><input type="radio" name="plan" value="week"><span class="plan-icon">⚡</span><span><b>周卡</b><small>有效期 7 天</small></span></label><label class="plan-option plan-option-month"><input type="radio" name="plan" value="month"><span class="plan-icon">●</span><span><b>月卡</b><small>有效期 30 天</small></span></label><label class="plan-option plan-option-quarter"><input type="radio" name="plan" value="quarter"><span class="plan-icon">◆</span><span><b>季卡</b><small>有效期 90 天</small></span></label><label class="plan-option plan-option-halfyear"><input type="radio" name="plan" value="halfyear"><span class="plan-icon">♥</span><span><b>半年</b><small>有效期 180 天</small></span></label><label class="plan-option plan-option-year"><input type="radio" name="plan" value="year"><span class="plan-icon">★</span><span><b>年卡</b><small>有效期 365 天</small></span></label></div><button>创建用户</button></form></div><script>function checkUsername(){clearTimeout(window.usernameTimer);var i=document.getElementById('username'),s=document.getElementById('username-status'),v=i.value.trim();s.className='username-status';s.textContent='';if(!v)return;window.usernameTimer=setTimeout(function(){fetch('/api/check-username?username='+encodeURIComponent(v)).then(function(r){return r.json()}).then(function(x){if(i.value.trim()!==v)return;s.className='username-status '+((x.exists||x.forbidden||x.invalid)?'exists':'available');s.textContent=x.invalid?'仅支持小写英文字母和数字':(x.forbidden?'该用户名包含管理员相关词语，不允许使用':(x.exists?'用户名已存在，请更换':'用户名可用'))}).catch(function(){})},250)}function toggleExpiry(){var x=document.querySelector('input[name=plan]:checked');document.getElementById('expiry').style.display=x&&x.value==='custom'?'block':'none'}toggleExpiry()</script>''' % esc(default), '新增用户'))
        if p.path == '/invites':
            q=q or {}
            keyword=q.get('q',[''])[0].strip()
            plan_filter=q.get('plan',[''])[0].strip()
            date_from=q.get('date_from',[''])[0].strip()
            date_to=q.get('date_to',[''])[0].strip()
            where=['archived=0','uses>=max_uses']
            params=[]
            if keyword:
                where.append('(registered_username LIKE ? OR code LIKE ?)'); params += [f'%{keyword}%', f'%{keyword}%']
            if plan_filter in PLAN_LABELS:
                where.append('plan=?'); params.append(plan_filter)
            if date_from:
                where.append('used_at>=?'); params.append(date_from+' 00:00:00')
            if date_to:
                where.append('used_at<=?'); params.append(date_to+' 23:59:59')
            used=db().execute('SELECT * FROM invites WHERE '+' AND '.join(where)+' ORDER BY used_at DESC,id DESC',params).fetchall()
            total=db().execute('SELECT COUNT(*) FROM invites WHERE archived=0 AND uses>=max_uses').fetchone()[0]
            pending=db().execute('SELECT * FROM invites WHERE archived=0 AND uses=0 AND exported=0 ORDER BY id DESC').fetchall()
            exported_unused=db().execute('SELECT * FROM invites WHERE archived=0 AND uses=0 AND exported=1 ORDER BY exported_at DESC,id DESC').fetchall()
            def plan_tag(r):
                return '<span class="invite-plan invite-plan-'+esc(r['plan'])+'">'+esc(PLAN_LABELS.get(r['plan'],r['plan']))+'</span>'
            def short_link(r):
                url='https://'+INVITE_HOST+'/register/'+r['code']
                return '<span class="invite-link" title="'+esc(url)+'">...'+esc(INVITE_HOST)+'/.../'+esc(r['code'][:8])+'</span><button type="button" class="icon-copy" title="复制链接" aria-label="复制链接" data-url="'+esc(url)+'" onclick="copyInvite(this)">📋</button>'
            used_groups=[]
            for plan in PLAN_LABELS:
                group=[r for r in used if r['plan']==plan]
                if not group: continue
                group_rows=[]
                for r in group:
                    user=r['registered_username'] or '—'
                    user_html='<a class="invite-user" href="/?q='+__import__('urllib.parse').parse.quote(user)+'">'+esc(user)+'</a>' if r['registered_username'] else '—'
                    query_url='https://'+INVITE_HOST+'/register/'+r['code']
                    group_rows.append('<tr><td><input type="checkbox" name="ids" value="'+str(r['id'])+'"></td><td>'+short_link(r)+'</td><td><span class="invite-status used">已使用</span></td><td>'+user_html+'</td><td>'+esc(r['used_at'] or '—')+'</td><td><a class="detail-link" href="'+esc(query_url)+'" target="_blank" rel="noopener">查询信息</a></td></tr>')
                used_groups.append('<details class="used-plan-fold" style="margin:10px 0;border:1px solid #2f4675;border-radius:14px;background:linear-gradient(135deg,#122342,#0c172d);overflow:hidden"><summary style="display:flex;align-items:center;justify-content:space-between;gap:12px;padding:14px 16px;cursor:pointer;list-style:none;color:#dce7ff;font-weight:700"><span style="display:flex;align-items:center;gap:9px"><span style="display:grid;place-items:center;width:28px;height:28px;border-radius:9px;background:#263d79;color:#aebeff">◆</span>'+esc(PLAN_LABELS[plan])+'</span><span style="min-width:38px;padding:4px 10px;text-align:center;border:1px solid #4867a5;border-radius:999px;background:#172f5b;color:#bcd0ff;font-size:12px">'+str(len(group))+' 张</span></summary><div class="table-wrap" style="margin:12px 16px 16px"><table class="invite-table"><thead><tr><th><input type="checkbox" onclick="toggleUsedPlan(this)"></th><th>邀请链接 / 邀请码</th><th>状态</th><th>注册用户名</th><th>使用时间</th><th>操作</th></tr></thead><tbody>'+''.join(group_rows)+'</tbody></table></div></details>')
            table=''.join(used_groups) or '<div class="table-empty">没有符合条件的已使用卡密</div>'
            plan_options='<option value="">全部卡种</option>'+''.join('<option value="'+k+'" '+('selected' if k==plan_filter else '')+'>'+v+'</option>' for k,v in PLAN_LABELS.items())
            generate_options=''.join('<option value="'+k+'">'+v+'</option>' for k,v in PLAN_LABELS.items())
            pending_rows=''.join('<tr><td><input type="checkbox" name="ids" value="'+str(r['id'])+'"></td><td>'+plan_tag(r)+'</td><td><span class="invite-link">'+esc(r['code'])+'</span></td><td><span class="invite-status unused">未导出</span></td><td>'+esc(r['created'])+'</td></tr>' for r in pending) or '<tr><td colspan="5" class="table-empty">暂无待导出的卡密，请先生成。</td></tr>'
            pending_table='<form method="post" action="/invites/export" onsubmit="return checkExport()"><div class="dashboard-head invite-used-title"><div><h3>待导出的卡密</h3><p class="hint">只有这里的卡密可以导出；导出后将进入“已导出”状态，不再允许重复导出。</p></div><button class="export-btn" type="submit">导出选中卡密（Excel 文本）</button></div><div class="table-wrap"><table class="invite-table pending-table"><thead><tr><th><input type="checkbox" onclick="togglePending(this)"></th><th>卡种</th><th>卡密</th><th>状态</th><th>生成时间</th></tr></thead><tbody>'+pending_rows+'</tbody></table></div><div class="table-footer"><span class="hint">导出格式为制表符文本，可直接粘贴到 Excel。</span></div></form>'
            exported_unused_groups=[]
            for plan in PLAN_LABELS:
                group=[r for r in exported_unused if r['plan']==plan]
                if not group: continue
                group_rows=''.join('<tr><td><input type="checkbox" name="ids" value="'+str(r['id'])+'"></td><td><span class="invite-link">'+esc(r['code'])+'</span></td><td><span class="invite-status used">已导出·未使用</span></td><td>'+esc(r['exported_at'] or '—')+'</td></tr>' for r in group)
                exported_unused_groups.append('<details class="exported-unused-plan" style="margin:10px 0;border:1px solid #2f4675;border-radius:14px;background:linear-gradient(135deg,#122342,#0c172d);overflow:hidden"><summary style="display:flex;align-items:center;justify-content:space-between;gap:12px;padding:14px 16px;cursor:pointer;list-style:none;color:#dce7ff;font-weight:700"><span style="display:flex;align-items:center;gap:9px"><span style="display:grid;place-items:center;width:28px;height:28px;border-radius:9px;background:#263d79;color:#aebeff">◆</span>'+esc(PLAN_LABELS[plan])+'</span><span style="min-width:38px;padding:4px 10px;text-align:center;border:1px solid #4867a5;border-radius:999px;background:#172f5b;color:#bcd0ff;font-size:12px">'+str(len(group))+' 张</span></summary><form method="post" action="/invites/redownload" onsubmit="return redownloadUnused(this)"><div style="display:flex;justify-content:flex-end;padding:12px 16px 0"><button class="export-btn" type="submit">重新下载选中'+esc(PLAN_LABELS[plan])+'卡密</button></div><div class="table-wrap" style="margin:12px 16px 16px"><table class="invite-table exported-unused-table"><thead><tr><th><input type="checkbox" onclick="toggleExportedUnused(this)"></th><th>卡密</th><th>状态</th><th>上次导出时间</th></tr></thead><tbody>'+group_rows+'</tbody></table></div></form></details>')
            exported_unused_table='<details class="exported-unused-fold" style="margin:22px 0;border:1px solid #36558f;border-radius:18px;background:linear-gradient(145deg,rgba(20,40,76,.92),rgba(12,24,48,.96));box-shadow:0 12px 32px #0003;overflow:hidden"><summary style="display:flex;align-items:center;justify-content:space-between;gap:14px;padding:18px 20px;cursor:pointer;list-style:none;color:#f3f6ff;font-size:17px;font-weight:800;letter-spacing:.2px;background:linear-gradient(135deg,#172f5b,#102342)"><span>📦 已导出但未使用的卡密</span><span style="display:inline-flex;align-items:center;justify-content:center;min-width:48px;height:30px;padding:0 12px;border:1px solid #6f8cff;border-radius:999px;background:#213b78;color:#dce7ff;font-size:13px">'+str(len(exported_unused))+' 张</span></summary><div class="exported-unused-content" style="padding:18px 20px 20px"><p class="hint" style="margin:0 0 16px;padding:11px 13px;border-left:3px solid #6f8cff;border-radius:8px;background:#0b1a35">按套餐分类展示。文件丢失时，可展开对应套餐重新下载；不会改变卡密状态。</p>'+''.join(exported_unused_groups)+'</div></details>'
            body = """<div class="invite-page"><div class="dashboard-head"><div><h2>邀请注册卡密</h2><p class="hint">新增卡密后可复制邀请链接发送给客户；已使用卡密会自动进入下方记录。</p></div><span class="invite-count">当前 %s / %s 条</span></div><form class="invite-generate-bar" method="post" action="/invites"><label>卡种<select name="plan">%s</select></label><label>生成数量<input type="number" name="quantity" value="1" min="1" max="100" required></label><button type="submit">＋ 生成卡密</button></form>%s%s<div class="dashboard-head invite-used-title"><div><h3>已使用卡密</h3><p class="hint">已使用链接保留在列表中，归档后不再显示，避免来源丢失。</p></div></div><form class="invite-filters" method="get" action="/invites"><input name="q" value="%s" placeholder="搜索用户名或邀请码"><select name="plan">%s</select><label>核销日期 <input type="date" name="date_from" value="%s"></label><span class="date-sep">至</span><label><input type="date" name="date_to" value="%s"></label><button type="submit">检索</button><a href="/invites">重置</a></form><form method="post" action="/invites/archive" onsubmit="return confirm('确定将选中的卡密放入历史归档吗？归档后不会删除数据。')"><div class="used-cards-fold"><div class="dashboard-head invite-used-title"><div><h3>已使用卡密</h3><p class="hint">按套餐分类折叠展示；仍支持卡密、用户名和日期检索。</p></div></div>%s</div><div class="table-footer"><button class="archive-btn" type="submit">放入历史归档</button><button class="export-btn" type="button" onclick="redownloadExported()">重新下载选中卡密</button><span class="hint">重新下载不会改变卡密状态。</span></div></form><script>%s</script></div>""" % (len(used), total, generate_options, pending_table, exported_unused_table, esc(keyword), plan_options, esc(date_from), esc(date_to), table, """function togglePending(x){document.querySelectorAll('.pending-table input[name=ids]').forEach(function(i){i.checked=x.checked})}function toggleUsedPlan(x){var table=x.closest('table');table.querySelectorAll('input[name=ids]').forEach(function(i){i.checked=x.checked})}function toggleExportedUnused(x){var table=x.closest('table');table.querySelectorAll('input[name=ids]').forEach(function(i){i.checked=x.checked})}function redownloadUnused(form){var n=form.querySelectorAll('input[name=ids]:checked').length;if(!n){alert('请先选择已导出但未使用的卡密');return false}return true}function closeExportModal(){var m=document.getElementById('export-confirm-modal');if(m)m.remove()}function checkExport(){var n=document.querySelectorAll('.pending-table input[name=ids]:checked').length;if(!n){showExportNotice('请先选择卡密','请至少勾选一条待导出的卡密，再进行导出。','知道了',false);return false}showExportNotice('确认导出卡密','本次将导出 '+n+' 条卡密。导出后会标记为“已导出”，之后不能再次复制或导出，请确认已准备好保存 Excel 文件。','确认导出',true);return false}function showExportNotice(title,msg,ok,submit){var old=document.getElementById('export-confirm-modal');if(old)old.remove();var m=document.createElement('div');m.id='export-confirm-modal';m.className='modal-mask export-confirm-mask';var c=document.createElement('div');c.className='modal-card export-confirm-card';c.innerHTML='<div class="export-confirm-icon">📊</div><h2></h2><p class="export-confirm-message"></p><div class="export-confirm-actions"><button type="button" class="secondary-link" onclick="closeExportModal()">取消</button><button type="button" class="export-confirm-ok"></button></div>';c.querySelector('h2').textContent=title;c.querySelector('.export-confirm-message').textContent=msg;var button=c.querySelector('.export-confirm-ok');button.textContent=ok;button.onclick=function(){if(submit){closeExportModal();var f=document.querySelector('form[action="/invites/export"]');f.removeAttribute('onsubmit');f.submit();setTimeout(function(){window.location.reload()},700)}else closeExportModal()};m.appendChild(c);document.body.appendChild(m)}function toggleAll(x){document.querySelectorAll('input[name=ids]').forEach(function(i){i.checked=x.checked})}function redownloadExported(){var ids=[].map.call(document.querySelectorAll('form[action="/invites/archive"] input[name=ids]:checked'),function(i){return i.value});if(!ids.length){alert('请先选择已导出的卡密');return}var f=document.createElement('form');f.method='POST';f.action='/invites/redownload';f.style.display='none';var i=document.createElement('input');i.name='ids';i.value=ids.join(',');f.appendChild(i);document.body.appendChild(f);f.submit();setTimeout(function(){f.remove()},1000)}function copyInvite(b){var u=b.dataset.url;function done(){b.textContent='✓';setTimeout(function(){b.textContent='📋'},1200)}if(navigator.clipboard){navigator.clipboard.writeText(u).then(done)}else{var x=document.createElement('textarea');x.value=u;document.body.appendChild(x);x.select();document.execCommand('copy');x.remove();done()}}""")
            return self.send(200,page(body,'邀请注册'))
        if p.path == '/settings':
            msg='<p class="hint">后台登录账号密码与 OpenList 账号密码分开。OpenList 信息只在这里配置。</p>'
            body='<div class="card"><h2>系统设置</h2>'+msg+'<form method="post" action="/settings">'
            body+='<label>OpenList 地址</label><input name="openlist_url" value="'+esc(setting('openlist_url'))+'" required>'
            body+='<label>OpenList 管理员账号</label><input name="openlist_user" value="'+esc(setting('openlist_user'))+'" required>'
            body+='<label>OpenList 管理员密码</label><input type="password" name="openlist_pass" value="***" autocomplete="new-password" required><p class="hint">密码已隐藏；如不修改请保持 *** 不变。</p>'
            body+='<label>新增用户默认目录</label><input name="default_path" value="'+esc(setting('default_path','/'))+'" required>'
            body+='<label>客服链接（可选）</label><input name="contact_url" value="'+esc(setting('contact_url'))+'" placeholder="https://..."><p class="hint">已使用邀请链接中的“联系客服”按钮将打开此地址。</p>'
            body+='<label>后台登录账号</label><input name="local_user" value="'+esc(setting('local_user'))+'" required>'
            body+='<label>修改后台密码（留空不修改）</label><input type="password" name="local_pass" value="" autocomplete="new-password">'
            body+='<button>保存</button></form></div>'
            return self.send(200,page(body,'系统设置'))
        return self.send(404,'not found','text/plain')
    def body(self):
        n=int(self.headers.get('Content-Length','0')); q=parse_qs(self.rfile.read(n).decode()); out={k:v[0].strip() for k,v in q.items()}; out['ids']=','.join(q.get('ids',[])); return out
    def do_POST(self):
        path=urlparse(self.path).path
        # Login and public invite redemption may call OpenList; don't hold the
        # global admin lock during network I/O. Serialize redemptions separately.
        if path == '/login':
            return self._do_POST()
        if path.startswith('/register/'):
            with REGISTER_LOCK:
                return self._do_POST()
        with DB_LOCK:
            return self._do_POST()

    def _do_POST(self):
        p=urlparse(self.path); d=self.body(); c=db(); host=self.headers.get('Host','').split(':',1)[0].lower()
        # Public invite redemption is serialized by REGISTER_LOCK, not DB_LOCK,
        # so slow OpenList calls cannot stall the admin UI.
        try:
            if p.path == '/setup':
                if not setup_required(): return self.send(409, 'Setup already completed', 'text/plain')
                username=d.get('username','').strip(); passwd=d.get('password',''); confirm=d.get('confirm_password','')
                if len(username)<4 or len(username)>64: return self.send(400, setup_page('账号长度需为 4-64 位'))
                if len(passwd)<12: return self.send(400, setup_page('密码至少需要 12 位'))
                if passwd != confirm: return self.send(400, setup_page('两次输入的密码不一致'))
                save_setting('local_user', username)
                save_setting('local_pass_hash', local_hash(passwd))
                sid=secrets.token_urlsafe(32); SESSIONS.add(sid)
                return self.send(303,'',headers={'Location':'/','Set-Cookie':'openlist_session='+sid+'; Path=/; HttpOnly; SameSite=Lax'})
            if p.path == '/login':
                if not check_local_login(d.get('username',''), d.get('password','')):
                    return self.send(401, login_modal('请输入正确的账号和密码'))
                sid=secrets.token_urlsafe(32); SESSIONS.add(sid)
                self.send(303,'',headers={'Location':'/','Set-Cookie':'openlist_session='+sid+'; Path=/; HttpOnly; SameSite=Lax'}); return
            if host == INVITE_HOST and p.path not in ('/query',) and not p.path.startswith('/register/'): return self.send(403,'forbidden','text/plain')
            if not self.auth() and not (host == INVITE_HOST and (p.path == '/query' or p.path.startswith('/register/'))): return self.deny()
            if p.path == '/query':
                username=d.get('username','').strip(); passwd=d.get('password','')
                if not username or not passwd: raise RuntimeError('请输入用户名和密码')
                user=c.execute('SELECT * FROM users WHERE username=?',(username,)).fetchone()
                if not user: raise RuntimeError('用户名或密码错误')
                base_url=setting('openlist_url').rstrip('/')
                req=urllib.request.Request(base_url+'/api/auth/login',data=json.dumps({'username':username,'password':passwd}).encode(),method='POST',headers={'Content-Type':'application/json'})
                try:
                    with urllib.request.urlopen(req,timeout=15) as resp: result=json.loads(resp.read().decode('utf-8','replace'))
                except Exception: raise RuntimeError('用户名或密码错误')
                if result.get('code') not in (None,0,200) or not (result.get('data',{}).get('token') or result.get('token')): raise RuntimeError('用户名或密码错误')
                return self.send(200,registered_info_page(None,user))
            if p.path in ('/invites/export','/invites/redownload'):
                ids=[int(x) for x in d.get('ids','').split(',') if x.isdigit()]
                if not ids: raise RuntimeError('未选择卡密')
                placeholders=','.join('?' for _ in ids)
                if p.path == '/invites/export':
                    rows=c.execute('SELECT * FROM invites WHERE id IN ('+placeholders+') AND uses=0 AND exported=0 AND archived=0 ORDER BY id',ids).fetchall()
                    if len(rows)!=len(set(ids)): raise RuntimeError('部分卡密已导出或不可用，请刷新后重试')
                else:
                    rows=c.execute('SELECT * FROM invites WHERE id IN ('+placeholders+') AND exported=1 AND archived=0 ORDER BY id',ids).fetchall()
                    if len(rows)!=len(set(ids)): raise RuntimeError('部分卡密未导出或已归档，请刷新后重试')
                exported_at=now()
                lines=['卡种\t卡密\t邀请链接\t生成时间']
                for r in rows: lines.append('%s\t%s\thttps://%s/register/%s\t%s' % (PLAN_LABELS.get(r['plan'],r['plan']),r['code'],INVITE_HOST,r['code'],r['created']))
                if p.path == '/invites/export':
                    c.executemany('UPDATE invites SET exported=1,exported_at=? WHERE id=?',[(exported_at,r['id']) for r in rows]); c.commit()
                data=('\n'.join(lines)+'\n').encode('utf-8')
                self.send_response(200); self.send_header('Content-Type','text/tab-separated-values; charset=utf-8'); self.send_header('Content-Disposition','attachment; filename=invite-cards-%s.xls' % exported_at.replace(' ','-').replace(':','')); self.send_header('Content-Length',str(len(data))); self.end_headers(); self.wfile.write(data); return
            if p.path in ('/invites/archive','/invites/delete'):
                raw=d.get('ids','')
                ids=[int(x) for x in raw.split(',') if x.isdigit()]
                if ids: c.executemany('UPDATE invites SET archived=1 WHERE id=? AND uses>=max_uses',[(i,) for i in ids]); c.commit()
                return self.done('/invites')
            if p.path == '/invites':
                plan=d.get('plan','week')
                if plan not in PLAN_DAYS: raise RuntimeError('套餐类型无效')
                try: quantity=int(d.get('quantity','1'))
                except ValueError: raise RuntimeError('生成数量无效')
                if quantity < 1 or quantity > 100: raise RuntimeError('生成数量需在 1 到 100 之间')
                for _ in range(quantity):
                    code=secrets.token_urlsafe(12)
                    c.execute('INSERT INTO invites(code,plan,uses,max_uses,created) VALUES(?,?,?,?,?)',(code,plan,0,1,now()))
                c.commit()
                return self.send(303,'',headers={'Location':'/invites'})
            if p.path == '/settings':
                for k in ('openlist_url','openlist_user','default_path','contact_url'): save_setting(k,d.get(k,''))
                if d.get('openlist_pass','') and d.get('openlist_pass') != '***': save_setting('openlist_pass',d.get('openlist_pass'))
                password_changed = bool(d.get('local_pass'))
                if d.get('local_user'): save_setting('local_user', d.get('local_user'))
                if password_changed: save_setting('local_pass_hash', local_hash(d.get('local_pass')))
                save_setting('openlist_token', '')
                if password_changed:
                    SESSIONS.clear()
                    return self.send(303,'',headers={'Location':'/login','Set-Cookie':'openlist_session=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax'})
                return self.send(303,'',headers={'Location':'/'})
            if p.path.startswith('/register/'):
                if self.headers.get('Host','').split(':',1)[0].lower() != INVITE_HOST: return self.send(404,'not found','text/plain')
                code=p.path.split('/')[-1]
                # REGISTER_LOCK serializes single-use redemption; this handler
                # intentionally does not hold DB_LOCK during remote OpenList calls.
                inv=c.execute('SELECT * FROM invites WHERE code=?',(code,)).fetchone()
                if not inv: raise RuntimeError('邀请链接不存在')
                if inv['uses']>=inv['max_uses']: raise RuntimeError('该邀请链接已使用，请返回链接查询注册信息')
                if inv['expires_at'] and inv['expires_at']<=now(): raise RuntimeError('邀请链接已过期')
                mode=d.get('mode','new'); plan=inv['plan']; days=PLAN_DAYS.get(plan)
                inv_id=inv['id']
                inv_code=inv['code']
                if mode=='old':
                    # Capture local user before remote I/O. No DB_LOCK is held here.
                    username=d.get('old_username','').strip()
                    local_row=c.execute('SELECT * FROM users WHERE username=?',(username,)).fetchone() if username else None
                    local=dict(local_row) if local_row else None
                    if not local: raise RuntimeError('账户不存在，请重新注册')
                if not days: raise RuntimeError('卡密套餐无效')
                if mode=='old':
                    username=d.get('old_username','').strip(); pwd=d.get('old_password','')
                    if not username or not pwd: raise RuntimeError('请输入原账号和账户密码')
                    if not local or local['username'] != username: raise RuntimeError('账户不存在，请重新注册')
                    # Check by username first. If found, preserve existing credentials
                    # and only authenticate the supplied current password. If deleted,
                    # recreate with the submitted password (local system does not store it).
                    openlist_user=find_openlist_user(username)
                    base_url=setting('openlist_url').rstrip('/')
                    if not base_url: raise RuntimeError('系统尚未配置 OpenList 地址')
                    if openlist_user:
                        verify_req=urllib.request.Request(base_url+'/api/auth/login',data=json.dumps({'username':username,'password':pwd}).encode(),method='POST',headers={'Content-Type':'application/json'})
                        try:
                            with urllib.request.urlopen(verify_req,timeout=15) as verify_resp:
                                verify_result=json.loads(verify_resp.read().decode('utf-8','replace'))
                            if not (verify_result.get('data',{}).get('token') or verify_result.get('token')): raise RuntimeError('账号或密码错误')
                        except (urllib.error.HTTPError,urllib.error.URLError,ValueError):
                            raise RuntimeError('账号或密码错误')
                        if verify_result.get('code') not in (None,0,200): raise RuntimeError('账号或密码错误')
                    else:
                        # Account absent remotely: the password entered by the user
                        # becomes the password of the recreated OpenList account.
                        created=api('POST','/api/admin/user/create',{'username':username,'password':pwd,'base_path':local['base_path'],'role':0,'permission':256,'disabled':False})
                        user_id=result_user_id(created)
                        if user_id is None:
                            openlist_user=find_openlist_user(username)
                            if not openlist_user or openlist_user.get('id') is None:
                                raise RuntimeError('OpenList 用户已创建，但无法获取用户 ID，请稍后联系管理员')
                            user_id=openlist_user['id']
                        openlist_user={'id':user_id,'username':username}
                    current=datetime.strptime(local['expires_at'],'%Y-%m-%d %H:%M:%S') if local['expires_at'] else datetime.now()
                    expiry=(max(current,datetime.now())+timedelta(days=days)).strftime('%Y-%m-%d %H:%M:%S')
                    total_days=max(1,int((datetime.strptime(expiry,'%Y-%m-%d %H:%M:%S')-datetime.strptime(local['created'],'%Y-%m-%d %H:%M:%S')).total_seconds()/86400))
                    display_plan=plan_for_duration_days(total_days)
                    if local['disabled'] or expired(local['expires_at']) or (local['openlist_id'] and str(local['openlist_id']) != str(openlist_user.get('id'))):
                        user_id=openlist_user.get('id')
                        if not user_id: raise RuntimeError('账户不存在，请重新注册')
                        api('POST','/api/admin/user/update',{'id':user_id,'username':local['username'],'base_path':local['base_path'],'role':0,'permission':256,'disabled':False})
                        # Reacquire lock only for the atomic local commit. The invite
                    # lock held by do_POST prevents duplicate redemption in-process.
                    with DB_LOCK:
                        c.execute('BEGIN IMMEDIATE')
                        current_inv=c.execute('SELECT uses,max_uses FROM invites WHERE id=?',(inv_id,)).fetchone()
                        if not current_inv or current_inv['uses']>=current_inv['max_uses']:
                            c.rollback(); raise RuntimeError('卡密已被使用')
                        c.execute('UPDATE users SET openlist_id=?,disabled=0,plan=?,expires_at=?,updated=? WHERE id=?',(user_id,display_plan,expiry,now(),local['id']))
                        c.execute('UPDATE invites SET uses=uses+1,used_at=?,registered_username=? WHERE id=? AND uses<max_uses',(now(),username,inv_id))
                        if c.execute('SELECT changes()').fetchone()[0]!=1:
                            c.rollback(); raise RuntimeError('卡密已被使用')
                        c.commit()
                    success_body='''<div class="renew-complete"><div class="renew-complete-glow"></div><div class="renew-complete-card"><div class="renew-complete-icon"><svg viewBox="0 0 64 64" aria-hidden="true"><circle cx="32" cy="32" r="28" fill="none" stroke="currentColor" stroke-width="3" opacity=".25"/><path d="m18 33 9 9 19-21" fill="none" stroke="currentColor" stroke-width="5" stroke-linecap="round" stroke-linejoin="round"/></svg></div><span class="renew-complete-kicker">MEMBERSHIP RENEWED</span><h2>充值成功</h2><p class="renew-complete-lead">会员时长已成功延长，祝您使用愉快</p><div class="renew-complete-details"><div><span>续费账号</span><strong>'''+esc(username)+'''</strong></div><div><span>本次充值</span><strong>'''+str(days)+''' 天</strong></div><div class="renew-complete-expiry"><span>新的到期时间</span><strong>'''+esc(expiry)+'''</strong></div></div><div class="renew-complete-foot"><span class="renew-complete-dot"></span>账号状态已恢复，可继续使用</div></div></div><style>.renew-complete{position:relative;min-height:calc(100vh - 110px);display:grid;place-items:center;padding:30px 16px;overflow:hidden}.renew-complete-glow{position:absolute;width:360px;height:360px;border-radius:50%;background:radial-gradient(circle,#24c98a22,transparent 68%);filter:blur(8px);pointer-events:none}.renew-complete-card{position:relative;width:min(100%,480px);padding:38px 32px 30px;border:1px solid #2c795e;border-radius:24px;background:linear-gradient(150deg,#142d33 0%,#101d30 48%,#111a2d 100%);box-shadow:0 28px 80px #0007,0 0 50px #1cbd7720;text-align:center;animation:renewRise .55s cubic-bezier(.2,.8,.2,1) both}.renew-complete-icon{display:grid;place-items:center;width:82px;height:82px;margin:0 auto 20px;border:1px solid #65e5ad;border-radius:26px;background:linear-gradient(145deg,#35c98a,#15845f);color:#effff7;box-shadow:0 12px 30px #159a7255,0 0 0 8px #35c98a12;transform:rotate(-4deg)}.renew-complete-icon svg{width:52px;height:52px}.renew-complete-kicker{color:#79ddb2;font-size:10px;font-weight:800;letter-spacing:2.5px}.renew-complete-card h2{margin:8px 0 7px;color:#f3fff9;font-size:30px;letter-spacing:1px}.renew-complete-lead{margin:0;color:#a9c9bc;font-size:14px;line-height:1.8}.renew-complete-details{margin:28px 0 18px;padding:4px 18px;border:1px solid #294a49;border-radius:16px;background:#09192366;text-align:left}.renew-complete-details>div{display:flex;justify-content:space-between;align-items:center;gap:16px;padding:15px 2px;border-bottom:1px solid #29414a}.renew-complete-details>div:last-child{border:0}.renew-complete-details span{color:#91a9ac;font-size:13px}.renew-complete-details strong{color:#edf7f5;font-size:15px;text-align:right;overflow-wrap:anywhere}.renew-complete-expiry strong{color:#78e0b0}.renew-complete-foot{display:flex;justify-content:center;align-items:center;gap:8px;color:#85b6a2;font-size:12px}.renew-complete-dot{width:7px;height:7px;border-radius:50%;background:#44d393;box-shadow:0 0 12px #44d393}.@keyframes renewRise{from{opacity:0;transform:translateY(12px) scale(.985)}to{opacity:1;transform:translateY(0) scale(1)}}@media(max-width:520px){.renew-complete{min-height:calc(100vh - 70px);padding:20px 4px}.renew-complete-card{padding:30px 20px 24px;border-radius:20px}.renew-complete-icon{width:72px;height:72px;border-radius:22px}.renew-complete-card h2{font-size:27px}.renew-complete-details{padding:2px 13px}.renew-complete-details>div{padding:14px 0}}</style>'''
                    return self.send(200,page(success_body,'充值成功',public=True))
                if mode!='new': raise RuntimeError('兑换方式无效')
                # New-user flow also runs without DB_LOCK during OpenList I/O;
                # duplicate names are checked again atomically before local commit.
                username=d.get('username','').strip(); base=setting('default_path','/') or '/'; pwd=d.get('password',''); confirm=d.get('confirm_password',''); expiry=plan_expiry(plan)
                if not pwd: raise RuntimeError('登录密码不能为空')
                if pwd!=confirm: raise RuntimeError('两次输入的密码不一致')
                if not username: raise RuntimeError('用户名不能为空')
                if invalid_username(username): raise RuntimeError('用户名仅支持小写英文字母和数字，长度最多 8 位')
                if forbidden_username(username): raise RuntimeError('该用户名包含管理员相关词语，不允许使用')
                if c.execute('SELECT 1 FROM users WHERE username=?',(username,)).fetchone(): raise RuntimeError('用户名已存在，请更换')
                if not base.startswith('/'): base='/'+base
                try:
                    result=api('POST','/api/admin/user/create',{'username':username,'password':pwd,'base_path':base,'role':0,'permission':256,'disabled':False})
                    oid=result_user_id(result)
                    if oid is None:
                        found=find_openlist_user(username)
                        if not found or found.get('id') is None: raise RuntimeError('OpenList 用户创建成功，但未能获取用户 ID')
                        oid=found['id']
                except RuntimeError as create_error:
                    # 上一次请求可能已在 OpenList 创建成功，但本地 SQLite 落库/响应中断，
                    # 重试时会收到 UNIQUE constraint。只有能用本次密码登录该账号时才自动接管，
                    # 避免误关联他人已有账号。
                    if 'UNIQUE constraint failed' not in str(create_error) and '已存在' not in str(create_error):
                        raise
                    base_url=setting('openlist_url').rstrip('/')
                    verify_req=urllib.request.Request(base_url+'/api/auth/login',data=json.dumps({'username':username,'password':pwd}).encode(),method='POST',headers={'Content-Type':'application/json'})
                    try:
                        with urllib.request.urlopen(verify_req,timeout=15) as verify_resp:
                            verify_result=json.loads(verify_resp.read().decode('utf-8','replace'))
                        if verify_result.get('code') not in (None,0,200) or not (verify_result.get('data',{}).get('token') or verify_result.get('token')):
                            raise RuntimeError('用户名已存在，请使用原注册密码重试，或更换用户名')
                    except (urllib.error.HTTPError,urllib.error.URLError,ValueError):
                        raise RuntimeError('用户名已存在，请使用原注册密码重试，或更换用户名')
                    found=find_openlist_user(username)
                    if not found or found.get('id') is None:
                        raise RuntimeError('OpenList 中已存在该用户，但无法同步用户信息')
                    oid=found['id']
                t=now()
                with DB_LOCK:
                    c.execute('BEGIN IMMEDIATE')
                    current_inv=c.execute('SELECT uses,max_uses FROM invites WHERE id=?',(inv_id,)).fetchone()
                    if not current_inv or current_inv['uses']>=current_inv['max_uses']:
                        c.rollback(); raise RuntimeError('卡密已被使用')
                    if c.execute('SELECT 1 FROM users WHERE username=?',(username,)).fetchone():
                        c.rollback(); raise RuntimeError('用户名已存在，请更换')
                    c.execute('INSERT INTO users(openlist_id,username,base_path,disabled,plan,expires_at,created,updated) VALUES(?,?,?,?,?,?,?,?)',(oid,username,base,0,plan,expiry,t,t))
                    c.execute('UPDATE invites SET uses=uses+1,used_at=?,registered_username=? WHERE id=? AND uses<max_uses',(now(),username,inv_id))
                    if c.execute('SELECT changes()').fetchone()[0]!=1:
                        c.rollback(); raise RuntimeError('卡密已被使用')
                    c.commit()
                return self.send(200,success_page(username,pwd,base,public=True))
            if p.path == '/new':
                username=d.get('username',''); base=d.get('base_path','/') or '/'; pwd=d.get('password','') or password(); plan=d.get('plan','week'); expiry=d.get('expires_at','').strip()
                if plan == 'day': expiry=(datetime.now()+timedelta(days=1)).strftime('%Y-%m-%d %H:%M:%S')
                elif plan == 'halfyear': expiry=(datetime.now()+timedelta(days=180)).strftime('%Y-%m-%d %H:%M:%S')
                elif plan == 'week': expiry=(datetime.now()+timedelta(days=7)).strftime('%Y-%m-%d %H:%M:%S')
                elif plan == 'month': expiry=(datetime.now()+timedelta(days=30)).strftime('%Y-%m-%d %H:%M:%S')
                elif plan == 'quarter': expiry=(datetime.now()+timedelta(days=90)).strftime('%Y-%m-%d %H:%M:%S')
                elif plan == 'year': expiry=(datetime.now()+timedelta(days=365)).strftime('%Y-%m-%d %H:%M:%S')
                else: raise RuntimeError('套餐类型无效')
                if not username: raise RuntimeError('用户名不能为空')
                if invalid_username(username): raise RuntimeError('用户名仅支持小写英文字母和数字，长度最多 8 位')
                if forbidden_username(username): raise RuntimeError('该用户名包含管理员相关词语，不允许使用')
                if c.execute('SELECT 1 FROM users WHERE username=?',(username,)).fetchone():
                    raise RuntimeError('用户名已存在，请更换')
                if not base.startswith('/'): base='/'+base
                result=api('POST','/api/admin/user/create',{'username':username,'password':pwd,'base_path':base,'role':0,'permission':256,'disabled':False})
                data=result.get('data') or result.get('user') or result
                oid=result_user_id(result)
                if oid is None:
                    found=find_openlist_user(username)
                    if not found or found.get('id') is None: raise RuntimeError('OpenList 用户创建成功，但未能获取用户 ID')
                    oid=found['id']
                t=now(); c.execute('INSERT INTO users(openlist_id,username,base_path,disabled,plan,expires_at,created,updated) VALUES(?,?,?,?,?,?,?,?)',(oid,username,base,0,plan,expiry,t,t)); c.commit()
                return self.send(200, success_page(username, pwd, base))
            parts=p.path.strip('/').split('/')
            if len(parts)==3 and parts[0]=='user' and parts[2] in ('disable','enable'):
                r=c.execute('SELECT * FROM users WHERE id=?',(int(parts[1]),)).fetchone()
                if not r: raise RuntimeError('本地用户不存在')
                disabled=parts[2]=='disable'
                oid=r['openlist_id']
                if not oid:
                    found=find_openlist_user(r['username'])
                    if not found: raise RuntimeError(f'OpenList 中找不到用户：{r["username"]}')
                    oid=found['id']
                    c.execute('UPDATE users SET openlist_id=?,updated=? WHERE id=?',(oid,now(),r['id']))
                payload={'id':oid,'username':r['username'],'base_path':r['base_path'],'role':0,'permission':256,'disabled':disabled}
                api('POST','/api/admin/user/update',payload)
                c.execute('UPDATE users SET disabled=?,updated=? WHERE id=?',(int(disabled),now(),r['id'])); c.commit()
                return self.done()
            if len(parts)==3 and parts[0]=='user' and parts[2]=='renew':
                r=c.execute('SELECT * FROM users WHERE id=?',(int(parts[1]),)).fetchone()
                if not r: raise RuntimeError('本地用户不存在')
                plan=d.get('plan','year')
                durations={'day':1,'week':7,'month':30,'quarter':90,'halfyear':180,'year':365}
                if plan not in durations: raise RuntimeError('套餐类型无效')
                current=datetime.strptime(r['expires_at'], '%Y-%m-%d %H:%M:%S') if r['expires_at'] else datetime.now()
                expiry=(max(current,datetime.now())+timedelta(days=durations[plan])).strftime('%Y-%m-%d %H:%M:%S')
                # 套餐状态按续费后的总有效期自动匹配：未达到更高档位时保持当前档位，
                # 达到更高档位时升级显示为该档位；不会因单次续费较小而降级。
                total_days=max(1, int((datetime.strptime(expiry, '%Y-%m-%d %H:%M:%S')-datetime.strptime(r['created'], '%Y-%m-%d %H:%M:%S')).total_seconds() / 86400))
                display_plan=plan_for_duration_days(total_days)
                c.execute('UPDATE users SET plan=?,expires_at=?,updated=? WHERE id=?',(display_plan,expiry,now(),r['id'])); c.commit()
                return self.done()
            if len(parts)==3 and parts[0]=='user' and parts[2]=='plan':
                r=c.execute('SELECT * FROM users WHERE id=?',(int(parts[1]),)).fetchone()
                if not r: raise RuntimeError('本地用户不存在')
                plan=d.get('plan','custom'); expiry=d.get('expires_at','').strip()
                durations={'day':1,'week':7,'month':30,'quarter':90,'halfyear':180,'year':365}
                if plan in durations: expiry=(datetime.now()+timedelta(days=durations[plan])).strftime('%Y-%m-%d %H:%M:%S')
                elif expiry: datetime.strptime(expiry, '%Y-%m-%d %H:%M:%S')
                c.execute('UPDATE users SET plan=?,expires_at=?,updated=? WHERE id=?',(plan,expiry,now(),r['id'])); c.commit()
                return self.done()
            if len(parts)==3 and parts[0]=='user' and parts[2]=='delete':
                r=c.execute('SELECT * FROM users WHERE id=?',(int(parts[1]),)).fetchone()
                if not r: raise RuntimeError('本地用户不存在')
                oid=r['openlist_id']
                if not oid:
                    found=find_openlist_user(r['username'])
                    if not found: raise RuntimeError('OpenList 中找不到该用户，已停止删除')
                    oid=found['id']
                    c.execute('UPDATE users SET openlist_id=?,updated=? WHERE id=?',(oid,now(),r['id']))
                api('POST',f'/api/admin/user/delete?id={oid}')
                c.execute('DELETE FROM users WHERE id=?',(r['id'],)); c.commit()
                return self.send(303,'',headers={'Location':'/'})
            raise RuntimeError('未知操作')
        except urllib.error.HTTPError as e:
            body=e.read().decode('utf-8','replace')
            renew_fail=host == INVITE_HOST and p.path.startswith('/register/') and d.get('mode')=='old'
            renew_back='/register/'+esc(p.path.split('/')[-1]) if p.path.startswith('/register/') else '/'
            if renew_fail and '账户不存在，请重新注册' in body:
                return self.send(400,page('<div class="card register-error-card"><div class="register-error-icon">!</div><h2>账户不存在</h2><p class="err">账户不存在，请重新注册。</p><a class="renew-back-link" href="'+renew_back+'">返回注册续费页面</a></div>','账户不存在',public=True))
            if 'exist' in body.lower() or 'duplicate' in body.lower() or 'username' in body.lower():
                if renew_fail:
                    return self.send(400,page('<div class="card register-error-card"><div class="register-error-icon">!</div><h2>续费失败</h2><p class="err">账号续费未完成，请检查账号信息后重试。</p><a class="renew-back-link" href="'+renew_back+'">返回注册续费页面</a></div>','续费失败',public=True))
                if host == INVITE_HOST:
                    back='/register/'+esc(p.path.split('/')[-1])
                    return self.send(400,page('<div class="card register-error-card register-duplicate-card"><div class="register-error-icon">!</div><h2>注册失败</h2><p class="duplicate-message">这个用户名已经被注册了，请更换一个新的用户名。</p><a class="renew-back-link" href="'+back+'">返回注册页面重新填写</a></div>','注册失败',public=True))
                return self.send(400,page('<div class="card"><div class="err">用户名已存在，请更换</div><p><a href="/new">返回新增用户</a></p></div>','用户名已存在'))
            if renew_fail:
                return self.send(400,page('<div class="card register-error-card"><div class="register-error-icon">!</div><h2>续费失败</h2><p class="err">续费未完成，请检查账号和密码后重试。</p><a class="renew-back-link" href="'+renew_back+'">返回注册续费页面</a></div>','续费失败',public=True))
            if host == INVITE_HOST:
                return self.send(400,page('<div class="card register-error-card"><div class="register-error-icon">!</div><h2>注册失败</h2><p class="err">注册失败，请检查填写内容后重试。</p></div>','注册失败',public=True))
            return self.send(400,page('<div class="card"><div class="err">操作失败：%s</div><p><a href="/">返回</a></p></div>'%(esc(body[:300])),'操作失败'))
        except Exception as e:
            if host == INVITE_HOST and p.path == '/query':
                return self.send(400,page('<div class="card register-error-card"><div class="register-error-icon">!</div><h2>查询失败</h2><p class="err">用户名或密码错误，请检查后重试。</p><a class="renew-back-link" href="/query">返回查询页面</a></div>','查询失败',public=True))
            renew_fail=host == INVITE_HOST and p.path.startswith('/register/') and d.get('mode')=='old'
            if renew_fail:
                renew_back='/register/'+esc(p.path.split('/')[-1])
                return self.send(400,page('<div class="card register-error-card"><div class="register-error-icon">!</div><h2>续费失败</h2><p class="err">'+esc(str(e))+'</p><a class="renew-back-link" href="'+renew_back+'">返回注册续费页面</a></div>','续费失败',public=True))
            if host == INVITE_HOST:
                back='/register/'+esc(p.path.split('/')[-1]) if p.path.startswith('/register/') else '/'
                detail=str(e)
                if 'UNIQUE constraint failed' in detail or '已存在' in detail or 'username' in detail.lower():
                    message='这个用户名已经被注册了，请更换一个新的用户名。'
                    title='用户名已存在'; tone='register-duplicate-card'
                elif 'database is locked' in detail:
                    message='系统正在处理上一笔请求，请稍等片刻后重试。'
                    title='系统繁忙'; tone=''
                elif 'OpenList API' in detail or '无法连接 OpenList' in detail:
                    message='用户服务暂时响应异常，请稍后重试。若连续失败，请联系客服。'
                    title='服务暂时不可用'; tone=''
                else:
                    message='注册没有完成，请检查填写内容后重试。'
                    title='注册失败'; tone=''
                return self.send(400,page('<div class="card register-error-card '+tone+'"><div class="register-error-icon">!</div><h2>'+title+'</h2><p class="duplicate-message">'+message+'</p><p class="error-help">如果重复尝试仍未成功，请返回注册链接重新填写，或联系客服。</p><a class="renew-back-link" href="'+back+'">返回注册页面</a></div>','注册失败',public=True))
            return self.send(400,page('<div class="card"><div class="err">操作失败：%s</div><p><a href="/">返回</a></p></div>'%(esc(e)),'操作失败'))
    def log_message(self,*a): pass

if __name__ == '__main__':
    # 清理任务放到后台线程，避免 OpenList API 慢/不可用时阻塞登录服务。
    db()
    threading.Thread(target=expiry_worker, name='expiry-worker', daemon=True).start()
    print(f'OpenList user admin listening on {HOST}:{PORT}', flush=True)
    ThreadingHTTPServer((HOST,PORT),Handler).serve_forever()
