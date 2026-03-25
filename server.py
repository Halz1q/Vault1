import sqlite3
import uuid
import hashlib
import time
import os
import secrets
from flask import Flask, request, jsonify, render_template_string, session, redirect, url_for
from functools import wraps

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)

DB_NAME = os.path.join(os.path.dirname(os.path.abspath(__file__)), "keys.db")

ADMIN_USERNAME = "Admin"
ADMIN_PASSWORD_HASH = hashlib.sha256("halz123".encode()).hexdigest()

def init_db():
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute("PRAGMA table_info(keys)")
    columns = [row[1] for row in c.fetchall()]
    
    if 'key_type' not in columns:
        c.execute("DROP TABLE IF EXISTS keys")
        c.execute('''CREATE TABLE keys (
            key TEXT PRIMARY KEY,
            key_type TEXT DEFAULT 'permanent',
            duration_hours INTEGER,
            max_devices INTEGER DEFAULT 1,
            devices TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            expires_at TIMESTAMP,
            used_at TIMESTAMP,
            is_active INTEGER DEFAULT 1
        )''')
    conn.commit()
    conn.close()

def generate_key():
    return uuid.uuid4().hex[:16].upper()

def hash_hwid(hwid):
    return hashlib.sha256(hwid.encode()).hexdigest()

def verify_key(key, hwid):
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    
    c.execute("SELECT key_type, duration_hours, expires_at, max_devices, devices, is_active FROM keys WHERE key = ?", (key,))
    row = c.fetchone()
    
    if not row:
        conn.close()
        return {"success": False, "message": "Ключ не найден"}
    
    key_type, duration_hours, expires_at, max_devices, devices_json, is_active = row
    
    if not is_active:
        conn.close()
        return {"success": False, "message": "Ключ заблокирован"}
    
    if expires_at:
        if time.strptime(expires_at, "%Y-%m-%d %H:%M:%S") < time.localtime():
            conn.close()
            return {"success": False, "message": "Ключ истёк"}
    
    devices = []
    if devices_json:
        devices = devices_json.split(",")
    
    if hwid in devices:
        conn.close()
        return {"success": True, "message": "OK"}
    
    if len(devices) >= max_devices:
        conn.close()
        return {"success": False, "message": f"Достигнут лимит устройств ({max_devices})"}
    
    devices.append(hwid)
    new_devices = ",".join(devices)
    c.execute("UPDATE keys SET devices = ?, used_at = CURRENT_TIMESTAMP WHERE key = ?", (new_devices, key))
    conn.commit()
    conn.close()
    
    msg = "Ключ активирован" if len(devices) == 1 else f"Привязано устройство {len(devices)}/{max_devices}"
    return {"success": True, "message": msg}

ADMIN_HTML = '''
<!DOCTYPE html>
<html>
<head>
    <title>Admin Panel</title>
    <style>
        body { background: #0a0e17; color: #fff; font-family: Arial; padding: 20px; }
        .container { max-width: 700px; margin: 0 auto; }
        h1 { color: #1e3a5f; }
        .key-box { background: #0d1320; padding: 15px; border-radius: 8px; margin: 10px 0; 
                   display: flex; justify-content: space-between; align-items: center; }
        .key { font-family: monospace; font-size: 18px; color: #4ade80; }
        input, select, button { padding: 10px; border-radius: 5px; border: 1px solid #1e3a5f; 
                        background: #0d1320; color: #fff; }
        button { background: #1e3a5f; cursor: pointer; }
        button:hover { background: #2d5a8f; }
        .keys-list { margin-top: 20px; }
        .form-row { display: flex; gap: 10px; margin-bottom: 10px; }
        .status { font-size: 12px; }
        .expired { color: #ef4444; }
        .active { color: #4ade80; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🔑 Генератор ключей</h1>
        <form method="POST" action="/admin/generate">
            <div class="form-row">
                <select name="key_type" style="width: 150px;">
                    <option value="permanent">Постоянный</option>
                    <option value="24h">24 часа</option>
                    <option value="3d">3 дня</option>
                    <option value="7d">7 дней</option>
                    <option value="14d">14 дней</option>
                    <option value="30d">30 дней</option>
                </select>
                <input type="number" name="max_devices" value="1" min="1" max="10" style="width: 80px;" title="Кол-во устройств">
                <button type="submit">Создать ключ</button>
            </div>
        </form>
        
        <h2>Активные ключи</h2>
        <div class="keys-list">
            {% for key in keys %}
            <div class="key-box">
                <div>
                    <span class="key">{{ key[0] }}</span>
                    <span class="status">| {{ key[1] }} | {{ key[2] }} устр.</span>
                </div>
                <span class="{{ 'active' if key[3] else 'expired' }}">{{ key[4] }}</span>
            </div>
            {% endfor %}
        </div>
    </div>
</body>
</html>
'''

LOGIN_HTML = '''
<!DOCTYPE html>
<html>
<head>
    <title>Вход</title>
    <style>
        body { background: #0a0e17; color: #fff; font-family: Arial; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; }
        .login-box { background: #0d1320; padding: 30px; border-radius: 10px; width: 300px; }
        h2 { color: #1e3a5f; text-align: center; }
        input { width: 100%; padding: 10px; margin: 10px 0; border-radius: 5px; border: 1px solid #1e3a5f; background: #0a0e17; color: #fff; box-sizing: border-box; }
        button { width: 100%; padding: 10px; border-radius: 5px; border: none; background: #1e3a5f; color: #fff; cursor: pointer; }
        button:hover { background: #2d5a8f; }
        .error { color: #ef4444; text-align: center; margin-top: 10px; }
    </style>
</head>
<body>
    <div class="login-box">
        <h2>🔐 Admin</h2>
        <form method="POST" action="/login">
            <input type="text" name="username" placeholder="Логин" required>
            <input type="password" name="password" placeholder="Пароль" required>
            <button type="submit">Войти</button>
            {% if error %}
            <p class="error">{{ error }}</p>
            {% endif %}
        </form>
    </div>
</body>
</html>
'''

def login_required(f):
    def decorated_function(*args, **kwargs):
        if not session.get('logged_in'):
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    decorated_function.__name__ = f.__name__
    return decorated_function

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        password_hash = hashlib.sha256(password.encode()).hexdigest()
        
        if username == ADMIN_USERNAME and password_hash == ADMIN_PASSWORD_HASH:
            session['logged_in'] = True
            return redirect(url_for('admin'))
        else:
            error = 'Неверный логин или пароль'
    
    return render_template_string(LOGIN_HTML, error=error)

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/')
def root():
    return redirect(url_for('login'))

@app.route('/admin')
@login_required
def admin():
    return render_template_string(ADMIN_HTML, keys=get_all_keys())

@app.route('/admin/generate', methods=['POST'])
def generate():
    key = generate_key()
    key_type = request.form.get('key_type', 'permanent')
    max_devices = int(request.form.get('max_devices', 1))
    
    duration_map = {'24h': 24, '3d': 72, '7d': 168, '14d': 336, '30d': 720}
    duration_hours = duration_map.get(key_type, None)
    
    expires_at = None
    if duration_hours:
        from datetime import datetime, timedelta
        expires_at = (datetime.now() + timedelta(hours=duration_hours)).strftime("%Y-%m-%d %H:%M:%S")
    
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute("INSERT INTO keys (key, key_type, duration_hours, max_devices, expires_at) VALUES (?, ?, ?, ?, ?)",
              (key, key_type, duration_hours, max_devices, expires_at))
    conn.commit()
    conn.close()
    return '<script>window.location="/"</script>'

@app.route('/api/activate', methods=['POST'])
def activate():
    data = request.json
    key = data.get('key', '')
    hwid = data.get('hwid', '')
    
    if not key or not hwid:
        return jsonify({"success": False, "message": "Некорректные данные"})
    
    result = verify_key(key, hwid)
    return jsonify(result)

@app.route('/api/check', methods=['POST'])
def check():
    data = request.json
    key = data.get('key', '')
    hwid = data.get('hwid', '')
    
    if not key or not hwid:
        return jsonify({"active": False})
    
    result = verify_key(key, hwid)
    return jsonify({"active": result["success"]})

def get_all_keys():
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute("SELECT key, key_type, max_devices, expires_at FROM keys WHERE is_active = 1 ORDER BY created_at DESC")
    rows = c.fetchall()
    conn.close()
    
    result = []
    for row in rows:
        key, key_type, max_devices, expires_at = row
        type_names = {'permanent': 'Постоянный', '24h': '24ч', '3d': '3д', '7d': '7д', '14d': '14д', '30d': '30д'}
        type_name = type_names.get(key_type, key_type)
        
        devices = 0
        conn = sqlite3.connect(DB_NAME)
        c = conn.cursor()
        c.execute("SELECT devices FROM keys WHERE key = ?", (key,))
        dev_row = c.fetchone()
        if dev_row and dev_row[0]:
            devices = len(dev_row[0].split(","))
        conn.close()
        
        status = "Не активирован"
        if expires_at:
            if time.strptime(expires_at, "%Y-%m-%d %H:%M:%S") < time.localtime():
                status = "Истёк"
            else:
                status = f"до {expires_at[:16]}"
        elif devices > 0:
            status = f"Активен ({devices}/{max_devices})"
        
        result.append((key, type_name, max_devices, devices, status))
    
    return result

if __name__ == '__main__':
    init_db()
    print("Сервер запущен: http://localhost:5086")
    app.run(host='0.0.0.0', port=5086)