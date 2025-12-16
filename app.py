import os
import sqlite3
import ctypes
import time
import uuid
from flask import Flask, request, render_template, redirect, url_for, session, flash, send_from_directory, jsonify
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = os.urandom(24)
UPLOAD_FOLDER = 'uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# --- LOAD C LIBRARY ---
try:
    totp_lib = ctypes.CDLL('./libtotp.so')
    totp_lib.generate_totp.argtypes = [ctypes.c_char_p, ctypes.c_size_t, ctypes.c_uint64]
    totp_lib.generate_totp.restype = ctypes.c_int
except Exception as e:
    print(f"Library Warning: {e}")
    totp_lib = None 

# --- DATABASE SETUP ---
def get_db_connection():
    conn = sqlite3.connect('woc_vault.db')
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = sqlite3.connect('woc_vault.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users 
                 (id TEXT PRIMARY KEY, username TEXT UNIQUE, password TEXT, secret_key TEXT)''')
    
    # NEW: Added 'role' column (owner, viewer, editor, revoked)
    # We also track 'source_filename' to group shares together
    c.execute('''CREATE TABLE IF NOT EXISTS file_registry 
                 (filename TEXT PRIMARY KEY, 
                  owner_username TEXT, 
                  shared_from TEXT, 
                  source_filename TEXT,
                  role TEXT DEFAULT 'owner')''')

    c.execute('''CREATE TABLE IF NOT EXISTS audit_logs 
                 (id INTEGER PRIMARY KEY AUTOINCREMENT, filename TEXT, owner_username TEXT, 
                  actor_username TEXT, action TEXT, timestamp DATETIME DEFAULT CURRENT_TIMESTAMP)''')
    conn.commit()
    conn.close()

init_db()

def log_action(filename, owner, actor, action):
    try:
        conn = get_db_connection()
        conn.execute('INSERT INTO audit_logs (filename, owner_username, actor_username, action) VALUES (?, ?, ?, ?)',
                     (filename, owner, actor, action))
        conn.commit()
        conn.close()
    except Exception: pass

# --- ROUTES ---

@app.route('/')
def home():
    if 'user_id' in session:
        conn = get_db_connection()
        # Fetch files owned by user AND ensure role is not 'revoked'
        files = conn.execute('''SELECT * FROM file_registry 
                                WHERE owner_username = ? AND role != 'revoked' ''', 
                             (session['username'],)).fetchall()
        conn.close()
        
        return render_template('index.html', 
                             user=session['username'],
                             trap_key=session.get('trap_key', ''), 
                             trap_mode=session.get('trap_mode', 0), 
                             files=files)
    return redirect(url_for('auth'))

@app.route('/auth')
def auth(): return render_template('auth.html')

@app.route('/signup', methods=['POST'])
def signup():
    username = request.form['username']
    password = request.form['password']
    user_secret_key = f"{username}_{os.urandom(4).hex()}"
    hashed_pw = generate_password_hash(password)
    
    print(f"\n[NEW USER] {username} | KEY: {user_secret_key}\n")
    
    try:
        conn = get_db_connection()
        conn.execute('INSERT INTO users (id, username, password, secret_key) VALUES (?, ?, ?, ?)',
                     (str(uuid.uuid4()), username, hashed_pw, user_secret_key))
        conn.commit()
        conn.close()
        flash("Account Created.", "success")
    except Exception as e: flash(str(e), "error")
    return redirect(url_for('auth'))

@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']
    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
    conn.close()

    if user and check_password_hash(user['password'], password):
        session['pre_auth_id'] = user['id']
        # DEBUG OTP
        if totp_lib:
            k = user['secret_key'].encode()
            otp = totp_lib.generate_totp(k, len(k), int(time.time()//30))
            print(f"\n[LOGIN DEBUG] VALID OTP: {otp}\n")
        return render_template('verify_otp.html', email="registered email")
    else:
        flash("Invalid Credentials", "error")
        return redirect(url_for('auth'))

@app.route('/verify_otp', methods=['POST'])
def verify_otp():
    user_otp = request.form['otp']
    user_id = session.get('pre_auth_id')
    if not user_id: return redirect(url_for('auth'))

    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
    conn.close()

    # TRAP CHECK
    is_valid = False
    if totp_lib:
        k = user['secret_key'].encode()
        t = int(time.time()//30)
        valid = totp_lib.generate_totp(k, len(k), t)
        prev = totp_lib.generate_totp(k, len(k), t-1)
        if str(valid) == user_otp or str(prev) == user_otp: is_valid = True

    # KEY ASSIGNMENT (PERSISTENCE FIX)
    if is_valid:
        session['trap_mode'] = 1
        session['trap_key'] = user['secret_key']
    else:
        session['trap_mode'] = 0
        session['trap_key'] = user_otp # Trap!

    session['user_id'] = user['id']
    session['username'] = user['username']
    session.pop('pre_auth_id', None)
    return redirect(url_for('home'))

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('auth'))

# --- FILE OPERATIONS ---

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'trap_key' not in session: return "Unauthorized", 401
    file = request.files['file']
    filename = f"{session['username']}_{int(time.time())}_{file.filename}" 
    file.save(os.path.join(UPLOAD_FOLDER, filename))
    
    conn = get_db_connection()
    # Owner gets 'owner' role, source is self
    conn.execute('INSERT INTO file_registry (filename, owner_username, shared_from, source_filename, role) VALUES (?, ?, ?, ?, ?)',
                 (filename, session['username'], "Self", filename, "owner"))
    conn.commit()
    conn.close()
    
    log_action(filename, session['username'], session['username'], "Created")
    return "OK", 200

@app.route('/download/<filename>')
def download_file(filename):
    if 'trap_key' not in session: return "Unauthorized", 401
    # Check permissions
    conn = get_db_connection()
    perm = conn.execute('SELECT role, owner_username FROM file_registry WHERE filename=?', (filename,)).fetchone()
    conn.close()
    
    if not perm or perm['role'] == 'revoked': return "Access Denied", 403

    log_action(filename, perm['owner_username'], session['username'], "Downloaded")
    return send_from_directory(UPLOAD_FOLDER, filename)

# --- SHARING & ROLES ---

@app.route('/get_share_key/<target>')
def get_share_key(target):
    conn = get_db_connection()
    u = conn.execute('SELECT secret_key FROM users WHERE username=?', (target,)).fetchone()
    conn.close()
    return u['secret_key'] if u else ("Not Found", 404)

@app.route('/share_file', methods=['POST'])
def share_file():
    if 'trap_key' not in session: return "Unauthorized", 401
    
    file = request.files['file']
    target = request.form['target_user']
    orig_name = request.form['original_filename'] 
    
    # 1. CHECK PERMISSIONS (Changed Logic)
    conn = get_db_connection()
    # Check if the current user is the owner OR an editor of this file
    perm = conn.execute('SELECT role, source_filename FROM file_registry WHERE filename = ? AND owner_username = ?', 
                        (orig_name, session['username'])).fetchone()
    
    # If they are not found, or have 'viewer'/'revoked' role, deny access
    if not perm or perm['role'] not in ['owner', 'editor']:
        conn.close()
        return "Permission Denied: Only Owners and Editors can share.", 403

    real_source = perm['source_filename'] # Keep the lineage alive
    
    # 2. Save new copy for the target
    new_filename = f"{target}_{int(time.time())}_{file.filename}"
    file.save(os.path.join(UPLOAD_FOLDER, new_filename))
    
    # 3. Grant 'viewer' role by default
    conn.execute('INSERT OR REPLACE INTO file_registry (filename, owner_username, shared_from, source_filename, role) VALUES (?, ?, ?, ?, ?)',
                 (new_filename, target, session['username'], real_source, "viewer"))
    conn.commit()
    conn.close()
    
    log_action(real_source, session['username'], session['username'], f"Shared with {target}")
    return "Shared", 200

# NEW: Get list of people who have access to MY file
# [UPDATED] Get list of ALL people who have access to this file (for Syncing)
@app.route('/get_file_users/<filename>')
def get_file_users(filename):
    conn = get_db_connection()
    
    # 1. Find the source_filename to identify the "Group"
    rec = conn.execute('SELECT source_filename FROM file_registry WHERE filename=?', (filename,)).fetchone()
    if not rec: 
        conn.close()
        return jsonify([])
    
    source = rec['source_filename']
    
    # 2. FETCH ALL SHARES (Removed "shared_from" filter)
    # This ensures Bob sees himself and Eve in the list so he can update their copies too.
    shares = conn.execute('''SELECT owner_username, role, filename 
                             FROM file_registry 
                             WHERE source_filename = ?''', 
                          (source,)).fetchall()
    conn.close()
    
    return jsonify([dict(row) for row in shares])

# NEW: Update role
@app.route('/update_role', methods=['POST'])
def update_role():
    data = request.json
    target_file = data['filename']
    new_role = data['role']
    
    conn = get_db_connection()
    conn.execute('UPDATE file_registry SET role = ? WHERE filename = ?', (new_role, target_file))
    conn.commit()
    conn.close()
    
    log_action(target_file, session['username'], session['username'], f"Changed role to {new_role}")
    return "Updated", 200

@app.route('/audit_logs')
def view_audit_logs():
    conn = get_db_connection()
    logs = conn.execute('SELECT * FROM audit_logs WHERE owner_username=? ORDER BY timestamp DESC', (session['username'],)).fetchall()
    conn.close()
    return render_template('audit.html', logs=logs)

@app.route('/update_file', methods=['POST'])
def update_file():
    if 'trap_key' not in session: return "Unauthorized", 401
    
    file = request.files['file']
    target_filename = request.form['filename']
    
    conn = get_db_connection()
    
    # 1. IDENTIFY THE FILE
    # Find out who owns this specific file and what its Master Source is
    target_info = conn.execute('SELECT owner_username, source_filename FROM file_registry WHERE filename=?', 
                               (target_filename,)).fetchone()
    
    if not target_info:
        conn.close()
        return "File not found", 404
        
    source_filename = target_info['source_filename']
    
    # 2. CHECK PRIVILEGE
    # Am I the Owner of this specific file?
    is_owner = (target_info['owner_username'] == session['username'])
    
    # Am I the Owner or Editor of the MASTER SOURCE?
    # (If I can edit the Master, I can edit all the copies)
    can_edit_source = conn.execute('''SELECT 1 FROM file_registry 
                                      WHERE filename=? AND owner_username=? 
                                      AND (role='owner' OR role='editor')''', 
                                   (source_filename, session['username'])).fetchone()
                                   
    # Also check if I'm an assigned editor on the source record
    is_assigned_editor = conn.execute('''SELECT 1 FROM file_registry 
                                         WHERE source_filename=? AND owner_username=? AND role='editor' ''', 
                                      (source_filename, session['username'])).fetchone()

    conn.close()
    
    if not is_owner and not can_edit_source and not is_assigned_editor:
        return "Permission Denied", 403
    
    # 3. OVERWRITE (Hard Delete first to prevent caching issues)
    save_path = os.path.join(UPLOAD_FOLDER, target_filename)
    if os.path.exists(save_path): os.remove(save_path)
    file.save(save_path)
    
    print(f"[SYNC] Updated file: {target_filename}")
    return "Updated", 200

if __name__ == '__main__':
    app.run(debug=True, port=5000)

