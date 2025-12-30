import os
import sqlite3
import ctypes
import time
import uuid
from flask import Flask, request, render_template, redirect, url_for, session, flash, send_from_directory, jsonify
from werkzeug.security import generate_password_hash, check_password_hash

import qrcode
import io
import base64
from flask import send_file

import boto3
from botocore.exceptions import NoCredentialsError


app = Flask(__name__)
app.secret_key = os.urandom(24)
# --- SUPABASE CONFIGURATION ---
S3_BUCKET = "pandoras-vault"  # Make sure you created this bucket in the 'Storage' tab!

# Initialize S3 Client with your specific details
s3 = boto3.client('s3', 
                  endpoint_url='https://pxrkpjzhdhvgtcxhmfev.storage.supabase.co/storage/v1/s3', #
                  aws_access_key_id='bedf6475c7fcd50646c3308d6e7789e5',
                  aws_secret_access_key='0c43d9ebeb410a5915e8c77dd3863cc081232cfee69395b187779f4a54973dab',
                  region_name='ap-south-1') #
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
    # 1. Add public_key to users
    c.execute('''CREATE TABLE IF NOT EXISTS users 
                 (id TEXT PRIMARY KEY, username TEXT UNIQUE, password TEXT, secret_key TEXT, public_key TEXT)''')
    
    # 2. Add encrypted_key to file_registry
    # We still use 'filename' as the primary key for the Logical File (User's view)
    c.execute('''CREATE TABLE IF NOT EXISTS file_registry 
                 (filename TEXT PRIMARY KEY, 
                  owner_username TEXT, 
                  shared_from TEXT, 
                  source_filename TEXT,
                  role TEXT DEFAULT 'owner',
                  encrypted_key TEXT)''')

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
    public_key = request.form['public_key']
    
    # 1. Generate the same random secret your C code uses
    raw_secret = f"{username}_{os.urandom(4).hex()}"
    hashed_pw = generate_password_hash(password)
    
    try:
        conn = get_db_connection()
        conn.execute('INSERT INTO users (id, username, password, secret_key, public_key) VALUES (?, ?, ?, ?, ?)',
                     (str(uuid.uuid4()), username, hashed_pw, raw_secret, public_key))
        conn.commit()
        conn.close()
        
        # 2. Redirect to the QR Setup Page
        # We store these briefly in session so the next page can generate the QR
        session['temp_secret'] = raw_secret
        session['temp_user'] = username
        return redirect(url_for('setup_2fa'))
        
    except Exception as e: 
        flash(str(e), "error")
        return redirect(url_for('auth'))
    

# Route to render the HTML page
@app.route('/setup_2fa')
def setup_2fa():
    if 'temp_secret' not in session: return redirect(url_for('auth'))
    return render_template('setup_2fa.html')

# Route to generate the actual PNG image
@app.route('/generate_qr')
def generate_qr():
    if 'temp_secret' not in session: return "Error", 400
    
    username = session['temp_user']
    raw_secret = session['temp_secret']
    
    # CRITICAL STEP: 
    # Google Authenticator needs the key in Base32 format.
    # We are NOT changing the key, just writing it in a different alphabet.
    b32_secret = base64.b32encode(raw_secret.encode('utf-8')).decode('utf-8')
    
    # Standard URI format for Authenticator Apps
    # This just tells the app: "Here is the secret, use SHA1 (default)"
    uri = f"otpauth://totp/PandoraVault:{username}?secret={b32_secret}&issuer=PandoraVault"
    
    img = qrcode.make(uri)
    buf = io.BytesIO()
    img.save(buf)
    buf.seek(0)
    
    return send_file(buf, mimetype='image/png')

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
    encrypted_key = request.form['encrypted_key']
    
    # 1. Generate Unique Name
    filename = f"{session['username']}_{int(time.time())}_{file.filename}" 
    
    # 2. UPLOAD TO AWS S3 (Replaces file.save)
    try:
        # We upload the file object directly. 
        # S3 overwrites if the name exists, but our timestamp prevents collisions.
        s3.upload_fileobj(file, S3_BUCKET, filename)
    except Exception as e:
        return f"Cloud Upload Error: {str(e)}", 500
    
    # 3. DATABASE (Exact same as before)
    conn = get_db_connection()
    conn.execute('INSERT INTO file_registry (filename, owner_username, shared_from, source_filename, role, encrypted_key) VALUES (?, ?, ?, ?, ?, ?)',
                 (filename, session['username'], "Self", filename, "owner", encrypted_key))
    conn.commit()
    conn.close()
    
    log_action(filename, session['username'], session['username'], "Created (Cloud)")
    return "OK", 200

@app.route('/download/<filename>')
def download_file(filename):
    if 'trap_key' not in session: return "Unauthorized", 401
    conn = get_db_connection()
    perm = conn.execute('SELECT role, owner_username, source_filename FROM file_registry WHERE filename=?', (filename,)).fetchone()
    conn.close()
    
    if not perm or perm['role'] == 'revoked': return "Access Denied", 403

    log_action(filename, perm['owner_username'], session['username'], "Downloaded (Cloud)")
    
    # SERVE FROM S3
    try:
        # 1. Get the object stream from S3
        file_obj = s3.get_object(Bucket=S3_BUCKET, Key=perm['source_filename'])
        
        # 2. Stream it directly to the user
        return send_file(
            file_obj['Body'],
            as_attachment=True,
            download_name=filename 
        )
    except Exception as e:
        return f"Cloud Retrieval Error: {str(e)}", 404

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
    
    # Notice: We are NOT getting request.files['file'] anymore. 
    # We are just trading keys.
    target = request.form['target_user']
    orig_name = request.form['original_filename'] 
    new_envelope = request.form['encrypted_key'] # <--- NEW: Key encrypted for Target
    
    conn = get_db_connection()
    perm = conn.execute('SELECT role, source_filename FROM file_registry WHERE filename = ? AND owner_username = ?', 
                        (orig_name, session['username'])).fetchone()
    
    if not perm or perm['role'] not in ['owner', 'editor']:
        conn.close()
        return "Permission Denied", 403

    real_source = perm['source_filename']
    
    # Create a "Virtual File" for the target. 
    # It has a unique name in the DB, but points to 'real_source' on disk.
    # WE DO NOT COPY THE FILE TO DISK.
    virtual_filename = f"{target}_{int(time.time())}_{orig_name.split('_', 2)[-1]}"
    
    conn.execute('INSERT OR REPLACE INTO file_registry (filename, owner_username, shared_from, source_filename, role, encrypted_key) VALUES (?, ?, ?, ?, ?, ?)',
                 (virtual_filename, target, session['username'], real_source, "viewer", new_envelope))
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
    
    # 1. IDENTIFY THE FILE (No changes here)
    target_info = conn.execute('SELECT owner_username, source_filename FROM file_registry WHERE filename=?', 
                               (target_filename,)).fetchone()
    
    if not target_info:
        conn.close()
        return "File not found", 404
        
    source_filename = target_info['source_filename']
    
    # 2. CHECK PRIVILEGE (No changes here)
    is_owner = (target_info['owner_username'] == session['username'])
    
    can_edit_source = conn.execute('''SELECT 1 FROM file_registry 
                                      WHERE filename=? AND owner_username=? 
                                      AND (role='owner' OR role='editor')''', 
                                   (source_filename, session['username'])).fetchone()
                                   
    is_assigned_editor = conn.execute('''SELECT 1 FROM file_registry 
                                         WHERE source_filename=? AND owner_username=? AND role='editor' ''', 
                                      (source_filename, session['username'])).fetchone()
    conn.close()
    
    if not is_owner and not can_edit_source and not is_assigned_editor:
        return "Permission Denied", 403
    
    # 3. OVERWRITE ON S3 (Replaces local file save)
    try:
        # S3 automatically overwrites if the key exists
        s3.upload_fileobj(file, S3_BUCKET, target_filename)
        print(f"[SYNC] Cloud file updated: {target_filename}")
        return "Updated", 200
    except Exception as e:
        return f"Cloud Sync Error: {str(e)}", 500

@app.route('/get_public_key/<username>')
def get_public_key(username):
    conn = get_db_connection()
    u = conn.execute('SELECT public_key FROM users WHERE username=?', (username,)).fetchone()
    conn.close()
    return u['public_key'] if u else ("Not Found", 404)

if __name__ == '__main__':
    app.run(debug=True, port=5000)



