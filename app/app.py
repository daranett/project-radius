from flask import Flask, render_template, request, flash, redirect, url_for, jsonify, session
import psycopg2
import time
from config import Config
from werkzeug.security import check_password_hash, generate_password_hash
import functools
from datetime import datetime
import traceback
import os
import subprocess
from werkzeug.utils import secure_filename
from flask import send_file
app = Flask(__name__)
app.config['SECRET_KEY'] = 'radius-dashboard-secret-2024'
app.config['SESSION_TYPE'] = 'filesystem'
app.config['SESSION_PERMANENT'] = True
app.config['SESSION_COOKIE_SECURE'] = False
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config.from_object(Config)
# === BACKUP & RESTORE CONFIGURATION ===
BACKUP_FOLDER = 'backups'
ALLOWED_BACKUP_EXTENSIONS = {'sql', 'backup'}
def ensure_backup_folder():
    if not os.path.exists(BACKUP_FOLDER):
        os.makedirs(BACKUP_FOLDER)
def allowed_backup_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_BACKUP_EXTENSIONS
def format_file_size(size_bytes):
    if size_bytes == 0:
        return '0 B'
   
    size_names = ['B', 'KB', 'MB', 'GB']
    i = 0
    while size_bytes >= 1024 and i < len(size_names) - 1:
        size_bytes /= 1024.0
        i += 1
   
    return f"{size_bytes:.2f} {size_names[i]}"
# === LOGIN REQUIRED DECORATOR ===
def login_required(f):
    @functools.wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function
# === DATABASE CONNECTION ===
def get_db_connection():
    return psycopg2.connect(
        host=app.config['DB_HOST'],
        database=app.config['DB_NAME'],
        user=app.config['DB_USER'],
        password=app.config['DB_PASSWORD'],
        port=app.config['DB_PORT']
    )
def execute_query(query, params=None, fetch=True):
    conn = get_db_connection()
    cur = conn.cursor()
    try:
        cur.execute(query, params)
        if fetch:
            result = cur.fetchall()
            columns = [desc[0] for desc in cur.description]
            return [dict(zip(columns, row)) for row in result]
        else:
            conn.commit()
            return True
    except Exception as e:
        conn.rollback()
        raise e
    finally:
        cur.close()
        conn.close()
# === HELPER FUNCTION FOR JSON REQUESTS ===
def get_request_data():
    try:
        if request.is_json:
            return request.get_json()
        else:
            data = request.form.to_dict()
            for key in data:
                if data[key] == '':
                    data[key] = None
            return data
    except Exception as e:
        print(f"DEBUG: Error getting request data: {str(e)}")
        return {}
# === HELPER FUNCTION FOR DATA LIMIT CONVERSION ===
def convert_data_limit_to_bytes(data_limit_str):
    """Convert data limit string (e.g., '10GB', '500MB') to bytes"""
    if not data_limit_str:
        return None
   
    try:
        data_limit_str = data_limit_str.strip().upper()
       
        # Extract number and unit
        import re
        match = re.match(r'^(\d+(?:\.\d+)?)\s*([KMGT]?B?)$', data_limit_str)
        if not match:
            return None
       
        value = float(match.group(1))
        unit = match.group(2)
       
        # Convert to bytes
        multipliers = {
            'B': 1,
            'KB': 1024,
            'MB': 1024 ** 2,
            'GB': 1024 ** 3,
            'TB': 1024 ** 4,
            'K': 1024,
            'M': 1024 ** 2,
            'G': 1024 ** 3,
            'T': 1024 ** 4
        }
       
        multiplier = multipliers.get(unit, 1)
        return int(value * multiplier)
    except Exception as e:
        print(f"DEBUG: Error converting data limit: {str(e)}")
        return None
# === BACKUP & RESTORE ROUTES ===
@app.route('/backup')
@login_required
def backup_page():
    return render_template('backup/index.html')
@app.route('/api/backup/check-folder')
@login_required
def api_check_backup_folder():
    try:
        ensure_backup_folder()
       
        folder_info = {
            'backup_folder': BACKUP_FOLDER,
            'absolute_path': os.path.abspath(BACKUP_FOLDER),
            'exists': os.path.exists(BACKUP_FOLDER),
            'is_directory': os.path.isdir(BACKUP_FOLDER),
            'permissions': oct(os.stat(BACKUP_FOLDER).st_mode)[-3:],
            'files': []
        }
       
        if os.path.exists(BACKUP_FOLDER):
            for f in os.listdir(BACKUP_FOLDER):
                filepath = os.path.join(BACKUP_FOLDER, f)
                if os.path.isfile(filepath):
                    stat = os.stat(filepath)
                    folder_info['files'].append({
                        'name': f,
                        'size': stat.st_size,
                        'created': datetime.fromtimestamp(stat.st_ctime).isoformat()
                    })
       
        return jsonify(folder_info)
    except Exception as e:
        return jsonify({'error': str(e)}), 500
@app.route('/api/backup/create', methods=['POST'])
@login_required
def api_create_backup():
    try:
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        backup_filename = f'radius_backup_{timestamp}.sql'
        backup_dir = '/app/backups'
       
        os.makedirs(backup_dir, exist_ok=True)
        backup_path = os.path.join(backup_dir, backup_filename)
       
        dump_cmd = [
            'pg_dump',
            '-h', app.config['DB_HOST'],
            '-U', app.config['DB_USER'],
            '-d', app.config['DB_NAME'],
            '-F', 'p',
            '-f', backup_path
        ]
       
        env = os.environ.copy()
        env['PGPASSWORD'] = app.config['DB_PASSWORD']
       
        result = subprocess.run(
            dump_cmd,
            env=env,
            capture_output=True,
            text=True
        )
       
        if result.returncode == 0:
            file_size = os.path.getsize(backup_path)
            file_size_mb = file_size / (1024 * 1024)
           
            return jsonify({
                'success': True,
                'message': 'Backup created successfully',
                'filename': backup_filename,
                'size': f'{file_size_mb:.2f} MB',
                'path': backup_path
            })
        else:
            return jsonify({
                'success': False,
                'error': f'Backup failed: {result.stderr}'
            }), 500
           
    except Exception as e:
        print(f"Backup error: {str(e)}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500
@app.route('/api/backup/list')
@login_required
def api_backup_list():
    try:
        ensure_backup_folder()
       
        backups = []
        for filename in os.listdir(BACKUP_FOLDER):
            if allowed_backup_file(filename):
                filepath = os.path.join(BACKUP_FOLDER, filename)
                file_stat = os.stat(filepath)
                backups.append({
                    'filename': filename,
                    'size': file_stat.st_size,
                    'created_at': datetime.fromtimestamp(file_stat.st_ctime).strftime('%Y-%m-%d %H:%M:%S'),
                    'size_human': format_file_size(file_stat.st_size)
                })
       
        backups.sort(key=lambda x: x['created_at'], reverse=True)
       
        return jsonify({'success': True, 'backups': backups})
    except Exception as e:
        print(f"Error listing backups: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500
@app.route('/api/backup/download/<filename>')
@login_required
def api_download_backup(filename):
    try:
        backup_dir = '/app/backups'
        filepath = os.path.join(backup_dir, filename)
       
        if not os.path.exists(filepath):
            return jsonify({'error': 'Backup file not found'}), 404
       
        return send_file(
            filepath,
            as_attachment=True,
            download_name=filename,
            mimetype='application/sql'
        )
       
    except Exception as e:
        return jsonify({'error': str(e)}), 500
@app.route('/api/backup/restore', methods=['POST'])
@login_required
def api_restore_backup():
    try:
        if request.content_type and 'application/json' in request.content_type:
            data = request.get_json()
        else:
            data = request.form.to_dict()
       
        filename = data.get('filename')
        if not filename:
            return jsonify({
                'success': False,
                'error': 'Filename is required'
            }), 400
       
        ensure_backup_folder()
        backup_path = os.path.join(BACKUP_FOLDER, filename)
       
        if not os.path.exists(backup_path):
            return jsonify({
                'success': False,
                'error': f'Backup file not found: {filename}'
            }), 404
       
        env = os.environ.copy()
        env['PGPASSWORD'] = app.config['DB_PASSWORD']
       
        result = subprocess.run([
            'psql',
            '-h', app.config['DB_HOST'],
            '-U', app.config['DB_USER'],
            '-d', app.config['DB_NAME'],
            '-f', backup_path
        ], env=env, capture_output=True, text=True)
       
        if result.returncode == 0:
            return jsonify({
                'success': True,
                'message': 'Database restored successfully'
            })
        else:
            print(f"DEBUG: Restore error: {result.stderr}")
            return jsonify({
                'success': False,
                'error': f'Restore failed: {result.stderr}'
            }), 500
           
    except Exception as e:
        print(f"DEBUG: Exception in restore: {str(e)}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500
@app.route('/api/backup/delete/<filename>', methods=['DELETE'])
@login_required
def api_delete_backup(filename):
    try:
        backup_dir = '/app/backups'
        filepath = os.path.join(backup_dir, filename)
       
        if not os.path.exists(filepath):
            return jsonify({
                'success': False,
                'error': 'Backup file not found'
            }), 404
       
        os.remove(filepath)
       
        return jsonify({
            'success': True,
            'message': 'Backup deleted successfully'
        })
       
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500
@app.route('/api/backup/upload', methods=['POST'])
@login_required
def api_upload_backup():
    try:
        file = None
        possible_keys = ['backup_file', 'file', 'upload_file', 'backup']
       
        for key in possible_keys:
            if key in request.files:
                file = request.files[key]
                break
       
        if not file:
            return jsonify({
                'success': False,
                'error': 'No file uploaded. Please use form field: backup_file'
            }), 400
       
        if file.filename == '' or not file.filename:
            return jsonify({
                'success': False,
                'error': 'No file selected'
            }), 400
       
        if not allowed_backup_file(file.filename):
            return jsonify({
                'success': False,
                'error': f'Only {ALLOWED_BACKUP_EXTENSIONS} files are allowed. Received: {file.filename}'
            }), 400
       
        ensure_backup_folder()
        backup_dir = BACKUP_FOLDER
       
        filename = secure_filename(file.filename)
        filepath = os.path.join(backup_dir, filename)
       
        if os.path.exists(filepath):
            name, ext = os.path.splitext(filename)
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"{name}_{timestamp}{ext}"
            filepath = os.path.join(backup_dir, filename)
       
        file.save(filepath)
       
        if os.path.exists(filepath):
            file_size = os.path.getsize(filepath)
           
            return jsonify({
                'success': True,
                'message': 'Backup uploaded successfully',
                'filename': filename,
                'size': format_file_size(file_size),
                'path': filepath
            })
        else:
            return jsonify({
                'success': False,
                'error': 'File failed to save on server'
            }), 500
       
    except Exception as e:
        print(f"DEBUG: Exception during upload: {str(e)}")
        return jsonify({
            'success': False,
            'error': f'Upload failed: {str(e)}'
        }), 500
@app.route('/api/backup/debug')
@login_required
def api_backup_debug():
    try:
        ensure_backup_folder()
       
        debug_info = {
            'backup_folder': BACKUP_FOLDER,
            'folder_exists': os.path.exists(BACKUP_FOLDER),
            'folder_path': os.path.abspath(BACKUP_FOLDER),
            'files_in_folder': [],
            'permissions': {
                'readable': os.access(BACKUP_FOLDER, os.R_OK),
                'writable': os.access(BACKUP_FOLDER, os.W_OK),
                'executable': os.access(BACKUP_FOLDER, os.X_OK)
            }
        }
       
        if os.path.exists(BACKUP_FOLDER):
            for filename in os.listdir(BACKUP_FOLDER):
                filepath = os.path.join(BACKUP_FOLDER, filename)
                if os.path.isfile(filepath):
                    file_stat = os.stat(filepath)
                    debug_info['files_in_folder'].append({
                        'filename': filename,
                        'size': file_stat.st_size,
                        'size_human': format_file_size(file_stat.st_size),
                        'created': datetime.fromtimestamp(file_stat.st_ctime).strftime('%Y-%m-%d %H:%M:%S')
                    })
       
        return jsonify(debug_info)
       
    except Exception as e:
        return jsonify({'error': str(e)}), 500
# === AUTHENTICATION ROUTES ===
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
       
        user = execute_query("SELECT * FROM admin_users WHERE username = %s AND is_active = TRUE", (username,))
       
        if user and check_password_hash(user[0]['password_hash'], password):
            session['user_id'] = user[0]['id']
            session['username'] = user[0]['username']
            session['role'] = user[0]['role']
           
            execute_query("UPDATE admin_users SET last_login = NOW() WHERE id = %s", (user[0]['id'],), fetch=False)
           
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password', 'error')
   
    return render_template('login.html')
@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out', 'info')
    return redirect(url_for('login'))
# === PROFILE & PASSWORD ROUTES ===
@app.route('/profile')
@login_required
def profile_page():
    return render_template('profile.html')
@app.route('/api/change-password', methods=['POST'])
@login_required
def api_change_password():
    try:
        data = get_request_data()
        current_password = data['current_password']
        new_password = data['new_password']
       
        user = execute_query("SELECT * FROM admin_users WHERE id = %s", (session['user_id'],))
       
        if not user or not check_password_hash(user[0]['password_hash'], current_password):
            return jsonify({'success': False, 'error': 'Current password is incorrect'})
       
        new_password_hash = generate_password_hash(new_password)
        execute_query("UPDATE admin_users SET password_hash = %s WHERE id = %s",
                     (new_password_hash, session['user_id']), fetch=False)
       
        return jsonify({'success': True, 'message': 'Password updated successfully'})
       
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})
# === MAIN ROUTES ===
@app.route('/')
@login_required
def dashboard():
    return render_template('dashboard.html')
@app.route('/nas')
@login_required
def nas_page():
    return render_template('nas.html')
@app.route('/users')
@login_required
def users_page():
    return render_template('users.html')
@app.route('/sessions')
@login_required
def sessions_page():
    return render_template('sessions.html')
@app.route('/logs')
@login_required
def logs_page():
    return render_template('logs.html')
# === API ROUTES ===
@app.route('/api/stats')
def api_stats():
    try:
        total_users = execute_query("SELECT COUNT(*) as count FROM radcheck")[0]['count']
        active_sessions = execute_query("SELECT COUNT(*) as count FROM radacct WHERE acctstoptime IS NULL")[0]['count']
        today_auth = execute_query("SELECT COUNT(*) as count FROM radpostauth WHERE DATE(authdate) = CURRENT_DATE")[0]['count']
        try:
            total_nas = execute_query("SELECT COUNT(*) as count FROM nas")[0]['count']
        except:
            total_nas = 0
        return jsonify({
            'total_users': total_users,
            'active_sessions': active_sessions,
            'today_auth': today_auth,
            'total_nas': total_nas
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500
@app.route('/api/nas')
def api_nas():
    try:
        nas_list = execute_query("SELECT * FROM nas ORDER BY id")
        return jsonify(nas_list)
    except Exception as e:
        if 'relation "nas" does not exist' in str(e):
            return jsonify([])
        return jsonify({'error': str(e)}), 500
@app.route('/api/nas/add', methods=['POST'])
def api_add_nas():
    try:
        data = get_request_data()
        try:
            execute_query("SELECT limit_proxy_state, require_ma FROM nas LIMIT 1")
            execute_query("""
                INSERT INTO nas (nasname, shortname, type, ports, secret, server, community, description, limit_proxy_state, require_ma)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, 'auto', 'auto')
            """, (
                data['nasname'], data['shortname'], data['type'], data['ports'],
                data['secret'], data.get('server', ''), data.get('community', ''), data.get('description', '')
            ), fetch=False)
        except:
            execute_query("""
                INSERT INTO nas (nasname, shortname, type, ports, secret, server, community, description)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            """, (
                data['nasname'], data['shortname'], data['type'], data['ports'],
                data['secret'], data.get('server', ''), data.get('community', ''), data.get('description', '')
            ), fetch=False)
        return jsonify({'success': True, 'message': 'NAS added successfully'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500
@app.route('/api/nas/delete/<int:nas_id>', methods=['DELETE'])
def api_delete_nas(nas_id):
    try:
        execute_query("DELETE FROM nas WHERE id = %s", (nas_id,), fetch=False)
        return jsonify({'success': True, 'message': 'NAS deleted successfully'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500
@app.route('/api/users')
def api_users():
    try:
        users = execute_query("""
            SELECT
                c.id,
                c.username,
                c.attribute,
                c.op,
                c.value as password,
                (SELECT value FROM radreply r1 WHERE r1.username = c.username AND r1.attribute = 'Framed-IP-Address' LIMIT 1) as ip_address,
                (SELECT value FROM radreply r2 WHERE r2.username = c.username AND r2.attribute = 'Mikrotik-Rate-Limit' LIMIT 1) as rate_limit,
                (SELECT value FROM radreply r3 WHERE r3.username = c.username AND r3.attribute = 'Session-Timeout' LIMIT 1) as session_timeout,
                (SELECT value FROM radreply r4 WHERE r4.username = c.username AND r4.attribute = 'Idle-Timeout' LIMIT 1) as idle_timeout,
                (SELECT value FROM radreply r5 WHERE r5.username = c.username AND r5.attribute = 'Mikrotik-Total-Limit' LIMIT 1) as data_limit,
                (SELECT COUNT(*) FROM radacct a WHERE a.username = c.username AND a.acctstoptime IS NULL) as active_sessions
            FROM radcheck c
            WHERE c.attribute = 'Cleartext-Password'
            ORDER BY c.username
        """)
        return jsonify(users)
    except Exception as e:
        return jsonify({'error': str(e)}), 500
@app.route('/api/users/add', methods=['POST'])
def api_add_user():
    try:
        data = get_request_data()
        print(f"DEBUG: Starting to add user: {data['username']}")
        # Insert password ke radcheck
        execute_query("""
            INSERT INTO radcheck (username, attribute, op, value)
            VALUES (%s, 'Cleartext-Password', ':=', %s)
        """, (data['username'], data['password']), fetch=False)
        print(f"DEBUG: radcheck inserted for {data['username']}")
        # PPP attributes
        ppp_attributes = [
            ('Framed-Protocol', ':=', 'PPP'),
            ('Service-Type', ':=', 'Framed-User'),
            ('Framed-Compression', ':=', 'Van-Jacobson-TCP-IP')
        ]
        for attr, op, value in ppp_attributes:
            execute_query("""
                INSERT INTO radreply (username, attribute, op, value)
                VALUES (%s, %s, %s, %s)
            """, (data['username'], attr, op, value), fetch=False)
        print(f"DEBUG: PPP attributes added for {data['username']}")
        # IP Address
        if data.get('ip_address'):
            execute_query("""
                INSERT INTO radreply (username, attribute, op, value)
                VALUES (%s, 'Framed-IP-Address', ':=', %s)
            """, (data['username'], data['ip_address']), fetch=False)
            print(f"DEBUG: IP address {data['ip_address']} added")
        # ✨ RATE LIMIT DENGAN PRIORITY & BURST
        if data.get('rate_limit'):
            rate_limit = data['rate_limit'] # e.g., "10M/10M"
            priority = data.get('priority', '5') # Default priority 5
           
            # Parse rate limit
            parts = rate_limit.split('/')
            if len(parts) == 2:
                down_speed = parts[0].strip()
                up_speed = parts[1].strip()
               
                # Extract numeric value
                down_val = int(''.join(filter(str.isdigit, down_speed)))
                up_val = int(''.join(filter(str.isdigit, up_speed)))
                unit_down = ''.join(filter(str.isalpha, down_speed)) or 'M'
                unit_up = ''.join(filter(str.isalpha, up_speed)) or 'M'
               
                # Calculate burst (2x speed) and threshold (50% speed)
                burst_down = f"{down_val * 2}{unit_down}"
                burst_up = f"{up_val * 2}{unit_up}"
                threshold_down = f"{max(1, down_val // 2)}{unit_down}"
                threshold_up = f"{max(1, up_val // 2)}{unit_up}"
               
                # Format lengkap: speed burst threshold burst_time priority
                full_rate_limit = f"{rate_limit} {burst_down}/{burst_up} {threshold_down}/{threshold_up} 8/8 {priority}/{priority}"
            else:
                # Fallback jika format tidak sesuai
                full_rate_limit = rate_limit
           
            execute_query("""
                INSERT INTO radreply (username, attribute, op, value)
                VALUES (%s, 'Mikrotik-Rate-Limit', ':=', %s)
            """, (data['username'], full_rate_limit), fetch=False)
            print(f"DEBUG: Rate limit added: {full_rate_limit}")
        # Session Timeout
        if data.get('session_timeout'):
            execute_query("""
                INSERT INTO radreply (username, attribute, op, value)
                VALUES (%s, 'Session-Timeout', ':=', %s)
            """, (data['username'], data['session_timeout']), fetch=False)
        # Idle Timeout
        if data.get('idle_timeout'):
            execute_query("""
                INSERT INTO radreply (username, attribute, op, value)
                VALUES (%s, 'Idle-Timeout', ':=', %s)
            """, (data['username'], data['idle_timeout']), fetch=False)
        # Data Limit (convert to bytes)
        if data.get('data_limit'):
            data_limit_bytes = convert_data_limit_to_bytes(data['data_limit'])
            if data_limit_bytes:
                execute_query("""
                    INSERT INTO radreply (username, attribute, op, value)
                    VALUES (%s, 'Mikrotik-Total-Limit', ':=', %s)
                """, (data['username'], str(data_limit_bytes)), fetch=False)
                print(f"DEBUG: Data limit added: {data['data_limit']} = {data_limit_bytes} bytes")
        print(f"DEBUG: User {data['username']} added SUCCESSFULLY with priority")
        return jsonify({'success': True, 'message': 'User added successfully with priority settings'})
    except Exception as e:
        print(f"DEBUG: ERROR adding user: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500
@app.route('/api/users/update/<username>', methods=['PUT'])
def api_update_user(username):
    try:
        data = get_request_data()
        print(f"DEBUG: Starting to update user: {username}")
        # Update IP Address
        if data.get('ip_address'):
            execute_query("DELETE FROM radreply WHERE username = %s AND attribute = 'Framed-IP-Address'", (username,), fetch=False)
            execute_query("INSERT INTO radreply (username, attribute, op, value) VALUES (%s, 'Framed-IP-Address', ':=', %s)",
                         (username, data['ip_address']), fetch=False)
            print(f"DEBUG: IP address updated to {data['ip_address']}")
        # ✨ Update Rate Limit WITH PRIORITY & BURST
        if data.get('rate_limit'):
            rate_limit = data['rate_limit']
            priority = data.get('priority', '5')
           
            parts = rate_limit.split('/')
            if len(parts) == 2:
                down_speed = parts[0].strip()
                up_speed = parts[1].strip()
               
                down_val = int(''.join(filter(str.isdigit, down_speed)))
                up_val = int(''.join(filter(str.isdigit, up_speed)))
                unit_down = ''.join(filter(str.isalpha, down_speed)) or 'M'
                unit_up = ''.join(filter(str.isalpha, up_speed)) or 'M'
               
                burst_down = f"{down_val * 2}{unit_down}"
                burst_up = f"{up_val * 2}{unit_up}"
                threshold_down = f"{max(1, down_val // 2)}{unit_down}"
                threshold_up = f"{max(1, up_val // 2)}{unit_up}"
               
                full_rate_limit = f"{rate_limit} {burst_down}/{burst_up} {threshold_down}/{threshold_up} 8/8 {priority}/{priority}"
            else:
                full_rate_limit = rate_limit
           
            execute_query("DELETE FROM radreply WHERE username = %s AND attribute = 'Mikrotik-Rate-Limit'", (username,), fetch=False)
            execute_query("INSERT INTO radreply (username, attribute, op, value) VALUES (%s, 'Mikrotik-Rate-Limit', ':=', %s)",
                         (username, full_rate_limit), fetch=False)
            print(f"DEBUG: Rate limit updated to {full_rate_limit}")
        # Update Session Timeout
        if data.get('session_timeout'):
            execute_query("DELETE FROM radreply WHERE username = %s AND attribute = 'Session-Timeout'", (username,), fetch=False)
            execute_query("INSERT INTO radreply (username, attribute, op, value) VALUES (%s, 'Session-Timeout', ':=', %s)",
                         (username, data['session_timeout']), fetch=False)
        # Update Idle Timeout
        if data.get('idle_timeout'):
            execute_query("DELETE FROM radreply WHERE username = %s AND attribute = 'Idle-Timeout'", (username,), fetch=False)
            execute_query("INSERT INTO radreply (username, attribute, op, value) VALUES (%s, 'Idle-Timeout', ':=', %s)",
                         (username, data['idle_timeout']), fetch=False)
        # Update Data Limit (convert to bytes)
        if data.get('data_limit'):
            data_limit_bytes = convert_data_limit_to_bytes(data['data_limit'])
            if data_limit_bytes:
                execute_query("DELETE FROM radreply WHERE username = %s AND attribute = 'Mikrotik-Total-Limit'", (username,), fetch=False)
                execute_query("INSERT INTO radreply (username, attribute, op, value) VALUES (%s, 'Mikrotik-Total-Limit', ':=', %s)",
                             (username, str(data_limit_bytes)), fetch=False)
                print(f"DEBUG: Data limit updated: {data['data_limit']} = {data_limit_bytes} bytes")
        print(f"DEBUG: User {username} updated SUCCESSFULLY")
        return jsonify({'success': True, 'message': 'User updated successfully'})
    except Exception as e:
        print(f"DEBUG: ERROR updating user: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500
@app.route('/api/users/delete/<int:user_id>', methods=['DELETE'])
def api_delete_user(user_id):
    try:
        user = execute_query("SELECT username FROM radcheck WHERE id = %s", (user_id,))
        if user:
            username = user[0]['username']
            execute_query("DELETE FROM radcheck WHERE username = %s", (username,), fetch=False)
            execute_query("DELETE FROM radreply WHERE username = %s", (username,), fetch=False)
            return jsonify({'success': True, 'message': 'User deleted successfully'})
        else:
            return jsonify({'success': False, 'error': 'User not found'}), 404
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500
@app.route('/api/sessions')
def api_sessions():
    try:
        sessions = execute_query("""
            SELECT
                radacctid,
                acctsessionid,
                acctuniqueid,
                username,
                nasipaddress,
                nasportid,
                nasporttype,
                acctstarttime,
                acctsessiontime,
                acctinputoctets,
                acctoutputoctets,
                calledstationid,
                callingstationid,
                framedipaddress,
                framedprotocol,
                servicetype,
                connectinfo_start
            FROM radacct
            WHERE acctstoptime IS NULL
            ORDER BY acctstarttime DESC
        """)
        return jsonify(sessions)
    except Exception as e:
        return jsonify({'error': str(e)}), 500
@app.route('/api/logs')
def api_logs():
    try:
        logs = execute_query("""
            SELECT
                id,
                username,
                reply,
                authdate,
                pass,
                calledstationid,
                callingstationid
            FROM radpostauth
            ORDER BY authdate DESC
            LIMIT 50
        """)
        return jsonify(logs)
    except Exception as e:
        return jsonify({'error': str(e)}), 500
@app.route('/health')
def health():
    return 'OK'
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
