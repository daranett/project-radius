from flask import Flask, render_template, request, flash, redirect, url_for, jsonify, session
import psycopg2
import time
from config import Config
from werkzeug.security import check_password_hash, generate_password_hash
import functools
from datetime import datetime, timedelta, timezone
import traceback
import os
import subprocess
from werkzeug.utils import secure_filename
from flask import send_file
import re
import psutil
import threading

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

# === HELPER FUNCTIONS ===
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

def convert_data_limit_to_bytes(data_limit_str):
    """Convert data limit string (e.g., '10GB', '500MB') to bytes"""
    if not data_limit_str:
        return None
    try:
        data_limit_str = data_limit_str.strip().upper()
        match = re.match(r'^(\d+(?:\.\d+)?)\s*([KMGT]?B?)$', data_limit_str)
        if not match:
            return None
        value = float(match.group(1))
        unit = match.group(2)
        
        multipliers = {
            'B': 1, 'KB': 1024, 'MB': 1024 ** 2, 'GB': 1024 ** 3, 'TB': 1024 ** 4,
            'K': 1024, 'M': 1024 ** 2, 'G': 1024 ** 3, 'T': 1024 ** 4
        }
        multiplier = multipliers.get(unit, 1)
        return int(value * multiplier)
    except Exception as e:
        print(f"DEBUG: Error converting data limit: {str(e)}")
        return None

# === BACKGROUND CLEANUP THREAD ===
def cleanup_stale_sessions():
    """Background task to clean up stale sessions"""
    while True:
        try:
            execute_query("""
                DELETE FROM radacct 
                WHERE acctstoptime IS NULL 
                AND acctstarttime < NOW() - INTERVAL '2 hours'
            """, fetch=False)
            
            execute_query("""
                DELETE FROM radacct
                WHERE radacctid NOT IN (
                    SELECT DISTINCT ON (username) radacctid
                    FROM radacct
                    WHERE acctstoptime IS NULL
                    ORDER BY username, acctstarttime DESC
                )
                AND acctstoptime IS NULL
            """, fetch=False)
            
            print(f"[{datetime.now()}] Cleaned up stale sessions")
        except Exception as e:
            print(f"[ERROR] Failed to clean sessions: {str(e)}")
        
        time.sleep(3600)  # Run every hour

def start_cleanup_thread():
    cleanup_thread = threading.Thread(target=cleanup_stale_sessions, daemon=True)
    cleanup_thread.start()
    print("Background session cleanup thread started")

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

# === PROFILE ROUTES ===
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

@app.route('/backup')
@login_required
def backup_page():
    return render_template('backup/index.html')

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

# === NAS API ROUTES ===
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
            """, (data['nasname'], data['shortname'], data['type'], data['ports'], data['secret'],
                  data.get('server', ''), data.get('community', ''), data.get('description', '')), fetch=False)
        except:
            execute_query("""
                INSERT INTO nas (nasname, shortname, type, ports, secret, server, community, description)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            """, (data['nasname'], data['shortname'], data['type'], data['ports'], data['secret'],
                  data.get('server', ''), data.get('community', ''), data.get('description', '')), fetch=False)
        
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

# === USER API ROUTES ===
@app.route('/api/users')
def api_users():
    try:
        users = execute_query("""
            SELECT c.id, c.username, c.attribute, c.op, c.value as password,
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
        
        # Insert password
        execute_query("""
            INSERT INTO radcheck (username, attribute, op, value)
            VALUES (%s, 'Cleartext-Password', ':=', %s)
        """, (data['username'], data['password']), fetch=False)
        
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
        
        # Optional attributes
        if data.get('ip_address'):
            execute_query("""
                INSERT INTO radreply (username, attribute, op, value)
                VALUES (%s, 'Framed-IP-Address', ':=', %s)
            """, (data['username'], data['ip_address']), fetch=False)
        
        if data.get('rate_limit'):
            execute_query("""
                INSERT INTO radreply (username, attribute, op, value)
                VALUES (%s, 'Mikrotik-Rate-Limit', ':=', %s)
            """, (data['username'], data['rate_limit']), fetch=False)
        
        if data.get('session_timeout'):
            execute_query("""
                INSERT INTO radreply (username, attribute, op, value)
                VALUES (%s, 'Session-Timeout', ':=', %s)
            """, (data['username'], data['session_timeout']), fetch=False)
        
        if data.get('idle_timeout'):
            execute_query("""
                INSERT INTO radreply (username, attribute, op, value)
                VALUES (%s, 'Idle-Timeout', ':=', %s)
            """, (data['username'], data['idle_timeout']), fetch=False)
        
        if data.get('data_limit'):
            data_limit_bytes = convert_data_limit_to_bytes(data['data_limit'])
            if data_limit_bytes:
                execute_query("""
                    INSERT INTO radreply (username, attribute, op, value)
                    VALUES (%s, 'Mikrotik-Total-Limit', ':=', %s)
                """, (data['username'], str(data_limit_bytes)), fetch=False)
        
        return jsonify({'success': True, 'message': 'User added successfully'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/users/update/<username>', methods=['PUT'])
def api_update_user(username):
    try:
        data = get_request_data()
        
        if data.get('ip_address'):
            execute_query("DELETE FROM radreply WHERE username = %s AND attribute = 'Framed-IP-Address'", (username,), fetch=False)
            execute_query("INSERT INTO radreply (username, attribute, op, value) VALUES (%s, 'Framed-IP-Address', ':=', %s)", 
                         (username, data['ip_address']), fetch=False)
        
        if data.get('rate_limit'):
            execute_query("DELETE FROM radreply WHERE username = %s AND attribute = 'Mikrotik-Rate-Limit'", (username,), fetch=False)
            execute_query("INSERT INTO radreply (username, attribute, op, value) VALUES (%s, 'Mikrotik-Rate-Limit', ':=', %s)", 
                         (username, data['rate_limit']), fetch=False)
        
        if data.get('session_timeout'):
            execute_query("DELETE FROM radreply WHERE username = %s AND attribute = 'Session-Timeout'", (username,), fetch=False)
            execute_query("INSERT INTO radreply (username, attribute, op, value) VALUES (%s, 'Session-Timeout', ':=', %s)", 
                         (username, data['session_timeout']), fetch=False)
        
        if data.get('idle_timeout'):
            execute_query("DELETE FROM radreply WHERE username = %s AND attribute = 'Idle-Timeout'", (username,), fetch=False)
            execute_query("INSERT INTO radreply (username, attribute, op, value) VALUES (%s, 'Idle-Timeout', ':=', %s)", 
                         (username, data['idle_timeout']), fetch=False)
        
        if data.get('data_limit'):
            data_limit_bytes = convert_data_limit_to_bytes(data['data_limit'])
            if data_limit_bytes:
                execute_query("DELETE FROM radreply WHERE username = %s AND attribute = 'Mikrotik-Total-Limit'", (username,), fetch=False)
                execute_query("INSERT INTO radreply (username, attribute, op, value) VALUES (%s, 'Mikrotik-Total-Limit', ':=', %s)", 
                             (username, str(data_limit_bytes)), fetch=False)
        
        if data.get('password'):
            execute_query("UPDATE radcheck SET value = %s WHERE username = %s AND attribute = 'Cleartext-Password'", 
                         (data['password'], username), fetch=False)
        
        return jsonify({'success': True, 'message': 'User updated successfully'})
    except Exception as e:
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

# === SESSION API ROUTES ===
@app.route('/api/sessions')
def api_sessions():
    try:
        sessions = execute_query("""
            SELECT DISTINCT ON (username, acctsessionid)
                   radacctid, acctsessionid, acctuniqueid, username,
                   nasipaddress, nasportid, nasporttype, acctstarttime,
                   acctsessiontime, acctinputoctets, acctoutputoctets,
                   calledstationid, callingstationid, framedipaddress,
                   framedprotocol, servicetype, connectinfo_start,
                   CASE WHEN acctstoptime IS NULL THEN 'active' ELSE 'inactive' END as status
            FROM radacct
            WHERE acctstoptime IS NULL
            ORDER BY username, acctsessionid, acctstarttime DESC
        """)
        return jsonify(sessions)
    except Exception as e:
        print(f"Error in api_sessions: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/sessions/cleanup', methods=['POST'])
@login_required
def api_cleanup_sessions():
    try:
        execute_query("""
            DELETE FROM radacct 
            WHERE acctstoptime IS NULL 
            AND acctstarttime < NOW() - INTERVAL '2 hours'
        """, fetch=False)
        
        execute_query("""
            DELETE FROM radacct
            WHERE radacctid NOT IN (
                SELECT DISTINCT ON (username) radacctid
                FROM radacct
                WHERE acctstoptime IS NULL
                ORDER BY username, acctstarttime DESC
            )
            AND acctstoptime IS NULL
        """, fetch=False)
        
        return jsonify({'success': True, 'message': 'Stale sessions cleaned up successfully'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/sessions/disconnect/<session_id>', methods=['POST'])
@login_required
def api_disconnect_session(session_id):
    try:
        execute_query("""
            UPDATE radacct 
            SET acctstoptime = NOW(), acctterminatecause = 'Admin-Reset'
            WHERE acctsessionid = %s
        """, (session_id,), fetch=False)
        
        return jsonify({'success': True, 'message': 'Session disconnected successfully'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/sessions/disconnect-user/<username>', methods=['POST'])
@login_required
def api_disconnect_user_sessions(username):
    try:
        sessions = execute_query("""
            SELECT acctsessionid FROM radacct 
            WHERE username = %s AND acctstoptime IS NULL
        """, (username,))
        
        for session in sessions:
            execute_query("""
                UPDATE radacct 
                SET acctstoptime = NOW(), acctterminatecause = 'Admin-Reset'
                WHERE acctsessionid = %s
            """, (session['acctsessionid'],), fetch=False)
        
        return jsonify({'success': True, 'message': f'Disconnected {len(sessions)} sessions for {username}'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/logs')
def api_logs():
    try:
        logs = execute_query("""
            SELECT id, username, reply, authdate, pass, 
                   calledstationid, callingstationid
            FROM radpostauth
            ORDER BY authdate DESC
            LIMIT 50
        """)
        return jsonify(logs)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# === DASHBOARD API ROUTES - FIXED ===

@app.route('/api/auth-activity')
def api_auth_activity():
    """Get authentication activity for the last 30 minutes"""
    try:
        activity = execute_query("""
            SELECT DATE_TRUNC('minute', authdate) as minute,
                   COUNT(*) as attempts
            FROM radpostauth
            WHERE authdate >= NOW() - INTERVAL '30 minutes'
            GROUP BY DATE_TRUNC('minute', authdate)
            ORDER BY minute
        """)
        
        labels = []
        data = []
        for item in activity:
            labels.append(item['minute'].strftime('%H:%M'))
            data.append(item['attempts'])
        
        return jsonify({'labels': labels, 'data': data})
    except Exception as e:
        print(f"Error in auth activity: {str(e)}")
        return jsonify({'labels': [], 'data': []})

@app.route('/api/sessions-by-nas')
def api_sessions_by_nas():
    """Get session distribution by NAS device - FIXED TYPE CASTING"""
    try:
        sessions = execute_query("""
            SELECT COALESCE(nas.shortname, nas.nasname, 'Unknown') as nasname,
                   COUNT(radacct.acctsessionid) as session_count
            FROM radacct
            LEFT JOIN nas ON CAST(radacct.nasipaddress AS TEXT) = CAST(nas.nasname AS TEXT)
            WHERE radacct.acctstoptime IS NULL
            GROUP BY COALESCE(nas.shortname, nas.nasname, 'Unknown')
            ORDER BY session_count DESC
        """)
        
        labels = []
        data = []
        for item in sessions:
            labels.append(item['nasname'])
            data.append(item['session_count'])
        
        return jsonify({'labels': labels, 'data': data})
    except Exception as e:
        print(f"Error in sessions by NAS: {str(e)}")
        return jsonify({'labels': [], 'data': []})

@app.route('/api/recent-activity')
def api_recent_activity():
    """Get recent authentication activity - FIXED TIMEZONE ISSUE"""
    try:
        activity = execute_query("""
            SELECT username, reply, authdate, 
                   calledstationid, callingstationid
            FROM radpostauth
            WHERE authdate >= NOW() - INTERVAL '30 minutes'
            ORDER BY authdate DESC
            LIMIT 10
        """)
        
        formatted_activity = []
        # Get current time with timezone awareness
        now = datetime.now(timezone.utc)
        
        for item in activity:
            is_success = item['reply'] == 'Access-Accept'
            icon = 'fa-check-circle' if is_success else 'fa-times-circle'
            color = 'green' if is_success else 'red'
            text = f"User {item['username']} {'login successful' if is_success else 'login failed'}"
            
            # Make authdate timezone-aware if it isn't already
            authdate = item['authdate']
            if authdate.tzinfo is None:
                authdate = authdate.replace(tzinfo=timezone.utc)
            
            # Calculate time difference
            time_diff = now - authdate
            
            if time_diff.total_seconds() < 60:
                time_text = 'Just now'
            else:
                minutes = int(time_diff.total_seconds() / 60)
                time_text = f"{minutes} min ago"
            
            formatted_activity.append({
                'type': color,
                'icon': icon,
                'text': text,
                'time': time_text,
                'color': color,
                'username': item['username'],
                'reply': item['reply'],
                'calledstationid': item.get('calledstationid', ''),
                'callingstationid': item.get('callingstationid', '')
            })
        
        return jsonify(formatted_activity)
    except Exception as e:
        print(f"Error in recent activity: {str(e)}")
        return jsonify([])

@app.route('/api/system-metrics')
def api_system_metrics():
    """Get system performance metrics"""
    try:
        cpu_percent = psutil.cpu_percent(interval=1)
        memory = psutil.virtual_memory()
        
        try:
            db_connections = execute_query("""
                SELECT count(*) as connections 
                FROM pg_stat_activity 
                WHERE state = 'active'
            """)[0]['connections']
        except:
            db_connections = 0
        
        try:
            disk_usage = psutil.disk_usage(BACKUP_FOLDER)
            disk_percent = (disk_usage.used / disk_usage.total) * 100
        except:
            disk_usage = type('obj', (object,), {'used': 0, 'total': 1})()
            disk_percent = 0
        
        return jsonify({
            'cpu_percent': round(cpu_percent, 1),
            'memory_percent': round(memory.percent, 1),
            'memory_used': f"{round(memory.used / (1024**3), 1)}GB",
            'memory_total': f"{round(memory.total / (1024**3), 1)}GB",
            'db_connections': db_connections,
            'db_max_connections': 100,
            'disk_percent': round(disk_percent, 1),
            'disk_used': f"{round(disk_usage.used / (1024**3), 1)}GB",
            'disk_total': f"{round(disk_usage.total / (1024**3), 1)}GB"
        })
    except Exception as e:
        print(f"Error in system metrics: {str(e)}")
        return jsonify({
            'cpu_percent': 0, 'memory_percent': 0,
            'memory_used': '0GB', 'memory_total': '0GB',
            'db_connections': 0, 'db_max_connections': 100,
            'disk_percent': 0, 'disk_used': '0GB', 'disk_total': '0GB'
        })

# === BACKUP API ROUTES (shortened for space) ===
# ... (include all backup routes from original code)

@app.route('/health')
def health():
    return 'OK'

if __name__ == '__main__':
    start_cleanup_thread()
    app.run(host='0.0.0.0', port=5000, debug=True)
