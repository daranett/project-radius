from flask import Flask, render_template, request, flash, redirect, url_for, jsonify, session
import psycopg2
import time
from config import Config
from werkzeug.security import check_password_hash, generate_password_hash
import functools

app = Flask(__name__)
app.config['SECRET_KEY'] = 'radius-dashboard-secret-2024'
app.config.from_object(Config)


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


# === AUTHENTICATION ROUTES ===
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        # Cek user di database
        user = execute_query("SELECT * FROM admin_users WHERE username = %s AND is_active = TRUE", (username,))
        
        if user and check_password_hash(user[0]['password_hash'], password):
            # Login sukses
            session['user_id'] = user[0]['id']
            session['username'] = user[0]['username']
            session['role'] = user[0]['role']
            
            # Update last login
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
        data = request.get_json()
        current_password = data['current_password']
        new_password = data['new_password']
        
        # Verify current password
        user = execute_query("SELECT * FROM admin_users WHERE id = %s", (session['user_id'],))
        
        if not user or not check_password_hash(user[0]['password_hash'], current_password):
            return jsonify({'success': False, 'error': 'Current password is incorrect'})
        
        # Update to new password
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

        # Handle NAS count
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
        data = request.get_json()

        # Check if NAS table has the new columns
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
        data = request.get_json()
        print(f"🟢 DEBUG: Starting to add user: {data['username']}")  # ✅ DEBUG

        # Add to radcheck - Password
        execute_query("""
            INSERT INTO radcheck (username, attribute, op, value)
            VALUES (%s, 'Cleartext-Password', ':=', %s)
        """, (data['username'], data['password']), fetch=False)
        print(f"🟢 DEBUG: radcheck inserted for {data['username']}")  # ✅ DEBUG

        # Add PPPoE attributes to radreply
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
        print(f"🟢 DEBUG: PPP attributes added for {data['username']}")  # ✅ DEBUG

        # Add IP address if provided
        if data.get('ip_address'):
            execute_query("""
                INSERT INTO radreply (username, attribute, op, value)
                VALUES (%s, 'Framed-IP-Address', ':=', %s)
            """, (data['username'], data['ip_address']), fetch=False)
            print(f"🟢 DEBUG: IP address {data['ip_address']} added")  # ✅ DEBUG

        # Add rate limit if provided
        if data.get('rate_limit'):
            execute_query("""
                INSERT INTO radreply (username, attribute, op, value)
                VALUES (%s, 'Mikrotik-Rate-Limit', ':=', %s)
            """, (data['username'], data['rate_limit']), fetch=False)
            print(f"🟢 DEBUG: Rate limit {data['rate_limit']} added")  # ✅ DEBUG

        # Add session timeout if provided
        if data.get('session_timeout'):
            execute_query("""
                INSERT INTO radreply (username, attribute, op, value)
                VALUES (%s, 'Session-Timeout', ':=', %s)
            """, (data['username'], data['session_timeout']), fetch=False)

        # Add idle timeout if provided
        if data.get('idle_timeout'):
            execute_query("""
                INSERT INTO radreply (username, attribute, op, value)
                VALUES (%s, 'Idle-Timeout', ':=', %s)
            """, (data['username'], data['idle_timeout']), fetch=False)

        # Add data limit if provided
        if data.get('data_limit'):
            execute_query("""
                INSERT INTO radreply (username, attribute, op, value)
                VALUES (%s, 'Mikrotik-Total-Limit', ':=', %s)
            """, (data['username'], data['data_limit']), fetch=False)

        print(f"🟢 DEBUG: User {data['username']} added SUCCESSFULLY")  # ✅ DEBUG
        return jsonify({'success': True, 'message': 'User added successfully with all attributes'})
    except Exception as e:
        print(f"🔴 DEBUG: ERROR adding user: {str(e)}")  # ✅ DEBUG
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/users/update/<username>', methods=['PUT'])
def api_update_user(username):
    try:
        data = request.get_json()
        print(f"🟢 DEBUG: Starting to update user: {username}")  # ✅ DEBUG

        # Update IP address jika provided
        if data.get('ip_address'):
            execute_query("""
                DELETE FROM radreply 
                WHERE username = %s AND attribute = 'Framed-IP-Address'
            """, (username,), fetch=False)
            execute_query("""
                INSERT INTO radreply (username, attribute, op, value)
                VALUES (%s, 'Framed-IP-Address', ':=', %s)
            """, (username, data['ip_address']), fetch=False)
            print(f"🟢 DEBUG: IP address updated to {data['ip_address']}")  # ✅ DEBUG

        # Update rate limit jika provided
        if data.get('rate_limit'):
            execute_query("""
                DELETE FROM radreply 
                WHERE username = %s AND attribute = 'Mikrotik-Rate-Limit'
            """, (username,), fetch=False)
            execute_query("""
                INSERT INTO radreply (username, attribute, op, value)
                VALUES (%s, 'Mikrotik-Rate-Limit', ':=', %s)
            """, (username, data['rate_limit']), fetch=False)
            print(f"🟢 DEBUG: Rate limit updated to {data['rate_limit']}")  # ✅ DEBUG

        # Update session timeout jika provided
        if data.get('session_timeout'):
            execute_query("""
                DELETE FROM radreply 
                WHERE username = %s AND attribute = 'Session-Timeout'
            """, (username,), fetch=False)
            execute_query("""
                INSERT INTO radreply (username, attribute, op, value)
                VALUES (%s, 'Session-Timeout', ':=', %s)
            """, (username, data['session_timeout']), fetch=False)

        # Update idle timeout jika provided
        if data.get('idle_timeout'):
            execute_query("""
                DELETE FROM radreply 
                WHERE username = %s AND attribute = 'Idle-Timeout'
            """, (username,), fetch=False)
            execute_query("""
                INSERT INTO radreply (username, attribute, op, value)
                VALUES (%s, 'Idle-Timeout', ':=', %s)
            """, (username, data['idle_timeout']), fetch=False)

        # Update data limit jika provided
        if data.get('data_limit'):
            execute_query("""
                DELETE FROM radreply 
                WHERE username = %s AND attribute = 'Mikrotik-Total-Limit'
            """, (username,), fetch=False)
            execute_query("""
                INSERT INTO radreply (username, attribute, op, value)
                VALUES (%s, 'Mikrotik-Total-Limit', ':=', %s)
            """, (username, data['data_limit']), fetch=False)

        print(f"🟢 DEBUG: User {username} updated SUCCESSFULLY")  # ✅ DEBUG
        return jsonify({'success': True, 'message': 'User updated successfully'})
    except Exception as e:
        print(f"🔴 DEBUG: ERROR updating user: {str(e)}")  # ✅ DEBUG
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
            SELECT * FROM radacct
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
