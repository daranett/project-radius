from flask import Flask, render_template, request, flash, redirect, url_for, jsonify, session
import psycopg2
import time
from config import Config
from werkzeug.security import check_password_hash, generate_password_hash
import functools
import routeros_api
from routeros_api.exceptions import RouterOsApiConnectionError, RouterOsApiCommunicationError
from datetime import datetime
import traceback
import os
import subprocess
from werkzeug.utils import secure_filename
from flask import send_file

app = Flask(__name__)
app.config['SECRET_KEY'] = 'radius-dashboard-secret-2024'
app.config['SESSION_TYPE'] = 'filesystem'  # Gunakan filesystem session
app.config['SESSION_PERMANENT'] = True  # Session persisten
app.config['SESSION_COOKIE_SECURE'] = False  # Set True jika pakai HTTPS
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config.from_object(Config)
app.config['UPLOAD_FOLDER'] = 'static/uploads/customers'
app.config['MAX_CONTENT_LENGTH'] = 2 * 1024 * 1024  # 2MB
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
# Konfigurasi upload file
app.config['UPLOAD_FOLDER'] = 'static/uploads/customers'
app.config['MAX_CONTENT_LENGTH'] = 2 * 1024 * 1024  # 2MB
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# === BACKUP & RESTORE CONFIGURATION ===
BACKUP_FOLDER = 'backups'
ALLOWED_BACKUP_EXTENSIONS = {'sql', 'backup'}

def ensure_backup_folder():
    """Ensure backup folder exists"""
    if not os.path.exists(BACKUP_FOLDER):
        os.makedirs(BACKUP_FOLDER)
        print(f"Created backup folder: {BACKUP_FOLDER}")

def allowed_backup_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_BACKUP_EXTENSIONS
def format_file_size(size_bytes):
    """Format file size to human readable"""
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
    """Handle both form data and JSON data"""
    try:
        if request.is_json:
            return request.get_json()
        else:
            # Handle form data
            data = request.form.to_dict()
            # Convert empty strings to None for database
            for key in data:
                if data[key] == '':
                    data[key] = None
            return data
    except Exception as e:
        print(f"DEBUG: Error getting request data: {str(e)}")
        return {}


# === MIKROTIK HELPER FUNCTIONS ===
def get_nas_devices():
    """Get all NAS devices from database"""
    try:
        return execute_query("SELECT * FROM nas ORDER BY id")
    except Exception as e:
        print(f"Error getting NAS devices: {e}")
        return []

def get_nas_by_id(nas_id):
    """Get NAS device by ID"""
    try:
        result = execute_query("SELECT * FROM nas WHERE id = %s", (nas_id,))
        return result[0] if result else None
    except Exception as e:
        print(f"Error getting NAS by ID: {e}")
        return None

def format_bytes(bytes_str):
    """Format bytes to human readable format"""
    try:
        bytes_val = int(bytes_str)
        if bytes_val < 1024:
            return f"{bytes_val} B"
        elif bytes_val < 1024*1024:
            return f"{bytes_val/1024:.1f} KB"
        elif bytes_val < 1024*1024*1024:
            return f"{bytes_val/(1024*1024):.1f} MB"
        else:
            return f"{bytes_val/(1024*1024*1024):.1f} GB"
    except:
        return "0 B"

def format_rate(rate_str):
    """Format rate to human readable format"""
    try:
        rate_val = int(rate_str)
        if rate_val < 1000:
            return f"{rate_val} b/s"
        elif rate_val < 1000000:
            return f"{rate_val/1000:.1f} Kb/s"
        else:
            return f"{rate_val/1000000:.1f} Mb/s"
    except:
        return "0 b/s"

def calculate_disk_usage(api):
    """Return USB and Internal Flash usage - REAL-TIME"""
    usb_usage = 0
    flash_usage = 0
    try:
        # USB - /disk
        try:
            disk_resource = api.get_resource('/disk')
            disks = disk_resource.get()
            print(f"DEBUG: /disk response: {disks}")
            if disks:
                for disk in disks:
                    mount = disk.get('mount-point', '')
                    if mount and mount not in ['swap', ''] and mount:
                        use = disk.get('use', '0%')
                        print(f"DEBUG: Disk found: {mount}, use={use}")
                        try:
                            usb_usage = int(use.replace("%", ""))
                        except:
                            pass
        except Exception as e:
            print(f"DEBUG: /disk failed: {e}")

        # Internal Flash - /system/resource
        system_resource = api.get_resource('/system/resource')
        system_info = system_resource.get()
        if system_info and system_info[0].get('total-hdd-space'):
            total_kb = int(system_info[0].get('total-hdd-space', 1))
            free_kb = int(system_info[0].get('free-hdd-space', 0))
            if total_kb > 0:
                flash_usage = int(((total_kb - free_kb) / total_kb) * 100)
                print(f"DEBUG: Internal flash usage: {flash_usage}%")

        print(f"DEBUG: USB: {usb_usage}%, Flash: {flash_usage}%")
        return usb_usage, flash_usage

    except Exception as e:
        print(f"DEBUG: calculate_disk_usage error: {e}")
        return 0, 0

def calculate_memory_usage(system_info):
    """Calculate memory usage properly"""
    try:
        if system_info:
            free_memory = int(system_info[0].get('free-memory', 0))
            total_memory = int(system_info[0].get('total-memory', 1))
            if total_memory > 0:
                used_memory = total_memory - free_memory
                usage_percent = (used_memory / total_memory) * 100
                return round(usage_percent, 1)
        return 0
    except:
        return 0

def save_mikrotik_credentials_db(nas_id, username, password, port=8728):
    """Save MikroTik credentials to database"""
    try:
        print("  → Ensuring table exists...")
        # Ensure table exists
        execute_query("""
            CREATE TABLE IF NOT EXISTS mikrotik_credentials (
                id SERIAL PRIMARY KEY,
                nas_id INTEGER NOT NULL UNIQUE,
                username VARCHAR(100) NOT NULL,
                password VARCHAR(255) NOT NULL,
                port INTEGER DEFAULT 8728,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (nas_id) REFERENCES nas(id) ON DELETE CASCADE
            )
        """, fetch=False)
        print("  ✓ Table ready")
        
        print(f"  → Inserting/updating credentials for NAS {nas_id}...")
        # Insert or update
        execute_query("""
            INSERT INTO mikrotik_credentials (nas_id, username, password, port)
            VALUES (%s, %s, %s, %s)
            ON CONFLICT (nas_id) 
            DO UPDATE SET 
                username = EXCLUDED.username,
                password = EXCLUDED.password,
                port = EXCLUDED.port,
                updated_at = CURRENT_TIMESTAMP
        """, (nas_id, username, password, port), fetch=False)
        
        print(f"  ✓ Database insert/update successful")
        return True
        
    except Exception as e:
        print(f"  ✗ Database error: {str(e)}")
        print(traceback.format_exc())
        return False


def get_mikrotik_credentials_db(nas_id):
    """Get MikroTik credentials from database"""
    try:
        print(f"  → Querying database for NAS {nas_id}...")
        result = execute_query("""
            SELECT username, password, port 
            FROM mikrotik_credentials 
            WHERE nas_id = %s
        """, (nas_id,))
        
        if result:
            print(f"  ✓ Found credentials in database")
            return result[0]
        else:
            print(f"  ✗ No credentials found in database")
            return None
            
    except Exception as e:
        print(f"  ✗ Database query error: {str(e)}")
        
        # If table doesn't exist, try to create it
        if 'does not exist' in str(e):
            print(f"  → Table doesn't exist, creating...")
            try:
                execute_query("""
                    CREATE TABLE IF NOT EXISTS mikrotik_credentials (
                        id SERIAL PRIMARY KEY,
                        nas_id INTEGER NOT NULL UNIQUE,
                        username VARCHAR(100) NOT NULL,
                        password VARCHAR(255) NOT NULL,
                        port INTEGER DEFAULT 8728,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        FOREIGN KEY (nas_id) REFERENCES nas(id) ON DELETE CASCADE
                    )
                """, fetch=False)
                print(f"  ✓ Table created successfully")
            except Exception as create_error:
                print(f"  ✗ Error creating table: {str(create_error)}")
        
        return None

# === MIKROTIK MONITORING WITH HISTORY ===
monitoring_history = {}

# === TRAFFIC RATE CALCULATION HISTORY (per NAS) ===
traffic_history = {}

def calculate_rates(nas_id, interface_name, current_rx, current_tx):
    current_time = time.time()
    key = f"{nas_id}_{interface_name}"
    
    if key not in traffic_history:
        traffic_history[key] = {
            'last_rx': current_rx,
            'last_tx': current_tx,
            'last_time': current_time
        }
        return 0, 0
    
    history = traffic_history[key]
    time_diff = current_time - history['last_time']
    
    if time_diff >= 2:  # Minimal 2 detik
        rx_rate = int((current_rx - history['last_rx']) * 8 / time_diff)
        tx_rate = int((current_tx - history['last_tx']) * 8 / time_diff)
        
        traffic_history[key] = {
            'last_rx': current_rx,
            'last_tx': current_tx,
            'last_time': current_time
        }
        return rx_rate, tx_rate
    else:
        return 0, 0

# === BACKUP & RESTORE ROUTES ===
import subprocess
import os
from datetime import datetime
import tempfile

@app.route('/backup')
@login_required
def backup_page():
    return render_template('backup/index.html')

@app.route('/api/backup/create', methods=['POST'])
@login_required
def api_create_backup():
    """Create database backup"""
    try:
        # Generate backup filename with timestamp
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        backup_filename = f'radius_backup_{timestamp}.sql'
        backup_dir = '/app/backups'
        
        # Create backup directory if not exists
        os.makedirs(backup_dir, exist_ok=True)
        
        backup_path = os.path.join(backup_dir, backup_filename)
        
        # PostgreSQL dump command
        dump_cmd = [
            'pg_dump',
            '-h', app.config['DB_HOST'],
            '-U', app.config['DB_USER'],
            '-d', app.config['DB_NAME'],
            '-F', 'p',  # Plain text format
            '-f', backup_path
        ]
        
        # Set password environment variable
        env = os.environ.copy()
        env['PGPASSWORD'] = app.config['DB_PASSWORD']
        
        # Execute backup
        result = subprocess.run(
            dump_cmd,
            env=env,
            capture_output=True,
            text=True
        )
        
        if result.returncode == 0:
            # Get file size
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
    """List all available backups"""
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
        
        # Sort by created date (newest first)
        backups.sort(key=lambda x: x['created_at'], reverse=True)
        
        return jsonify({'success': True, 'backups': backups})
    except Exception as e:
        print(f"Error listing backups: {str(e)}")
        import traceback
        print(traceback.format_exc())
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/backup/download/<filename>')
@login_required
def api_download_backup(filename):
    """Download backup file"""
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
    """Restore database from backup"""
    try:
        data = get_request_data()
        filename = data.get('filename')
        
        if not filename:
            return jsonify({
                'success': False,
                'error': 'Filename is required'
            }), 400
        
        backup_dir = '/app/backups'
        backup_path = os.path.join(backup_dir, filename)
        
        if not os.path.exists(backup_path):
            return jsonify({
                'success': False,
                'error': 'Backup file not found'
            }), 404
        
        # PostgreSQL restore command
        restore_cmd = [
            'psql',
            '-h', app.config['DB_HOST'],
            '-U', app.config['DB_USER'],
            '-d', app.config['DB_NAME'],
            '-f', backup_path
        ]
        
        # Set password environment variable
        env = os.environ.copy()
        env['PGPASSWORD'] = app.config['DB_PASSWORD']
        
        # Execute restore
        result = subprocess.run(
            restore_cmd,
            env=env,
            capture_output=True,
            text=True
        )
        
        if result.returncode == 0:
            return jsonify({
                'success': True,
                'message': 'Database restored successfully'
            })
        else:
            return jsonify({
                'success': False,
                'error': f'Restore failed: {result.stderr}'
            }), 500
            
    except Exception as e:
        print(f"Restore error: {str(e)}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/backup/delete/<filename>', methods=['DELETE'])
@login_required
def api_delete_backup(filename):
    """Delete backup file"""
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
    """Upload backup file"""
    try:
        if 'backup_file' not in request.files:
            return jsonify({
                'success': False,
                'error': 'No file uploaded'
            }), 400
        
        file = request.files['backup_file']
        
        if file.filename == '':
            return jsonify({
                'success': False,
                'error': 'No file selected'
            }), 400
        
        if not file.filename.endswith('.sql'):
            return jsonify({
                'success': False,
                'error': 'Only .sql files are allowed'
            }), 400
        
        backup_dir = '/app/backups'
        os.makedirs(backup_dir, exist_ok=True)
        
        # Save file
        filepath = os.path.join(backup_dir, secure_filename(file.filename))
        file.save(filepath)
        
        return jsonify({
            'success': True,
            'message': 'Backup uploaded successfully',
            'filename': file.filename
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/mikrotik/<int:nas_id>/monitoring/realtime')
@login_required
def mikrotik_monitoring_realtime(nas_id):
    try:
        print(f"DEBUG: Starting realtime monitoring for NAS ID: {nas_id}")
        
        # Get NAS device details
        nas = get_nas_by_id(nas_id)
        if not nas:
            print("DEBUG: NAS device not found")
            return jsonify({'success': False, 'error': 'NAS device not found'}), 404
        
        print(f"DEBUG: Found NAS: {nas['nasname']} - {nas['shortname']}")
        
        # Get credentials - cek session dulu, lalu database
        session_key = f'mikrotik_creds_{nas_id}'
        creds = session.get(session_key, {})
        
        if not creds.get('username') or not creds.get('password'):
            db_creds = get_mikrotik_credentials_db(nas_id)
            if db_creds:
                creds = {
                    'username': db_creds['username'],
                    'password': db_creds['password'],
                    'port': db_creds['port']
                }
                session[session_key] = creds
            else:
                print("DEBUG: No credentials configured in database")
                return jsonify({'success': False, 'error': 'MikroTik credentials not configured. Please set username and password in Settings.'}), 400
        
        print(f"DEBUG: Using credentials: {creds}")
        
        mikrotik_ip = nas['nasname']
        mikrotik_username = creds.get('username', 'admin')
        mikrotik_password = creds.get('password', '')
        mikrotik_port = creds.get('port', 8728)
        
        if not mikrotik_password:
            print("DEBUG: No password configured")
            return jsonify({'success': False, 'error': 'MikroTik credentials not configured. Please set username and password in Settings.'}), 400
        
        print(f"DEBUG: Attempting connection to {mikrotik_ip}:{mikrotik_port} with user {mikrotik_username}")
        
        # Connect to MikroTik
        try:
            connection = routeros_api.RouterOsApiPool(
                mikrotik_ip,
                username=mikrotik_username,
                password=mikrotik_password,
                port=mikrotik_port,
                plaintext_login=True,
                use_ssl=False
            )
            api = connection.get_api()
            print("DEBUG: Successfully connected to MikroTik")
        except Exception as conn_error:
            print(f"DEBUG: Connection failed: {str(conn_error)}")
            return jsonify({'success': False, 'error': f'Connection failed: {str(conn_error)}'}), 500
        
        # Get monitoring data
        try:
            # System resource
            system_resource = api.get_resource('/system/resource')
            system_info = system_resource.get()
            print(f"DEBUG: System info retrieved")
            
            # Interfaces
            interface_resource = api.get_resource('/interface')
            interfaces = interface_resource.get()
            print(f"DEBUG: Found {len(interfaces)} interfaces")
            
            # Identity
            identity_resource = api.get_resource('/system/identity')
            identity = identity_resource.get()
            print(f"DEBUG: Identity retrieved")
            
            # v7+: Gunakan rx-byte/tx-byte → hitung rate manual
            print("DEBUG: Using manual rate calculation from rx-byte/tx-byte")

        except Exception as data_error:
            print(f"DEBUG: Data retrieval failed: {str(data_error)}")
            connection.disconnect()
            return jsonify({'success': False, 'error': f'Data retrieval failed: {str(data_error)}'}), 500
        
        # === HITUNG DISK USAGE SEBELUM DISCONNECT ===
        usb_usage, flash_usage = calculate_disk_usage(api)
        
        connection.disconnect()
        
        # Process data untuk grafik
        current_time = int(time.time() * 1000)
        
        # Initialize history untuk device ini
        if nas_id not in monitoring_history:
            monitoring_history[nas_id] = {
                'cpu': [],
                'memory': [],
                'interfaces': {}
            }
        
        # Process system resources
        cpu_load = system_info[0].get('cpu-load', '0') if system_info else '0'
        memory_usage = calculate_memory_usage(system_info)
        
        # Update CPU history
        monitoring_history[nas_id]['cpu'].append({
            'time': current_time,
            'value': float(cpu_load)
        })
        if len(monitoring_history[nas_id]['cpu']) > 60:
            monitoring_history[nas_id]['cpu'].pop(0)
        
        # Update memory history
        monitoring_history[nas_id]['memory'].append({
            'time': current_time,
            'value': float(memory_usage)
        })
        if len(monitoring_history[nas_id]['memory']) > 60:
            monitoring_history[nas_id]['memory'].pop(0)
        
        # Process interfaces dengan perhitungan manual
        processed_interfaces = []
        interface_count = 0
        
        for iface in interfaces:
            name = iface.get('name', '')
            iface_type = iface.get('type', '')
            
            # Filter interface penting
            if not (name.startswith(('ether', 'vlan', 'bridge', 'pppoe')) and 
                    iface_type in ['ether', 'vlan', 'bridge', 'ppp-out']):
                continue
            
            # Ambil byte counter
            rx_bytes = int(iface.get('rx-byte', 0))
            tx_bytes = int(iface.get('tx-byte', 0))
            
            # HITUNG RATE MANUAL
            rx_rate, tx_rate = calculate_rates(nas_id, name, rx_bytes, tx_bytes)
            
            # Update history
            if name not in monitoring_history[nas_id]['interfaces']:
                monitoring_history[nas_id]['interfaces'][name] = {'rx': [], 'tx': []}
            
            monitoring_history[nas_id]['interfaces'][name]['rx'].append({
                'time': current_time,
                'value': rx_rate
            })
            monitoring_history[nas_id]['interfaces'][name]['tx'].append({
                'time': current_time,
                'value': tx_rate
            })
            
            # Keep last 30
            if len(monitoring_history[nas_id]['interfaces'][name]['rx']) > 30:
                monitoring_history[nas_id]['interfaces'][name]['rx'].pop(0)
                monitoring_history[nas_id]['interfaces'][name]['tx'].pop(0)
            
            processed_interfaces.append({
                'name': name,
                'type': iface_type,
                'running': iface.get('running', 'false') == 'true',
                'rx_rate': format_rate(str(rx_rate)),
                'tx_rate': format_rate(str(tx_rate)),
                'rx_bits': rx_rate,
                'tx_bits': tx_rate,
                'rx_total': format_bytes(str(rx_bytes)),
                'tx_total': format_bytes(str(tx_bytes))
            })
            
            interface_count += 1
            if interface_count >= 12:
                break
        
        # Prepare response
        monitoring_data = {
            'success': True,
            'timestamp': current_time,
            'system': {
                'hostname': identity[0].get('name', 'Unknown') if identity else 'Unknown',
                'version': system_info[0].get('version', 'N/A') if system_info else 'N/A',
                'uptime': system_info[0].get('uptime', 'N/A') if system_info else 'N/A',
                'board': system_info[0].get('board-name', 'N/A') if system_info else 'N/A',
            },
            'resources': {
                'cpu': cpu_load,
                'memory': str(memory_usage),
                'disk_usb': str(usb_usage),
                'disk_flash': str(flash_usage)
            },
            'interfaces': processed_interfaces,
            'history': {
                'cpu': monitoring_history[nas_id]['cpu'][-30:],
                'memory': monitoring_history[nas_id]['memory'][-30:],
                'interfaces': monitoring_history[nas_id]['interfaces']
            }
        }
        
        print(f"DEBUG: Successfully prepared monitoring data with {len(processed_interfaces)} interfaces")
        if processed_interfaces:
            print(f"DEBUG: Sample traffic - {processed_interfaces[0]['name']}: RX={processed_interfaces[0]['rx_rate']}, TX={processed_interfaces[0]['tx_rate']}")
        return jsonify(monitoring_data)
        
    except RouterOsApiConnectionError as e:
        print(f"DEBUG: RouterOS API Connection Error: {str(e)}")
        return jsonify({'success': False, 'error': f'Cannot connect to MikroTik device. Check IP address, port, and network connectivity.'}), 500
    except RouterOsApiCommunicationError as e:
        print(f"DEBUG: RouterOS API Communication Error: {str(e)}")
        return jsonify({'success': False, 'error': f'Authentication failed. Check username and password.'}), 401
    except Exception as e:
        print(f"DEBUG: Unexpected error: {str(e)}")
        import traceback
        print(f"DEBUG: Traceback: {traceback.format_exc()}")
        return jsonify({'success': False, 'error': f'Unexpected error: {str(e)}'}), 500

# === REPORTS API ===
@app.route('/api/billing/reports/summary')
@login_required
def api_billing_reports_summary():
    """Get billing summary reports"""
    try:
        # Monthly income summary
        monthly_income = execute_query("""
            SELECT 
                EXTRACT(YEAR FROM i.created_at) as year,
                EXTRACT(MONTH FROM i.created_at) as month,
                COUNT(i.id) as invoice_count,
                COALESCE(SUM(i.amount), 0) as total_amount,
                COALESCE(SUM(CASE WHEN i.status = 'paid' THEN i.amount ELSE 0 END), 0) as paid_amount,
                COALESCE(SUM(CASE WHEN i.status = 'pending' THEN i.amount ELSE 0 END), 0) as pending_amount
            FROM billing_invoices i
            WHERE i.deleted_at IS NULL
            GROUP BY year, month
            ORDER BY year DESC, month DESC
            LIMIT 12
        """)
        
        # Package performance
        package_performance = execute_query("""
            SELECT 
                p.name as package_name,
                COUNT(c.id) as customer_count,
                COUNT(i.id) as invoice_count,
                COALESCE(SUM(i.amount), 0) as total_revenue
            FROM billing_packages p
            LEFT JOIN billing_customers c ON p.id = c.package_id AND c.deleted_at IS NULL
            LEFT JOIN billing_invoices i ON c.id = i.customer_id AND i.deleted_at IS NULL
            WHERE p.deleted_at IS NULL
            GROUP BY p.id, p.name
            ORDER BY total_revenue DESC
        """)
        
        # Payment methods summary
        payment_methods = execute_query("""
            SELECT 
                payment_method,
                COUNT(*) as transaction_count,
                COALESCE(SUM(amount), 0) as total_amount
            FROM billing_payments 
            WHERE deleted_at IS NULL
            GROUP BY payment_method
            ORDER BY total_amount DESC
        """)
        
        return jsonify({
            'monthly_income': monthly_income,
            'package_performance': package_performance,
            'payment_methods': payment_methods
        })
        
    except Exception as e:
        print(f"DEBUG: Error loading reports: {str(e)}")
        return jsonify({'error': str(e)}), 500

# === RECORD PAYMENT ROUTE ===
@app.route('/api/billing/payments/record', methods=['POST'])
@login_required
def api_record_payment():
    """Record payment for invoice"""
    try:
        data = get_request_data()
        
        # Validasi data yang required
        if not data.get('invoice_id') or not data.get('amount'):
            return jsonify({'success': False, 'error': 'Invoice ID dan amount wajib diisi'})
        
        # Cek apakah invoice exists
        invoice = execute_query("""
            SELECT i.*, c.full_name, p.name as package_name, p.price_monthly as invoice_amount
            FROM billing_invoices i
            JOIN billing_customers c ON i.customer_id = c.id
            JOIN billing_packages p ON i.package_id = p.id
            WHERE i.id = %s AND i.deleted_at IS NULL
        """, (data['invoice_id'],))
        
        if not invoice:
            return jsonify({'success': False, 'error': 'Invoice tidak ditemukan'}), 404
        
        invoice_data = invoice[0]
        
        # Record payment - GUNAKAN method DARI FRONTEND
        execute_query("""
            INSERT INTO billing_payments 
            (invoice_id, payment_method, amount, reference_number, notes, payment_date)
            VALUES (%s, %s, %s, %s, %s, CURRENT_TIMESTAMP)
        """, (
            data['invoice_id'],
            data.get('method', 'cash'),  # INI YANG DIUBAH
            data['amount'],
            data.get('reference_number', ''),
            data.get('notes', 'Pembayaran invoice')
        ), fetch=False)
        
        # Update invoice status to paid if payment covers full amount
        if float(data['amount']) >= float(invoice_data['invoice_amount']):
            execute_query("""
                UPDATE billing_invoices 
                SET status = 'paid'
                WHERE id = %s AND deleted_at IS NULL
            """, (data['invoice_id'],), fetch=False)
        
        return jsonify({
            'success': True, 
            'message': 'Pembayaran berhasil dicatat'
        })
        
    except Exception as e:
        print(f"DEBUG: Error recording payment: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500


# === BILLING ROUTES ===

@app.route('/billing/packages')
@login_required
def billing_packages():
    return render_template('billing/packages.html')

@app.route('/billing/customers')
@login_required
def billing_customers():
    return render_template('billing/customers.html')

@app.route('/billing/invoices')
@login_required
def billing_invoices():
    return render_template('billing/invoices.html')

@app.route('/billing/payments')
@login_required
def billing_payments():
    return render_template('billing/payments.html')

@app.route('/billing/reports')
@login_required
def billing_reports():
    return render_template('billing/reports.html')

# === BILLING API ROUTES ===

@app.route('/api/billing/stats')
@login_required
def api_billing_stats():
    """Get billing statistics for dashboard"""
    try:
        stats = execute_query("""
            SELECT 
                (SELECT COUNT(*) FROM billing_customers WHERE status = 'active' AND deleted_at IS NULL) as active_customers,
                (SELECT COUNT(*) FROM billing_invoices WHERE status = 'pending' AND deleted_at IS NULL) as pending_invoices,
                (SELECT COALESCE(SUM(amount), 0) FROM billing_payments WHERE DATE(payment_date) = CURRENT_DATE AND deleted_at IS NULL) as today_income,
                (SELECT COALESCE(SUM(amount), 0) FROM billing_invoices WHERE status = 'paid' AND period_month = EXTRACT(MONTH FROM CURRENT_DATE) AND deleted_at IS NULL) as monthly_income,
                (SELECT COUNT(*) FROM billing_packages WHERE is_active = true AND deleted_at IS NULL) as active_packages,
                (SELECT COUNT(*) FROM billing_packages WHERE deleted_at IS NULL) as total_packages
        """)
        return jsonify(stats[0] if stats else {})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# === PACKAGES CRUD API ===

@app.route('/api/billing/packages')
@login_required
def api_billing_packages():
    """Get all active billing packages"""
    try:
        packages = execute_query("""
            SELECT * FROM billing_packages 
            WHERE deleted_at IS NULL 
            ORDER BY name
        """)
        return jsonify(packages)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/billing/packages/<int:package_id>')
@login_required
def api_get_billing_package(package_id):
    """Get specific package"""
    try:
        package = execute_query("""
            SELECT * FROM billing_packages 
            WHERE id = %s AND deleted_at IS NULL
        """, (package_id,))
        return jsonify(package[0] if package else {})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/billing/packages/add', methods=['POST'])
@login_required
def api_add_billing_package():
    """Add new billing package"""
    try:
        data = get_request_data()
        execute_query("""
            INSERT INTO billing_packages (name, description, price_monthly, price_daily, bandwidth_limit, session_timeout, idle_timeout)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
        """, (
            data['name'], 
            data.get('description', ''), 
            data['price_monthly'], 
            data['price_daily'], 
            data.get('bandwidth_limit', ''), 
            data.get('session_timeout', 3600), 
            data.get('idle_timeout', 300)
        ), fetch=False)
        return jsonify({'success': True, 'message': 'Package added successfully'})
    except Exception as e:
        print(f"DEBUG: Error adding package: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/billing/packages/update/<int:package_id>', methods=['PUT'])
@login_required
def api_update_billing_package(package_id):
    """Update billing package"""
    try:
        data = get_request_data()
        print(f"DEBUG: Updating package {package_id} with data: {data}")
        
        # Check if this is a partial update (e.g., only status toggle)
        if 'name' not in data:
            # Partial update - only update provided fields
            update_fields = []
            update_values = []
            
            if 'is_active' in data:
                update_fields.append("is_active = %s")
                update_values.append(data['is_active'])
            
            if update_fields:
                query = f"UPDATE billing_packages SET {', '.join(update_fields)} WHERE id = %s AND deleted_at IS NULL"
                update_values.append(package_id)
                execute_query(query, tuple(update_values), fetch=False)
        else:
            # Full update - update all fields
            execute_query("""
                UPDATE billing_packages 
                SET name = %s, description = %s, price_monthly = %s, price_daily = %s, 
                    bandwidth_limit = %s, session_timeout = %s, idle_timeout = %s, is_active = %s
                WHERE id = %s AND deleted_at IS NULL
            """, (
                data['name'], data.get('description', ''), data['price_monthly'], data['price_daily'],
                data.get('bandwidth_limit', ''), data.get('session_timeout', 3600), 
                data.get('idle_timeout', 300), data.get('is_active', True), package_id
            ), fetch=False)
        
        return jsonify({'success': True, 'message': 'Package updated successfully'})
    except Exception as e:
        print(f"DEBUG: Error updating package: {str(e)}")
        print(f"DEBUG: Traceback: {traceback.format_exc()}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/billing/packages/delete/<int:package_id>', methods=['DELETE'])
@login_required
def api_delete_billing_package(package_id):
    """Soft delete billing package"""
    try:
        # Cek apakah package digunakan oleh customers
        customers_using = execute_query("""
            SELECT COUNT(*) as count FROM billing_customers 
            WHERE package_id = %s AND deleted_at IS NULL
        """, (package_id,))
        
        if customers_using and customers_using[0]['count'] > 0:
            return jsonify({'success': False, 'error': 'Cannot delete package. It is being used by customers.'}), 400
        
        execute_query("""
            UPDATE billing_packages SET deleted_at = CURRENT_TIMESTAMP 
            WHERE id = %s AND deleted_at IS NULL
        """, (package_id,), fetch=False)
        return jsonify({'success': True, 'message': 'Package deleted successfully'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

# === CUSTOMERS CRUD API ===

@app.route('/api/billing/customers')
@login_required
def api_billing_customers():
    """Get all active customers"""
    try:
        customers = execute_query("""
            SELECT c.*, p.name as package_name, p.price_monthly,
                   (SELECT COUNT(*) FROM billing_invoices i WHERE i.customer_id = c.id AND i.status = 'pending' AND i.deleted_at IS NULL) as pending_invoices
            FROM billing_customers c
            LEFT JOIN billing_packages p ON c.package_id = p.id
            WHERE c.deleted_at IS NULL
            ORDER BY c.full_name
        """)
        return jsonify(customers)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/billing/customers/<int:customer_id>')
@login_required
def api_get_billing_customer(customer_id):
    """Get specific customer"""
    try:
        customer = execute_query("""
            SELECT c.*, p.name as package_name, p.price_monthly
            FROM billing_customers c
            LEFT JOIN billing_packages p ON c.package_id = p.id
            WHERE c.id = %s AND c.deleted_at IS NULL
        """, (customer_id,))
        
        if customer:
            # Format date untuk frontend
            customer[0]['install_date_formatted'] = customer[0]['install_date'].strftime('%Y-%m-%d') if customer[0]['install_date'] else ''
        
        return jsonify(customer[0] if customer else {})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/billing/customers/add', methods=['POST'])
@login_required
def api_add_billing_customer():
    """Add new billing customer - DIPERBARUI DENGAN FIELD BARU"""
    try:
        data = get_request_data()
        print(f"DEBUG: Adding customer with data: {data}")
        
        # Validasi data yang required
        if not data.get('install_date'):
            return jsonify({'success': False, 'error': 'Tanggal instalasi wajib diisi'})
        
        if not data.get('due_day') or int(data['due_day']) < 1 or int(data['due_day']) > 31:
            return jsonify({'success': False, 'error': 'Tanggal jatuh tempo harus antara 1-31'})
        
        # Handle file upload
        photo_path = None
        if 'photo' in request.files:
            file = request.files['photo']
            if file and file.filename != '' and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                # Create directory if not exists
                os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(file_path)
                photo_path = file_path
                print(f"DEBUG: File saved to {photo_path}")
        
        execute_query("""
            INSERT INTO billing_customers 
            (full_name, email, phone, address, package_id, status, notes, 
             install_date, due_day, lat, lng, technician_notes, photo_path)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """, (
            data['full_name'], 
            data.get('email', ''), 
            data.get('phone', ''), 
            data.get('address', ''), 
            data['package_id'],
            data.get('status', 'active'),
            data.get('notes', ''),
            data.get('install_date'),  # TAMBAHAN
            data.get('due_day', 1),    # TAMBAHAN
            data.get('lat'),           # TAMBAHAN
            data.get('lng'),           # TAMBAHAN
            data.get('technician_notes', ''),  # TAMBAHAN
            photo_path  # TAMBAHAN - photo path
        ), fetch=False)
        
        return jsonify({'success': True, 'message': 'Customer added successfully'})
    except Exception as e:
        print(f"DEBUG: Error adding customer: {str(e)}")
        print(f"DEBUG: Traceback: {traceback.format_exc()}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/billing/customers/update/<int:customer_id>', methods=['PUT'])
@login_required
def api_update_billing_customer(customer_id):
    """Update billing customer - DIPERBARUI DENGAN FIELD BARU"""
    try:
        # Handle form data dengan file upload
        data = request.form.to_dict()
        print(f"DEBUG: Updating customer {customer_id} with data: {data}")
        
        # Validasi due_day
        if data.get('due_day') and (int(data['due_day']) < 1 or int(data['due_day']) > 31):
            return jsonify({'success': False, 'error': 'Tanggal jatuh tempo harus antara 1-31'})
        
        # Handle empty values for database
        install_date = data.get('install_date') if data.get('install_date') else None
        due_day = data.get('due_day', 1)
        lat = data.get('lat') if data.get('lat') else None
        lng = data.get('lng') if data.get('lng') else None
        
        # Handle file upload
        photo_path = None
        if 'photo' in request.files:
            file = request.files['photo']
            if file and file.filename != '' and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                # Create directory if not exists
                os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(file_path)
                photo_path = file_path
                print(f"DEBUG: File saved to {photo_path}")
        
        # Jika ada file upload, update photo_path juga
        if photo_path:
            execute_query("""
                UPDATE billing_customers 
                SET full_name = %s, email = %s, phone = %s, address = %s, 
                    package_id = %s, status = %s, notes = %s,
                    install_date = %s, due_day = %s, lat = %s, lng = %s, 
                    technician_notes = %s, photo_path = %s
                WHERE id = %s AND deleted_at IS NULL
            """, (
                data['full_name'], 
                data.get('email', ''), 
                data.get('phone', ''), 
                data.get('address', ''), 
                data['package_id'], 
                data.get('status', 'active'),
                data.get('notes', ''),
                install_date,  # TAMBAHAN
                due_day,       # TAMBAHAN  
                lat,           # TAMBAHAN
                lng,           # TAMBAHAN
                data.get('technician_notes', ''),  # TAMBAHAN
                photo_path,    # TAMBAHAN - photo path
                customer_id
            ), fetch=False)
        else:
            # Update tanpa mengubah photo_path
            execute_query("""
                UPDATE billing_customers 
                SET full_name = %s, email = %s, phone = %s, address = %s, 
                    package_id = %s, status = %s, notes = %s,
                    install_date = %s, due_day = %s, lat = %s, lng = %s, 
                    technician_notes = %s
                WHERE id = %s AND deleted_at IS NULL
            """, (
                data['full_name'], 
                data.get('email', ''), 
                data.get('phone', ''), 
                data.get('address', ''), 
                data['package_id'], 
                data.get('status', 'active'),
                data.get('notes', ''),
                install_date,  # TAMBAHAN
                due_day,       # TAMBAHAN  
                lat,           # TAMBAHAN
                lng,           # TAMBAHAN
                data.get('technician_notes', ''),  # TAMBAHAN
                customer_id
            ), fetch=False)
        
        return jsonify({'success': True, 'message': 'Customer updated successfully'})
    except Exception as e:
        print(f"DEBUG: Error updating customer: {str(e)}")
        print(f"DEBUG: Traceback: {traceback.format_exc()}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/billing/customers/delete/<int:customer_id>', methods=['DELETE'])
@login_required
def api_delete_billing_customer(customer_id):
    """Soft delete billing customer"""
    try:
        execute_query("""
            UPDATE billing_customers SET deleted_at = CURRENT_TIMESTAMP 
            WHERE id = %s AND deleted_at IS NULL
        """, (customer_id,), fetch=False)
        return jsonify({'success': True, 'message': 'Customer deleted successfully'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

# === MAP & COORDINATES API ===
@app.route('/api/customers/map')
@login_required
def api_customers_map():
    """Get customer locations for map"""
    try:
        customers = execute_query("""
            SELECT id, full_name, lat, lng, address, status
            FROM billing_customers 
            WHERE deleted_at IS NULL 
            AND lat IS NOT NULL 
            AND lng IS NOT NULL
        """)
        return jsonify(customers)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/customers/<int:customer_id>/coordinates', methods=['PUT'])
@login_required
def api_update_customer_coordinates(customer_id):
    """Update customer coordinates only"""
    try:
        data = get_request_data()
        print(f"DEBUG: Updating coordinates for customer {customer_id}: {data}")
        
        execute_query("""
            UPDATE billing_customers 
            SET lat = %s, lng = %s
            WHERE id = %s AND deleted_at IS NULL
        """, (
            data.get('lat'),
            data.get('lng'),
            customer_id
        ), fetch=False)
        
        return jsonify({'success': True, 'message': 'Koordinat berhasil diperbarui'})
    except Exception as e:
        print(f"DEBUG: Error updating coordinates: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500

# === INVOICES API ===

@app.route('/api/billing/invoices')
@login_required
def api_billing_invoices():
    """Get all active invoices"""
    try:
        invoices = execute_query("""
            SELECT i.*, c.full_name, c.email, p.name as package_name
            FROM billing_invoices i
            JOIN billing_customers c ON i.customer_id = c.id
            JOIN billing_packages p ON i.package_id = p.id
            WHERE i.deleted_at IS NULL
            ORDER BY i.created_at DESC
        """)
        return jsonify(invoices)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/billing/invoices/generate', methods=['POST'])
@login_required
def api_generate_invoices():
    """Generate monthly invoices for active customers"""
    try:
        current_month = datetime.now().month
        current_year = datetime.now().year
        
        # Generate invoices for active customers
        result = execute_query("""
            INSERT INTO billing_invoices (customer_id, package_id, period_month, period_year, amount, due_date)
            SELECT 
                c.id,
                c.package_id,
                %s, %s,
                p.price_monthly,
                CURRENT_DATE + INTERVAL '7 days'
            FROM billing_customers c
            JOIN billing_packages p ON c.package_id = p.id
            WHERE c.status = 'active' 
            AND c.deleted_at IS NULL
            AND p.deleted_at IS NULL
            AND NOT EXISTS (
                SELECT 1 FROM billing_invoices i 
                WHERE i.customer_id = c.id 
                AND i.period_month = %s 
                AND i.period_year = %s
                AND i.deleted_at IS NULL
            )
        """, (current_month, current_year, current_month, current_year), fetch=False)
        
        return jsonify({'success': True, 'message': 'Invoices generated successfully'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

# === INVOICE PAYMENT ROUTE ===
@app.route('/api/billing/invoices/pay/<int:invoice_id>', methods=['POST'])
@login_required
def api_pay_invoice(invoice_id):
    """Mark invoice as paid and record payment"""
    try:
        data = get_request_data()
        
        # Cek apakah invoice exists
        invoice = execute_query("""
            SELECT i.*, c.full_name, p.name as package_name, p.price_monthly as amount
            FROM billing_invoices i
            JOIN billing_customers c ON i.customer_id = c.id
            JOIN billing_packages p ON i.package_id = p.id
            WHERE i.id = %s AND i.deleted_at IS NULL
        """, (invoice_id,))
        
        if not invoice:
            return jsonify({'success': False, 'error': 'Invoice tidak ditemukan'}), 404
        
        invoice_data = invoice[0]
        
        # Record payment
        execute_query("""
            INSERT INTO billing_payments 
            (invoice_id, payment_method, amount, reference_number, notes, payment_date)
            VALUES (%s, %s, %s, %s, %s, CURRENT_TIMESTAMP)
        """, (
            invoice_id,
            data.get('payment_method', 'cash'),
            invoice_data['amount'],
            data.get('reference_number', ''),
            data.get('notes', 'Pembayaran invoice')
        ), fetch=False)
        
        # Update invoice status to paid (tanpa paid_at)
        execute_query("""
            UPDATE billing_invoices 
            SET status = 'paid'
            WHERE id = %s AND deleted_at IS NULL
        """, (invoice_id,), fetch=False)
        
        return jsonify({
            'success': True, 
            'message': 'Invoice berhasil dibayar'
        })
        
    except Exception as e:
        print(f"DEBUG: Error paying invoice: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500

# === INVOICE TEMPLATE PAGE ===
@app.route('/billing/invoice/<int:invoice_id>')
@login_required
def invoice_detail_page(invoice_id):
    """Halaman template invoice dengan data dinamis"""
    try:
        # Ambil data invoice dari database
        invoice = execute_query("""
            SELECT i.*, c.full_name, c.email, c.phone, c.address, 
                   p.name as package_name, p.price_monthly as amount,
                   p.bandwidth_limit
            FROM billing_invoices i
            JOIN billing_customers c ON i.customer_id = c.id
            JOIN billing_packages p ON i.package_id = p.id
            WHERE i.id = %s AND i.deleted_at IS NULL
        """, (invoice_id,))
        
        if not invoice:
            flash('Invoice tidak ditemukan', 'error')
            return redirect(url_for('billing_invoices'))
        
        invoice_data = invoice[0]
        
        # Format data untuk template
        # PERBAIKI TYPE CONVERSION DI SINI:
        amount = float(invoice_data['amount'])  # Convert Decimal to float
        tax_amount = int(amount * 0.11)  # 11% PPN
        total_amount = int(amount * 1.11)

# Format data untuk template
        context = {
            'invoice': invoice_data,
            'invoice_number': invoice_data.get('invoice_number', f'INV-{invoice_id:06d}'),
            'customer_name': invoice_data['full_name'],
            'customer_email': invoice_data.get('email', ''),
            'customer_phone': invoice_data.get('phone', ''),
            'customer_address': invoice_data.get('address', ''),
            'package_name': invoice_data['package_name'],
            'bandwidth_limit': invoice_data.get('bandwidth_limit', '50 Mbps'),
            'amount': amount,
            'tax_amount': tax_amount,
            'total_amount': total_amount,
            'invoice_date': invoice_data.get('created_at', datetime.now()).strftime('%d %B %Y'),
            'due_date': invoice_data.get('due_date', datetime.now()).strftime('%d %B %Y'),
            'period_month': invoice_data.get('period_month', datetime.now().month),
            'period_year': invoice_data.get('period_year', datetime.now().year)
}
        
        return render_template('billing/invoice_template.html', **context)
        
    except Exception as e:
        print(f"DEBUG: Error loading invoice: {str(e)}")
        flash('Error memuat invoice', 'error')
        return redirect(url_for('billing_invoices'))

@app.route('/api/billing/invoices/update-status/<int:invoice_id>', methods=['PUT'])
@login_required
def api_update_invoice_status(invoice_id):
    """Update invoice status"""
    try:
        data = get_request_data()
        execute_query("""
            UPDATE billing_invoices 
            SET status = %s
            WHERE id = %s AND deleted_at IS NULL
        """, (data['status'], invoice_id), fetch=False)
        return jsonify({'success': True, 'message': 'Invoice status updated successfully'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

# === PAYMENTS API ===

@app.route('/api/billing/payments')
@login_required
def api_billing_payments():
    """Get all active payments"""
    try:
        payments = execute_query("""
            SELECT 
                p.id,
                p.invoice_id,
                p.amount,
                p.payment_method,
                p.reference_number,
                p.notes,
                p.payment_date,
                p.created_at,
                p.updated_at,
                i.invoice_number,
                c.full_name as customer_name
            FROM billing_payments p
            JOIN billing_invoices i ON p.invoice_id = i.id
            JOIN billing_customers c ON i.customer_id = c.id
            WHERE p.deleted_at IS NULL
            ORDER BY p.payment_date DESC
        """)
        
        # Transform data untuk frontend
        transformed_payments = []
        for payment in payments:
            transformed_payments.append({
                'id': payment['id'],
                'invoice_id': payment['invoice_id'],
                'amount': payment['amount'],
                'method': payment['payment_method'],  # Ubah payment_method jadi method
                'reference_number': payment['reference_number'],
                'notes': payment['notes'],
                'payment_date': payment['payment_date'],
                'invoice_number': payment['invoice_number'],
                'customer_name': payment['customer_name']  # Sudah pakai alias
            })
        
        return jsonify(transformed_payments)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/billing/payments/add', methods=['POST'])
@login_required
def api_add_billing_payment():
    """Add new payment - alternatif untuk payments/record"""
    try:
        data = get_request_data()
        
        # Validasi
        if not data.get('invoice_id') or not data.get('amount'):
            return jsonify({'success': False, 'error': 'Invoice ID dan amount wajib diisi'})
        
        execute_query("""
            INSERT INTO billing_payments (invoice_id, payment_method, amount, reference_number, notes)
            VALUES (%s, %s, %s, %s, %s)
        """, (
            data['invoice_id'],
            data.get('payment_method', 'cash'),
            data['amount'],
            data.get('reference_number', ''),
            data.get('notes', '')
        ), fetch=False)
        
        # Update invoice status
        execute_query("""
            UPDATE billing_invoices 
            SET status = 'paid'
            WHERE id = %s AND amount <= %s AND deleted_at IS NULL
        """, (data['invoice_id'], data['amount']), fetch=False)
        
        return jsonify({'success': True, 'message': 'Payment recorded successfully'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

# === CUSTOMER SEARCH API ===
@app.route('/api/billing/customers/search')
@login_required
def api_search_customers():
    """Search customers dengan berbagai filter"""
    try:
        search = request.args.get('search', '')
        status = request.args.get('status', '')
        package_id = request.args.get('package_id', '')
        
        query = """
            SELECT c.*, p.name as package_name 
            FROM billing_customers c
            LEFT JOIN billing_packages p ON c.package_id = p.id
            WHERE c.deleted_at IS NULL
        """
        params = []
        
        if search:
            query += " AND (c.full_name ILIKE %s OR c.email ILIKE %s OR c.phone ILIKE %s)"
            params.extend([f'%{search}%', f'%{search}%', f'%{search}%'])
        
        if status:
            query += " AND c.status = %s"
            params.append(status)
            
        if package_id:
            query += " AND c.package_id = %s"
            params.append(package_id)
            
        query += " ORDER BY c.full_name"
        
        customers = execute_query(query, params)
        return jsonify(customers)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# === INIT DB ===

@app.route('/api/billing/init-db', methods=['POST'])
@login_required
def api_init_billing_db():
    """Initialize billing database tables"""
    try:
        # Tables sudah dibuat via SQL script, jadi return success
        return jsonify({'success': True, 'message': 'Billing database already initialized'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


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
        data = get_request_data()
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


@app.route('/mikrotik')
@login_required
def mikrotik_monitoring():
    nas_devices = get_nas_devices()
    return render_template('mikrotik_simple.html', nas_devices=nas_devices)


@app.route('/mikrotik-simple')
@login_required
def mikrotik_monitoring_simple():
    nas_devices = get_nas_devices()
    return render_template('mikrotik_simple.html', nas_devices=nas_devices)


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

        execute_query("""
            INSERT INTO radcheck (username, attribute, op, value)
            VALUES (%s, 'Cleartext-Password', ':=', %s)
        """, (data['username'], data['password']), fetch=False)
        print(f"DEBUG: radcheck inserted for {data['username']}")

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

        if data.get('ip_address'):
            execute_query("""
                INSERT INTO radreply (username, attribute, op, value)
                VALUES (%s, 'Framed-IP-Address', ':=', %s)
            """, (data['username'], data['ip_address']), fetch=False)
            print(f"DEBUG: IP address {data['ip_address']} added")

        if data.get('rate_limit'):
            execute_query("""
                INSERT INTO radreply (username, attribute, op, value)
                VALUES (%s, 'Mikrotik-Rate-Limit', ':=', %s)
            """, (data['username'], data['rate_limit']), fetch=False)
            print(f"DEBUG: Rate limit {data['rate_limit']} added")

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
            execute_query("""
                INSERT INTO radreply (username, attribute, op, value)
                VALUES (%s, 'Mikrotik-Total-Limit', ':=', %s)
            """, (data['username'], data['data_limit']), fetch=False)

        print(f"DEBUG: User {data['username']} added SUCCESSFULLY")
        return jsonify({'success': True, 'message': 'User added successfully with all attributes'})
    except Exception as e:
        print(f"DEBUG: ERROR adding user: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/users/update/<username>', methods=['PUT'])
def api_update_user(username):
    try:
        data = get_request_data()
        print(f"DEBUG: Starting to update user: {username}")

        if data.get('ip_address'):
            execute_query("""
                DELETE FROM radreply 
                WHERE username = %s AND attribute = 'Framed-IP-Address'
            """, (username,), fetch=False)
            execute_query("""
                INSERT INTO radreply (username, attribute, op, value)
                VALUES (%s, 'Framed-IP-Address', ':=', %s)
            """, (username, data['ip_address']), fetch=False)
            print(f"DEBUG: IP address updated to {data['ip_address']}")

        if data.get('rate_limit'):
            execute_query("""
                DELETE FROM radreply 
                WHERE username = %s AND attribute = 'Mikrotik-Rate-Limit'
            """, (username,), fetch=False)
            execute_query("""
                INSERT INTO radreply (username, attribute, op, value)
                VALUES (%s, 'Mikrotik-Rate-Limit', ':=', %s)
            """, (username, data['rate_limit']), fetch=False)
            print(f"DEBUG: Rate limit updated to {data['rate_limit']}")

        if data.get('session_timeout'):
            execute_query("""
                DELETE FROM radreply 
                WHERE username = %s AND attribute = 'Session-Timeout'
            """, (username,), fetch=False)
            execute_query("""
                INSERT INTO radreply (username, attribute, op, value)
                VALUES (%s, 'Session-Timeout', ':=', %s)
            """, (username, data['session_timeout']), fetch=False)

        if data.get('idle_timeout'):
            execute_query("""
                DELETE FROM radreply 
                WHERE username = %s AND attribute = 'Idle-Timeout'
            """, (username,), fetch=False)
            execute_query("""
                INSERT INTO radreply (username, attribute, op, value)
                VALUES (%s, 'Idle-Timeout', ':=', %s)
            """, (username, data['idle_timeout']), fetch=False)

        if data.get('data_limit'):
            execute_query("""
                DELETE FROM radreply 
                WHERE username = %s AND attribute = 'Mikrotik-Total-Limit'
            """, (username,), fetch=False)
            execute_query("""
                INSERT INTO radreply (username, attribute, op, value)
                VALUES (%s, 'Mikrotik-Total-Limit', ':=', %s)
            """, (username, data['data_limit']), fetch=False)

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


@app.route('/api/mikrotik/credentials', methods=['POST'])
@login_required
def api_save_mikrotik_credentials():
    try:
        data = get_request_data()
        nas_id = data.get('nas_id')
        username = data.get('username')
        password = data.get('password')
        port = data.get('port', 8728)
        
        print(f"\n{'='*60}")
        print(f"SAVE CREDENTIALS REQUEST")
        print(f"{'='*60}")
        print(f"NAS ID: {nas_id}")
        print(f"Username: {username}")
        print(f"Password: {'*' * len(password) if password else 'EMPTY'}")
        print(f"Port: {port}")
        print(f"{'='*60}\n")
        
        if not nas_id or not username or not password:
            error_msg = f"Missing required fields: nas_id={nas_id}, username={username}, password={'SET' if password else 'EMPTY'}"
            print(f"ERROR: {error_msg}")
            return jsonify({'success': False, 'error': error_msg}), 400
        
        # 1. Save to DATABASE
        print("Step 1: Saving to database...")
        db_success = save_mikrotik_credentials_db(nas_id, username, password, port)
        
        if not db_success:
            print("ERROR: Failed to save to database")
            return jsonify({'success': False, 'error': 'Failed to save to database'}), 500
        
        print("✓ Database save successful")
        
        # 2. Verify database save
        print("\nStep 2: Verifying database save...")
        db_verify = get_mikrotik_credentials_db(nas_id)
        if db_verify:
            print(f"✓ Verification successful: Found username='{db_verify['username']}' in database")
        else:
            print("WARNING: Verification failed - credentials not found after save")
        
        # 3. Save to SESSION
        print("\nStep 3: Saving to session...")
        session_key = f'mikrotik_creds_{nas_id}'
        session[session_key] = {
            'username': username,
            'password': password,
            'port': port
        }
        session.permanent = True
        session.modified = True
        print(f"✓ Session save successful with key: {session_key}")
        
        # 4. Verify session save
        print("\nStep 4: Verifying session save...")
        session_verify = session.get(session_key)
        if session_verify:
            print(f"✓ Session verification successful: {session_verify['username']}")
        else:
            print("WARNING: Session verification failed")
        
        print(f"\n{'='*60}")
        print(f"SAVE COMPLETED SUCCESSFULLY")
        print(f"{'='*60}\n")
        
        return jsonify({
            'success': True, 
            'message': 'Credentials saved successfully',
            'debug': {
                'nas_id': nas_id,
                'username': username,
                'port': port,
                'db_saved': db_success,
                'session_saved': True
            }
        })
        
    except Exception as e:
        print(f"\n{'='*60}")
        print(f"ERROR IN SAVE CREDENTIALS")
        print(f"{'='*60}")
        print(f"Error: {str(e)}")
        print(traceback.format_exc())
        print(f"{'='*60}\n")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/mikrotik/credentials/<int:nas_id>')
@login_required
def api_get_mikrotik_credentials(nas_id):
    try:
        print(f"\n{'='*60}")
        print(f"GET CREDENTIALS REQUEST")
        print(f"{'='*60}")
        print(f"NAS ID: {nas_id}")
        
        # 1. Check SESSION first
        print("\nStep 1: Checking session...")
        session_key = f'mikrotik_creds_{nas_id}'
        creds = session.get(session_key, {})
        
        if creds.get('username') and creds.get('password'):
            print(f"✓ Found in session: username='{creds['username']}', port={creds.get('port', 8728)}")
            print(f"{'='*60}\n")
            return jsonify(creds)
        else:
            print("✗ Not found in session, checking database...")
        
        # 2. Check DATABASE
        print("\nStep 2: Checking database...")
        db_creds = get_mikrotik_credentials_db(nas_id)
        
        if db_creds:
            print(f"✓ Found in database: username='{db_creds['username']}', port={db_creds['port']}")
            
            # 3. Save to session for next time
            print("\nStep 3: Caching to session...")
            creds = {
                'username': db_creds['username'],
                'password': db_creds['password'],
                'port': db_creds['port']
            }
            session[session_key] = creds
            session.permanent = True
            session.modified = True
            print(f"✓ Cached to session with key: {session_key}")
            
            print(f"\n{'='*60}")
            print(f"GET COMPLETED - FOUND IN DATABASE")
            print(f"{'='*60}\n")
            
            return jsonify(creds)
        else:
            print("✗ Not found in database")
            print(f"\n{'='*60}")
            print(f"GET COMPLETED - NOT FOUND")
            print(f"{'='*60}\n")
            return jsonify({})
        
    except Exception as e:
        print(f"\n{'='*60}")
        print(f"ERROR IN GET CREDENTIALS")
        print(f"{'='*60}")
        print(f"Error: {str(e)}")
        print(traceback.format_exc())
        print(f"{'='*60}\n")
        return jsonify({'error': str(e)}), 500


# === MIKROTIK MONITORING API ROUTES (Original - untuk kompatibilitas) ===
@app.route('/api/mikrotik/<int:nas_id>/monitoring')
@login_required
def mikrotik_monitoring_api(nas_id):
    try:
        print(f"DEBUG: Starting MikroTik monitoring for NAS ID: {nas_id}")
        
        nas = get_nas_by_id(nas_id)
        
        if not nas:
            print("DEBUG: NAS device not found")
            return jsonify({'success': False, 'error': 'NAS device not found'}), 404
        
        session_key = f'mikrotik_creds_{nas_id}'
        creds = session.get(session_key, {})
        
        mikrotik_ip = nas['nasname']
        mikrotik_username = creds.get('username', 'admin')
        mikrotik_password = creds.get('password', '')
        mikrotik_port = creds.get('port', 8728)
        
        print(f"DEBUG: Connecting to {mikrotik_ip} with user {mikrotik_username}")
        
        if not mikrotik_password:
            print("DEBUG: No password configured")
            return jsonify({'success': False, 'error': 'MikroTik credentials not configured. Please set username and password.'}), 400
        
        try:
            connection = routeros_api.RouterOsApiPool(
                mikrotik_ip,
                username=mikrotik_username,
                password=mikrotik_password,
                port=mikrotik_port,
                plaintext_login=True,
                use_ssl=False
            )
            api = connection.get_api()
            print("DEBUG: Successfully connected to MikroTik")
        except Exception as conn_error:
            print(f"DEBUG: Connection failed: {str(conn_error)}")
            return jsonify({'success': False, 'error': f'Connection failed: {str(conn_error)}'}), 500
        
        try:
            system_resource = api.get_resource('/system/resource')
            system_info = system_resource.get()
            print("DEBUG: Got system resource")
            
            interface_resource = api.get_resource('/interface')
            interfaces = interface_resource.get()
            print("DEBUG: Got interfaces")
            
            identity_resource = api.get_resource('/system/identity')
            identity = identity_resource.get()
            print("DEBUG: Got identity")
            
        except Exception as data_error:
            print(f"DEBUG: Data retrieval failed: {str(data_error)}")
            connection.disconnect()
            return jsonify({'success': False, 'error': f'Data retrieval failed: {str(data_error)}'}), 500
        
        # Hitung disk sebelum disconnect
        disk_usb, disk_flash = calculate_disk_usage(api)
        
        connection.disconnect()
        print("DEBUG: Disconnected from MikroTik")
        
        processed_interfaces = []
        for iface in interfaces[:10]:
            name = iface.get('name', '')
            if name.startswith(('ppp-', 'ovpn-')):
                continue
                
            processed_interfaces.append({
                'name': name,
                'type': iface.get('type', 'N/A'),
                'running': iface.get('running', 'false') == 'true',
                'rx_rate': format_rate(iface.get('rx-rate', '0')),
                'tx_rate': format_rate(iface.get('tx-rate', '0')),
                'rx_total': format_bytes(iface.get('rx-byte', '0')),
                'tx_total': format_bytes(iface.get('tx-byte', '0'))
            })
        
        monitoring_data = {
            'success': True,
            'system': {
                'hostname': identity[0].get('name', 'Unknown') if identity else 'Unknown',
                'version': system_info[0].get('version', 'N/A') if system_info else 'N/A',
                'uptime': system_info[0].get('uptime', 'N/A') if system_info else 'N/A',
                'board': system_info[0].get('board-name', 'N/A') if system_info else 'N/A',
            },
            'resources': {
                'cpu': system_info[0].get('cpu-load', '0') if system_info else '0',
                'memory': str(calculate_memory_usage(system_info)),
                'disk_usb': str(disk_usb),
                'disk_flash': str(disk_flash)
            },
            'interfaces': processed_interfaces
        }
        
        print("DEBUG: Successfully prepared monitoring data")
        return jsonify(monitoring_data)
        
    except RouterOsApiConnectionError as e:
        print(f"DEBUG: RouterOS API Connection Error: {str(e)}")
        return jsonify({'success': False, 'error': f'Cannot connect to MikroTik device. Check IP address and network connectivity.'}), 500
    except RouterOsApiCommunicationError as e:
        print(f"DEBUG: RouterOS API Communication Error: {str(e)}")
        return jsonify({'success': False, 'error': f'Authentication failed. Check username and password.'}), 401
    except Exception as e:
        print(f"DEBUG: Unexpected error: {str(e)}")
        return jsonify({'success': False, 'error': f'Unexpected error: {str(e)}'}), 500

@app.route('/health')
def health():
    return 'OK'


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
