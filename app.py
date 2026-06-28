from flask import Flask, render_template, request, jsonify, make_response, redirect, url_for, session, send_from_directory
from flask_socketio import SocketIO, emit
from flask_cors import CORS
from database import Database
from crypto_utils import CryptoUtils
from threat_detector import ThreatDetector
from packet_capture import PacketCapture
from nmap_scanner import NmapScanner
from auth import AuthSystem
from log_monitor import RealLogMonitor
from email_alert import EmailAlertSystem
from datetime import datetime, timedelta
import json
import threading
import csv
import io
import os
import logging
from logging.handlers import RotatingFileHandler
import psutil
import platform
import time
import re
import hashlib
import secrets
from collections import defaultdict
from functools import wraps

# ==================== CONFIGURATION ====================
app = Flask(__name__)
app.config['SECRET_KEY'] = 'siem-super-secret-key-2024-enterprise-v2'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=2)
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max upload
CORS(app)

# ==================== LOGGING SETUP ====================
if not os.path.exists('logs'):
    os.makedirs('logs')

file_handler = RotatingFileHandler('logs/siem.log', maxBytes=10240, backupCount=10)
file_handler.setFormatter(logging.Formatter(
    '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
))
file_handler.setLevel(logging.INFO)

app.logger.addHandler(file_handler)
app.logger.setLevel(logging.INFO)
app.logger.info('=' * 60)
app.logger.info('SIEM ENTERPRISE SYSTEM STARTUP')
app.logger.info('=' * 60)

# ==================== SOCKETIO ====================
socketio = SocketIO(
    app, 
    cors_allowed_origins="*", 
    async_mode='threading', 
    ping_timeout=60, 
    ping_interval=25,
    max_http_buffer_size=10**7
)

# ==================== INITIALIZE COMPONENTS ====================
db = Database()
crypto = CryptoUtils()
detector = ThreatDetector(db, socketio)
packet_capture = PacketCapture()
nmap_scanner = NmapScanner()
auth = AuthSystem()
email_alerts = EmailAlertSystem()

# Start log monitor with WebSocket support
real_monitor = RealLogMonitor(detector, db, socketio)
real_monitor.start()
app.logger.info("📡 REAL SSH log monitoring ACTIVE")

# ==================== GLOBAL DATA STORES ====================
traffic_data = []
attack_data = defaultdict(list)
system_metrics = {}
alert_history = []
packet_history = []
live_connections = {}
request_logs = []
live_packets = []
capture_running = False
capture_interface = 'any'

# ==================== SYSTEM METRICS COLLECTOR ====================
def collect_system_metrics():
    """Collect comprehensive real-time system metrics"""
    try:
        cpu_percent = psutil.cpu_percent(interval=0.5)
        cpu_per_core = psutil.cpu_percent(interval=0.5, percpu=True)
        memory = psutil.virtual_memory()
        disk = psutil.disk_usage('/')
        net_io = psutil.net_io_counters()
        
        # Get network connections with details
        connections = psutil.net_connections()
        conn_count = len(connections)
        listening_ports = len([c for c in connections if c.status == 'LISTEN'])
        
        # Get process info
        processes = list(psutil.process_iter(['name', 'cpu_percent', 'memory_percent']))
        top_processes = sorted(
            processes, 
            key=lambda p: p.info.get('cpu_percent', 0) or 0, 
            reverse=True
        )[:5]
        
        # Get load average
        try:
            load_avg = psutil.getloadavg()
        except:
            load_avg = (0, 0, 0)
        
        return {
            'cpu_percent': cpu_percent,
            'cpu_per_core': cpu_per_core,
            'cpu_count': psutil.cpu_count(),
            'memory_percent': memory.percent,
            'memory_used': memory.used // (1024**2),
            'memory_total': memory.total // (1024**2),
            'memory_available': memory.available // (1024**2),
            'disk_usage': disk.percent,
            'disk_used': disk.used // (1024**2),
            'disk_total': disk.total // (1024**2),
            'disk_free': disk.free // (1024**2),
            'network_sent': net_io.bytes_sent // (1024**2),
            'network_recv': net_io.bytes_recv // (1024**2),
            'network_packets_sent': net_io.packets_sent,
            'network_packets_recv': net_io.packets_recv,
            'connections_total': conn_count,
            'listening_ports': listening_ports,
            'process_count': len(psutil.pids()),
            'top_processes': [
                {
                    'name': p.info.get('name', 'unknown'),
                    'cpu': p.info.get('cpu_percent', 0) or 0,
                    'memory': p.info.get('memory_percent', 0) or 0
                }
                for p in top_processes[:5]
            ],
            'system': platform.system(),
            'platform': platform.platform(),
            'release': platform.release(),
            'version': platform.version(),
            'hostname': platform.node(),
            'uptime': int(time.time() - psutil.boot_time()),
            'uptime_formatted': str(timedelta(seconds=int(time.time() - psutil.boot_time()))),
            'load_avg_1min': load_avg[0],
            'load_avg_5min': load_avg[1],
            'load_avg_15min': load_avg[2],
            'timestamp': datetime.now().isoformat()
        }
    except Exception as e:
        app.logger.error(f"Error collecting metrics: {e}")
        return {}

def metrics_collector():
    """Background thread for continuous system metrics collection"""
    while True:
        try:
            global system_metrics
            system_metrics = collect_system_metrics()
            socketio.emit('system_metrics', system_metrics)
            time.sleep(2)
        except Exception as e:
            app.logger.error(f"Metrics collection error: {e}")
            time.sleep(5)

# Start metrics collector
threading.Thread(target=metrics_collector, daemon=True).start()

# ==================== REQUEST INTERCEPTOR ====================
@app.before_request
def before_request():
    """Intercept all requests for threat detection and logging"""
    # Skip static and login pages
    if request.endpoint in ['static', 'login_page', 'signup_page', 'favicon']:
        return
    
    client_ip = request.remote_addr or 'unknown'
    user_agent = request.headers.get('User-Agent', 'Unknown')
    method = request.method
    path = request.path
    
    # Log request
    request_logs.append({
        'timestamp': datetime.now().isoformat(),
        'ip': client_ip,
        'method': method,
        'path': path,
        'user_agent': user_agent
    })
    if len(request_logs) > 1000:
        request_logs.pop(0)
    
    # Check for suspicious user agents
    suspicious_agents = ['sqlmap', 'nikto', 'nmap', 'burp', 'zap', 'wget', 'curl']
    for agent in suspicious_agents:
        if agent.lower() in user_agent.lower():
            db.add_alert(
                'SUSPICIOUS_USER_AGENT',
                'MEDIUM',
                client_ip,
                f'Suspicious user agent detected: {user_agent} from {client_ip}'
            )
            socketio.emit('new_alert', {
                'type': 'SUSPICIOUS_USER_AGENT',
                'severity': 'MEDIUM',
                'message': f'Suspicious user agent: {user_agent}',
                'source': client_ip,
                'timestamp': datetime.now().isoformat()
            })
            break
    
    # Collect all payload data for threat scanning
    payloads_to_check = []
    
    # Check URL parameters
    if request.args:
        payloads_to_check.extend(request.args.values())
    
    # Check form data
    if request.form:
        payloads_to_check.extend(request.form.values())
    
    # Check JSON data
    if request.is_json and request.json:
        if isinstance(request.json, dict):
            payloads_to_check.extend(str(v) for v in request.json.values())
        elif isinstance(request.json, list):
            payloads_to_check.extend(str(item) for item in request.json)
    
    # Scan each payload for threats
    for content in payloads_to_check:
        if content and isinstance(content, str) and len(content) > 2:
            threats = detector.scan_payload_for_threats(content, client_ip)
            for threat in threats:
                db.add_alert(threat['type'], threat['severity'], client_ip, threat['message'])
                socketio.emit('new_alert', {
                    'type': threat['type'],
                    'severity': threat['severity'],
                    'message': threat['message'],
                    'source': client_ip,
                    'timestamp': datetime.now().isoformat()
                })
                
                # Send email for critical threats
                if threat['severity'] == 'CRITICAL':
                    email_alerts.send_alert_email(
                        f"{threat['type']} from {client_ip}",
                        threat['message'],
                        client_ip
                    )
                update_traffic_data()

# ==================== AUTH DECORATOR ====================
def require_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'token' not in session:
            return redirect(url_for('login_page'))
        valid, user_session = auth.verify_session(session['token'])
        if not valid:
            session.clear()
            return redirect(url_for('login_page'))
        return f(*args, **kwargs)
    return decorated

# ==================== AUTH ROUTES ====================
@app.route('/login', methods=['GET', 'POST'])
def login_page():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        otp_code = request.form.get('otp_code', '')
        
        if not username or not password:
            return render_template('login.html', error="Username and password required")
        
        token, message, attempt_count = auth.login(username, password, otp_code=otp_code)
        
        # Check if 2FA OTP is required
        if message == "2FA_OTP_REQUIRED":
            return render_template('login.html', error="2FA_OTP_REQUIRED - OTP sent to your email")
        
        # Track failed attempts for brute force detection
        if attempt_count and attempt_count >= 1:
            detector.detect_brute_force(request.remote_addr, username)
            real_monitor.add_real_attack_feed(request.remote_addr, attempt_count)
            update_traffic_data()
            socketio.emit('new_alert', {
                'type': 'bruteforce',
                'severity': 'HIGH' if attempt_count >= 5 else 'MEDIUM',
                'message': f'⚠️ {attempt_count} failed attempts from {request.remote_addr} for {username}',
                'source': request.remote_addr,
                'timestamp': datetime.now().isoformat()
            })
            
            # Send email alert for brute force
            if attempt_count >= 5:
                email_alerts.send_alert_email(
                    f"BRUTE FORCE ATTACK from {request.remote_addr}",
                    f"{attempt_count} failed login attempts for user {username} from {request.remote_addr}",
                    request.remote_addr,
                    "CRITICAL"
                )
        
        if token:
            session['token'] = token
            session['user'] = username
            session.permanent = True
            app.logger.info(f"User {username} logged in from {request.remote_addr}")
            return redirect(url_for('dashboard'))
        else:
            return render_template('login.html', error=message)
    
    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup_page():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')
        enable_2fa = request.form.get('enable_2fa', 'on') == 'on'
        
        # Validation
        if not username or not email or not password:
            return render_template('signup.html', error="All fields are required")
        
        if len(username) < 3:
            return render_template('signup.html', error="Username must be at least 3 characters")
        
        if not re.match(r'^[a-zA-Z0-9_.-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$', email):
            return render_template('signup.html', error="Invalid email address")
        
        if password != confirm_password:
            return render_template('signup.html', error="Passwords do not match")
        
        if len(password) < 8:
            return render_template('signup.html', error="Password must be at least 8 characters")
        
        if not any(c.isupper() for c in password):
            return render_template('signup.html', error="Password must contain an uppercase letter")
        if not any(c.islower() for c in password):
            return render_template('signup.html', error="Password must contain a lowercase letter")
        if not any(c.isdigit() for c in password):
            return render_template('signup.html', error="Password must contain a number")
        if not any(c in '!@#$%^&*()_+-=[]{}|;:,.<>?/' for c in password):
            return render_template('signup.html', error="Password must contain a special character")
        
        success, message = auth.register(username, email, password, enable_2fa)
        if success:
            app.logger.info(f"New user registered: {username} from {request.remote_addr}")
            return render_template('signup.html', success=message)
        else:
            return render_template('signup.html', error=message)
    
    return render_template('signup.html')

@app.route('/logout')
def logout():
    if 'token' in session:
        user = session.get('user', 'unknown')
        auth.logout(session['token'])
        app.logger.info(f"User {user} logged out")
    session.clear()
    return redirect(url_for('login_page'))

# ==================== MAIN ROUTES ====================
@app.route('/')
@require_auth
def dashboard():
    valid, user_session = auth.verify_session(session['token'])
    return render_template('dashboard.html', session=user_session)

# ==================== API ROUTES ====================
@app.route('/api/stats')
@require_auth
def get_stats():
    """Get comprehensive system statistics"""
    stats = db.get_stats()
    integrity = db.get_integrity_status()
    packet_stats = packet_capture.get_stats()
    
    # Get attack statistics
    attack_stats = {
        'bruteforce': db.get_alerts_by_type('BRUTE_FORCE_ATTACK'),
        'suspicious': db.get_alerts_by_type('SUSPICIOUS_LOGIN_ATTEMPTS'),
        'port_scan': db.get_alerts_by_type('PORT_SCAN_PACKET'),
        'sql_injection': db.get_alerts_by_type('SQL_INJECTION'),
        'xss': db.get_alerts_by_type('XSS_ATTACK'),
        'path_traversal': db.get_alerts_by_type('PATH_TRAVERSAL'),
        'open_ports': db.get_alerts_by_type('OPEN_PORTS_FOUND'),
        'suspicious_agent': db.get_alerts_by_type('SUSPICIOUS_USER_AGENT')
    }
    
    return jsonify({
        'stats': stats,
        'integrity': integrity,
        'traffic': traffic_data[-50:],
        'packet_stats': packet_stats,
        'attack_stats': attack_stats,
        'system_metrics': system_metrics,
        'timestamp': datetime.now().isoformat()
    })

@app.route('/api/alerts')
@require_auth
def get_alerts():
    """Get filtered alerts"""
    severity = request.args.get('severity', 'all')
    source = request.args.get('source', '')
    limit = int(request.args.get('limit', 100))
    offset = int(request.args.get('offset', 0))
    
    alerts = db.get_alerts(limit=limit, severity=severity, source=source, offset=offset)
    total = db.get_alerts_count(severity=severity, source=source)
    
    return jsonify({
        'alerts': alerts,
        'total': total,
        'offset': offset,
        'limit': limit
    })

@app.route('/api/alerts/latest')
@require_auth
def get_latest_alerts():
    """Get latest alerts for real-time updates"""
    alerts = db.get_alerts(limit=20)
    return jsonify(alerts)

@app.route('/api/alerts/count')
@require_auth
def get_alert_counts():
    """Get alert counts by severity"""
    counts = db.get_alert_counts_by_severity()
    return jsonify(counts)

@app.route('/api/alerts/resolve/<int:alert_id>', methods=['POST'])
@require_auth
def resolve_alert(alert_id):
    """Mark an alert as resolved"""
    success = db.resolve_alert(alert_id)
    if success:
        app.logger.info(f"Alert {alert_id} resolved by {session.get('user', 'unknown')}")
    return jsonify({'success': success})

@app.route('/api/alerts/batch-resolve', methods=['POST'])
@require_auth
def batch_resolve_alerts():
    """Resolve multiple alerts at once"""
    data = request.json or {}
    alert_ids = data.get('alert_ids', [])
    if not alert_ids:
        return jsonify({'success': False, 'error': 'No alert IDs provided'})
    
    success_count = 0
    for alert_id in alert_ids:
        if db.resolve_alert(alert_id):
            success_count += 1
    
    app.logger.info(f"Batch resolved {success_count} alerts by {session.get('user', 'unknown')}")
    return jsonify({'success': True, 'resolved': success_count})

@app.route('/api/packets')
@require_auth
def get_packets():
    """Get captured packets"""
    limit = int(request.args.get('limit', 50))
    protocol = request.args.get('protocol', 'all')
    packets = db.get_packets(limit=limit, protocol=protocol)
    return jsonify(packets)

@app.route('/api/packets/latest')
@require_auth
def get_latest_packets():
    """Get latest packets"""
    packets = db.get_packets(limit=20)
    return jsonify(packets)

# ============ NEW PACKET ENDPOINTS ============
@app.route('/api/packets/live')
@require_auth
def get_live_packets():
    """Get live packets from current capture session"""
    limit = int(request.args.get('limit', 50))
    protocol = request.args.get('protocol', 'all')
    
    # Get from live capture
    packets = packet_capture.get_live_packets(limit)
    
    # Filter by protocol if specified
    if protocol != 'all' and packets:
        packets = [p for p in packets if p.get('protocol') == protocol]
    
    return jsonify(packets[:limit])

@app.route('/api/packets/stats')
@require_auth
def get_packet_stats():
    """Get packet statistics"""
    stats = packet_capture.get_stats()
    return jsonify(stats)

@app.route('/api/capture/interfaces')
@require_auth
def capture_interfaces():
    """Get available network interfaces for capture"""
    interfaces = packet_capture.get_interfaces()
    return jsonify(interfaces)

@app.route('/api/packet/<int:packet_id>')
@require_auth
def get_packet_detail(packet_id):
    """Get packet details by ID"""
    packet = db.get_packet_by_id(packet_id)
    if packet:
        return jsonify(packet)
    return jsonify({'error': 'Packet not found'}), 404

@app.route('/api/live-feed')
@require_auth
def get_live_feed():
    """Get live attack feed"""
    feed = real_monitor.get_feed()
    return jsonify(feed)

@app.route('/api/live-feed/clear', methods=['POST'])
@require_auth
def clear_live_feed():
    """Clear live feed"""
    real_monitor.clear_feed()
    return jsonify({'success': True})

@app.route('/api/bruteforce-status')
@require_auth
def get_bruteforce_status():
    """Get brute force attack status"""
    status = auth.get_brute_force_status()
    return jsonify(status)

@app.route('/api/request-otp', methods=['POST'])
def request_otp():
    """Request 2FA OTP for a user"""
    data = request.json or {}
    username = data.get('username')
    
    if not username:
        return jsonify({'success': False, 'message': 'Username required'})
    
    success, message = auth.request_2fa_otp(username)
    return jsonify({'success': success, 'message': message})

@app.route('/api/verify-otp', methods=['POST'])
def verify_otp():
    """Verify 2FA OTP"""
    data = request.json or {}
    username = data.get('username')
    otp = data.get('otp')
    
    if not username or not otp:
        return jsonify({'success': False, 'message': 'Username and OTP required'})
    
    success, message = auth.verify_2fa_otp(username, otp)
    return jsonify({'success': success, 'message': message})

@app.route('/api/2fa-status')
@require_auth
def get_2fa_status():
    """Get 2FA status for current user"""
    valid, user_session = auth.verify_session(session['token'])
    if not valid:
        return jsonify({'error': 'Unauthorized'}), 401
    username = user_session.get('username')
    status = auth.get_2fa_status(username)
    return jsonify(status)

@app.route('/api/capture/start', methods=['POST'])
@require_auth
def capture_start():
    """Start packet capture"""
    global capture_running, capture_interface
    
    data = request.json or {}
    interface = data.get('interface', 'any')
    count = data.get('count', 30)
    timeout = data.get('timeout', 15)
    
    if packet_capture.is_capturing():
        return jsonify({'status': 'already_running', 'message': 'Capture already in progress'})
    
    capture_interface = interface
    packet_capture.set_socketio(socketio)
    
    def capture_thread():
        global capture_running
        capture_running = True
        try:
            packets = packet_capture.start_capture(interface, packet_limit=count, timeout=timeout)
            app.logger.info(f"Captured {len(packets)} packets on {interface}")
            
            for p in packets:
                # Store packet
                db.add_packet(p)
                packet_history.append(p)
                if len(packet_history) > 1000:
                    packet_history.pop(0)
                
                # =========================================================
                # ❌❌❌ PACKET ALERTS COMPLETELY DISABLED ❌❌❌
                # This was causing infinite spam alerts
                # =========================================================
                # threat_info = detector.analyze_packet(p)
                # if threat_info:
                #     db.add_alert(
                #         threat_info['type'], 
                #         threat_info['severity'], 
                #         p.get('src_ip', ''), 
                #         threat_info['message']
                #     )
                #     update_traffic_data()
                #     socketio.emit('new_alert', {
                #         'type': threat_info['type'],
                #         'severity': threat_info['severity'],
                #         'message': threat_info['message'],
                #         'source': p.get('src_ip', ''),
                #         'timestamp': datetime.now().isoformat()
                #     })
                #     
                #     if threat_info['severity'] == 'CRITICAL':
                #         email_alerts.send_alert_email(
                #             f"{threat_info['type']} on Network",
                #             threat_info['message'],
                #             p.get('src_ip', ''),
                #             "CRITICAL"
                #         )
                # =========================================================
            
            socketio.emit('capture_done', {'count': len(packets)})
        except Exception as e:
            app.logger.error(f"Packet capture error: {e}")
            socketio.emit('capture_error', {'error': str(e)})
        finally:
            capture_running = False
    
    threading.Thread(target=capture_thread, daemon=True).start()
    return jsonify({
        'status': 'started', 
        'message': f'Sniffing {count} packets on {interface}...'
    })

@app.route('/api/capture/stop', methods=['POST'])
@require_auth
def capture_stop():
    """Stop packet capture"""
    global capture_running
    packet_capture.stop_capture()
    capture_running = False
    return jsonify({'status': 'stopped'})

@app.route('/api/capture/status')
@require_auth
def capture_status():
    """Get capture status"""
    return jsonify({
        'capturing': packet_capture.is_capturing() or capture_running,
        'packet_count': packet_capture.get_packet_count(),
        'interface': capture_interface
    })

@app.route('/api/nmap/scan', methods=['POST'])
@require_auth
def nmap_scan():
    """Run Nmap scan"""
    data = request.json or {}
    target = data.get('target', 'localhost')
    scan_type = data.get('type', 'quick')
    ports = data.get('ports', '')
    
    app.logger.info(f"Nmap scan started: {scan_type} on {target} by {session.get('user', 'unknown')}")
    
    if scan_type == 'quick':
        result = nmap_scanner.quick_scan(target)
    elif scan_type == 'comprehensive':
        result = nmap_scanner.comprehensive_scan(target)
    elif scan_type == 'vulnerability':
        result = nmap_scanner.vulnerability_scan(target)
    else:
        result = nmap_scanner.quick_scan(target)
    
    # Log open ports as alerts
    if result.get('open_ports') and len(result['open_ports']) > 0:
        db.add_alert(
            'OPEN_PORTS_FOUND', 
            result.get('risk_level', 'MEDIUM'), 
            target, 
            f"Found {len(result['open_ports'])} open ports on {target}"
        )
        update_traffic_data()
        socketio.emit('new_alert', {
            'type': 'OPEN_PORTS_FOUND',
            'severity': result.get('risk_level', 'MEDIUM'),
            'message': f'Found {len(result["open_ports"])} open ports on {target}',
            'source': target,
            'timestamp': datetime.now().isoformat()
        })
        
        # Email for high risk scans
        if result.get('risk_level') == 'HIGH':
            email_alerts.send_alert_email(
                f"Open ports found on {target}",
                f"Found {len(result['open_ports'])} open ports on {target}",
                target,
                "HIGH"
            )
    
    return jsonify(result)

@app.route('/api/nmap/interfaces')
@require_auth
def nmap_interfaces():
    """Get available network interfaces"""
    interfaces = nmap_scanner.get_interfaces()
    return jsonify(interfaces)

# ==================== EXPORT ROUTES ====================
@app.route('/api/export')
@require_auth
def export_report():
    """Export full HTML report"""
    alerts = db.get_alerts(limit=100)
    stats = db.get_stats()
    integrity = db.get_integrity_status()
    packets = db.get_packets(limit=50)
    attack_stats = db.get_attack_statistics()
    
    # Generate HTML report
    alert_rows = ""
    for a in alerts[:20]:
        severity_color = 'red' if a['severity'] in ['CRITICAL', 'HIGH'] else 'orange' if a['severity'] == 'MEDIUM' else 'green'
        alert_rows += f"""
        <tr>
            <td>{a['timestamp'][:19]}</td>
            <td>{a['type']}</td>
            <td><span style="color:{severity_color};font-weight:bold;">{a['severity']}</span></td>
            <td>{a['source']}</td>
            <td>{a['message'][:60]}</td>
        </tr>
        """
    
    packet_rows = ""
    for p in packets[:20]:
        packet_rows += f"""
        <tr>
            <td>{p['timestamp'][:19]}</td>
            <td>{p['src_ip']}</td>
            <td>{p['dst_ip']}</td>
            <td>{p['protocol']}</td>
            <td>{p['threat']}</td>
        </tr>
        """
    
    html = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>SIEM Enterprise Report</title>
        <style>
            * {{ margin:0; padding:0; box-sizing:border-box; }}
            body {{ font-family:'Segoe UI',Arial; background:#f0f4f8; padding:30px; }}
            .header {{ background:linear-gradient(135deg,#1a1f3a,#0a0e27); color:white; padding:30px; border-radius:10px; margin-bottom:20px; }}
            .header h1 {{ font-size:28px; }}
            .header p {{ opacity:0.7; margin-top:5px; }}
            .stats-grid {{ display:grid; grid-template-columns:repeat(4,1fr); gap:15px; margin-bottom:30px; }}
            .stat-card {{ background:white; padding:20px; border-radius:10px; box-shadow:0 2px 10px rgba(0,0,0,0.1); text-align:center; }}
            .stat-value {{ font-size:28px; font-weight:bold; color:#00d4ff; }}
            .stat-label {{ color:#666; font-size:12px; margin-top:5px; }}
            .section {{ background:white; border-radius:10px; padding:20px; margin-bottom:20px; box-shadow:0 2px 10px rgba(0,0,0,0.1); }}
            .section-title {{ color:#1a1f3a; border-bottom:2px solid #00d4ff; padding-bottom:10px; margin-bottom:15px; }}
            table {{ width:100%; border-collapse:collapse; font-size:13px; }}
            th {{ background:#1a1f3a; color:white; padding:10px; text-align:left; }}
            td {{ padding:8px 10px; border-bottom:1px solid #eee; }}
            tr:hover {{ background:#f5f5f5; }}
            .footer {{ text-align:center; color:#888; font-size:12px; margin-top:20px; }}
            .risk-high {{ color:#ef4444; }}
            .risk-medium {{ color:#f59e0b; }}
            .risk-low {{ color:#10b981; }}
        </style>
    </head>
    <body>
        <div class="header">
            <h1>🛡️ SIEM Enterprise Security Report</h1>
            <p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            <p>System: {platform.system()} {platform.release()}</p>
        </div>
        
        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-value">{stats.get('total_alerts', 0)}</div>
                <div class="stat-label">Total Alerts</div>
            </div>
            <div class="stat-card">
                <div class="stat-value" style="color:#ef4444;">{stats.get('active_threats', 0)}</div>
                <div class="stat-label">Active Threats</div>
            </div>
            <div class="stat-card">
                <div class="stat-value" style="color:#10b981;">{integrity.get('integrity_percentage', 0)}%</div>
                <div class="stat-label">Log Integrity</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{stats.get('total_packets', 0)}</div>
                <div class="stat-label">Packets Captured</div>
            </div>
        </div>
        
        <div class="section">
            <h2 class="section-title">📊 Attack Statistics</h2>
            <div style="display:grid; grid-template-columns:repeat(4,1fr); gap:10px;">
                <div style="background:#f8f9fa; padding:15px; border-radius:8px; text-align:center;">
                    <div style="font-size:24px; font-weight:bold; color:#ef4444;">{attack_stats.get('bruteforce', 0)}</div>
                    <div style="font-size:12px; color:#666;">Brute Force</div>
                </div>
                <div style="background:#f8f9fa; padding:15px; border-radius:8px; text-align:center;">
                    <div style="font-size:24px; font-weight:bold; color:#f59e0b;">{attack_stats.get('sql_injection', 0)}</div>
                    <div style="font-size:12px; color:#666;">SQL Injection</div>
                </div>
                <div style="background:#f8f9fa; padding:15px; border-radius:8px; text-align:center;">
                    <div style="font-size:24px; font-weight:bold; color:#f59e0b;">{attack_stats.get('xss', 0)}</div>
                    <div style="font-size:12px; color:#666;">XSS Attacks</div>
                </div>
                <div style="background:#f8f9fa; padding:15px; border-radius:8px; text-align:center;">
                    <div style="font-size:24px; font-weight:bold; color:#7c3aed;">{attack_stats.get('port_scan', 0)}</div>
                    <div style="font-size:12px; color:#666;">Port Scans</div>
                </div>
            </div>
        </div>
        
        <div class="section">
            <h2 class="section-title">🚨 Security Alerts</h2>
            <table>
                <tr><th>Time</th><th>Type</th><th>Severity</th><th>Source</th><th>Message</th></tr>
                {alert_rows if alert_rows else '<tr><td colspan="5" style="text-align:center;color:#888;">No alerts recorded</td></tr>'}
            </table>
        </div>
        
        <div class="section">
            <h2 class="section-title">📡 Network Packets</h2>
            <table>
                <tr><th>Time</th><th>Source</th><th>Destination</th><th>Protocol</th><th>Threat</th></tr>
                {packet_rows if packet_rows else '<tr><td colspan="5" style="text-align:center;color:#888;">No packets captured</td></tr>'}
            </table>
        </div>
        
        <div class="footer">
            <p>🔐 SHA-256 Protected | SIEM Enterprise v3.0</p>
            <p>All logs are cryptographically verified for integrity</p>
        </div>
    </body>
    </html>
    """
    
    response = make_response(html)
    response.headers['Content-Type'] = 'text/html'
    response.headers['Content-Disposition'] = f'attachment; filename=siem-report-{datetime.now().strftime("%Y%m%d_%H%M%S")}.html'
    return response

@app.route('/api/export/csv')
@require_auth
def export_csv():
    """Export alerts as CSV"""
    severity = request.args.get('severity', 'all')
    source = request.args.get('source', '')
    limit = int(request.args.get('limit', 1000))
    
    alerts = db.get_alerts(limit=limit, severity=severity, source=source)
    
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['Timestamp', 'Type', 'Severity', 'Source', 'Message'])
    
    for alert in alerts:
        writer.writerow([
            alert['timestamp'],
            alert['type'],
            alert['severity'],
            alert['source'],
            alert['message']
        ])
    
    response = make_response(output.getvalue())
    response.headers['Content-Disposition'] = f'attachment; filename=siem-alerts-{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv'
    response.headers['Content-Type'] = 'text/csv'
    return response

@app.route('/api/export/json')
@require_auth
def export_json():
    """Export alerts as JSON"""
    severity = request.args.get('severity', 'all')
    source = request.args.get('source', '')
    limit = int(request.args.get('limit', 1000))
    
    alerts = db.get_alerts(limit=limit, severity=severity, source=source)
    
    return jsonify({
        'export_date': datetime.now().isoformat(),
        'total': len(alerts),
        'alerts': alerts
    })

@app.route('/api/export/packets')
@require_auth
def export_packets_csv():
    """Export packets as CSV"""
    packets = db.get_packets(limit=1000)
    
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['Timestamp', 'Source IP', 'Destination IP', 'Protocol', 'Threat'])
    
    for packet in packets:
        writer.writerow([
            packet['timestamp'],
            packet['src_ip'],
            packet['dst_ip'],
            packet['protocol'],
            packet['threat']
        ])
    
    response = make_response(output.getvalue())
    response.headers['Content-Disposition'] = f'attachment; filename=siem-packets-{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv'
    response.headers['Content-Type'] = 'text/csv'
    return response

# ==================== ADMIN ROUTES ====================
@app.route('/api/admin/users')
@require_auth
def admin_users():
    """Get all users (admin only)"""
    valid, user_session = auth.verify_session(session['token'])
    if user_session.get('role') != 'admin':
        return jsonify({'error': 'Admin access required'}), 403
    
    users = db.get_all_users()
    return jsonify(users)

@app.route('/api/admin/user/<int:user_id>', methods=['DELETE'])
@require_auth
def admin_delete_user(user_id):
    """Delete a user (admin only)"""
    valid, user_session = auth.verify_session(session['token'])
    if user_session.get('role') != 'admin':
        return jsonify({'error': 'Admin access required'}), 403
    
    success = db.delete_user(user_id)
    return jsonify({'success': success})

@app.route('/api/admin/clear-alerts', methods=['POST'])
@require_auth
def admin_clear_alerts():
    """Clear all alerts (admin only)"""
    valid, user_session = auth.verify_session(session['token'])
    if user_session.get('role') != 'admin':
        return jsonify({'error': 'Admin access required'}), 403
    
    db.clear_alerts()
    app.logger.info(f"All alerts cleared by {session.get('user', 'unknown')}")
    return jsonify({'success': True})

@app.route('/api/admin/system-info')
@require_auth
def admin_system_info():
    """Get detailed system information (admin only)"""
    valid, user_session = auth.verify_session(session['token'])
    if user_session.get('role') != 'admin':
        return jsonify({'error': 'Admin access required'}), 403
    
    return jsonify({
        'system': system_metrics,
        'database_size': db.get_db_size(),
        'alert_count': db.get_alerts_count(),
        'packet_count': db.get_packets_count(),
        'user_count': db.get_user_count(),
        'logs': request_logs[-50:],
        'timestamp': datetime.now().isoformat()
    })

# ==================== SOCKETIO EVENTS ====================
@socketio.on('connect')
def handle_connect():
    """Handle client connection"""
    client_id = request.sid
    ip = request.remote_addr
    live_connections[client_id] = {
        'ip': ip,
        'connected_at': datetime.now().isoformat()
    }
    app.logger.info(f"Client connected: {ip} ({client_id})")
    emit('connected', {
        'status': 'connected',
        'timestamp': datetime.now().isoformat(),
        'client_id': client_id
    })
    
    # Send initial metrics
    emit('system_metrics', system_metrics)
    
    # Send any existing live packets
    live_packets_data = packet_capture.get_live_packets(20)
    if live_packets_data:
        emit('packets_batch', live_packets_data)

@socketio.on('disconnect')
def handle_disconnect():
    """Handle client disconnection"""
    client_id = request.sid
    if client_id in live_connections:
        ip = live_connections[client_id].get('ip', 'unknown')
        app.logger.info(f"Client disconnected: {ip} ({client_id})")
        del live_connections[client_id]

@socketio.on('request_metrics')
def handle_metrics_request():
    """Handle manual metrics request"""
    emit('system_metrics', system_metrics)

@socketio.on('request_live_feed')
def handle_feed_request():
    """Handle live feed request"""
    feed = real_monitor.get_feed()
    emit('live_feed', feed)

@socketio.on('request_alerts')
def handle_alerts_request():
    """Handle alerts request"""
    alerts = db.get_alerts(limit=20)
    emit('alerts_update', alerts)

@socketio.on('request_live_packets')
def handle_live_packets_request():
    """Handle live packets request"""
    packets = packet_capture.get_live_packets(50)
    emit('packets_batch', packets)

@socketio.on('ping')
def handle_ping():
    """Handle ping for keep-alive"""
    emit('pong', {'timestamp': datetime.now().isoformat()})

# ==================== HELPERS ====================
def update_traffic_data():
    """Update traffic trend data"""
    global traffic_data
    traffic_data.append({
        'time': datetime.now().strftime('%H:%M:%S'),
        'value': len(db.get_alerts())
    })
    if len(traffic_data) > 50:
        traffic_data.pop(0)

# ==================== ERROR HANDLERS ====================
@app.errorhandler(404)
def not_found(error):
    """Handle 404 errors"""
    return jsonify({'error': 'Not found'}), 404

@app.errorhandler(500)
def internal_error(error):
    """Handle 500 errors"""
    app.logger.error(f"Internal server error: {error}")
    return jsonify({'error': 'Internal server error'}), 500

# ==================== MAIN ====================
if __name__ == '__main__':
    print("""
    ╔══════════════════════════════════════════════════════════════════════════════════╗
    ║                    SIEM ENTERPRISE - Advanced Threat Detection System           ║
    ╠══════════════════════════════════════════════════════════════════════════════════╣
    ║                                                                                  ║
    ║  🌐 Dashboard: http://localhost:5000                                             ║
    ║  🔐 Login: admin / Admin@123                                                     ║
    ║  📧 2FA OTP will be sent to: fizzafaisal07@gmail.com                             ║
    ║                                                                                  ║
    ║  🚀 FEATURES:                                                                    ║
    ║  ✓ Real-time Brute Force Detection & Account Lockout                             ║
    ║  ✓ SQL Injection & XSS Attack Detection                                         ║
    ║  ✓ Path Traversal Detection                                                     ║
    ║  ✓ Network Packet Analysis & Port Scanning Detection                            ║
    ║  ✓ System Metrics Monitoring (CPU, Memory, Disk, Network)                       ║
    ║  ✓ Email Alerts for Critical Threats                                            ║
    ║  ✓ SHA-256 Log Integrity Verification                                           ║
    ║  ✓ Live Attack Visualization with Real-time Charts                              ║
    ║  ✓ Nmap Integration for Vulnerability Scanning                                  ║
    ║  ✓ Export Reports (HTML, CSV, JSON)                                             ║
    ║  ✓ 2FA Support (Email OTP)                                                      ║
    ║  ✓ WebSocket Real-time Updates                                                  ║
    ║  ✓ Responsive Dashboard with Dark Theme                                         ║
    ║  ✓ Alert Filtering & Search                                                     ║
    ║  ✓ Batch Alert Resolution                                                       ║
    ║  ✓ Admin User Management                                                        ║
    ║                                                                                  ║
    ╚══════════════════════════════════════════════════════════════════════════════════╝
    """)
    
    # Create required directories
    os.makedirs('templates', exist_ok=True)
    os.makedirs('logs', exist_ok=True)
    
    # Check if nmap is installed
    try:
        import subprocess
        subprocess.run(['nmap', '--version'], capture_output=True, check=True)
        print("✅ Nmap is installed and ready")
    except:
        print("⚠️  Nmap not found. Install with: sudo apt-get install nmap (Linux) or brew install nmap (Mac)")
    
    socketio.run(app, host='0.0.0.0', port=5000, debug=True, allow_unsafe_werkzeug=True)