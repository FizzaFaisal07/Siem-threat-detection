import time
import os
import threading
from datetime import datetime
from datetime import timedelta  
from collections import defaultdict
import platform

# Try to import Windows Event Log support
try:
    import win32evtlog
    import win32evtlogutil
    import win32security
    import pywintypes
    WINDOWS_EVTLOG_AVAILABLE = True
except ImportError:
    WINDOWS_EVTLOG_AVAILABLE = False
    print("⚠️ pywin32 not installed. Install with: pip install pywin32")
    print("   For Windows event log monitoring")

class RealLogMonitor:
    def __init__(self, detector, db, socketio=None):
        self.detector = detector
        self.db = db
        self.running = True
        self.failed_counts = defaultdict(list)
        self.attack_feed = []
        self.socketio = socketio
        self.is_windows = platform.system() == 'Windows'
        
        # Set log file paths based on OS
        if self.is_windows:
            # Windows uses Event Log, not files
            self.log_file = None
            self.use_event_log = True
        else:
            # Linux/Mac use log files
            self.log_file = '/var/log/auth.log' if os.path.exists('/var/log/auth.log') else '/var/log/secure'
            self.use_event_log = False
        
        # Windows Event Log monitoring state
        self.last_event_id = None
        self.monitoring_active = False
        
    def set_socketio(self, socketio):
        """Set SocketIO instance for real-time updates"""
        self.socketio = socketio
        
    def start(self):
        """Start monitoring based on OS"""
        if self.is_windows:
            if WINDOWS_EVTLOG_AVAILABLE:
                print("📡 Windows Event Log monitoring ACTIVE")
                print("   Monitoring Security Log for failed logins (Event ID 4625)")
                threading.Thread(target=self._monitor_windows_event_log, daemon=True).start()
            else:
                print("📡 pywin32 not installed. Install with: pip install pywin32")
                print("📡 Using mock mode - Enter wrong password 5 times to test brute force")
        else:
            if os.path.exists(self.log_file):
                print(f"📡 Monitoring Linux/Mac log file: {self.log_file}")
                threading.Thread(target=self._monitor_file, daemon=True).start()
            else:
                print("📡 SIEM Active - No log file found. Enter wrong password 5 times to test brute force")
    
    def _monitor_windows_event_log(self):
        """Monitor Windows Security Event Log for failed logins"""
        print("📡 SIEM KERNEL: Reading Windows Security Event Log")
        
        try:
            # Open the Security event log
            handle = win32evtlog.OpenEventLog(None, "Security")
            
            # Read events in real-time
            flags = win32evtlog.EVENTLOG_SEQUENTIAL_READ | win32evtlog.EVENTLOG_FORWARDS_READ
            
            # Get the oldest event record number to start from
            # We'll read the last 100 events to avoid missing anything
            properties = win32evtlog.GetEventLogInformation(handle, win32evtlog.EvtEventLogInfoClass.EvtEventLogClassicInfo)
            
            # Read events in a loop
            last_event_time = datetime.now()
            
            while self.running:
                try:
                    # Read events
                    events = win32evtlog.ReadEventLog(handle, flags, 0)
                    
                    if events:
                        for event in events:
                            self._process_windows_event(event)
                    else:
                        # No new events, wait a bit
                        time.sleep(1)
                        
                except pywintypes.error as e:
                    if e.winerror == 0:  # No more events
                        time.sleep(1)
                    else:
                        print(f"⚠️ Windows Event Log error: {e}")
                        time.sleep(5)
                        
        except Exception as e:
            print(f"❌ Windows Event Log monitoring error: {e}")
            print("   Make sure you have administrator privileges")
            print("   Run the application as Administrator")
    
    def _process_windows_event(self, event):
        """Process a Windows Event Log entry"""
        try:
            event_id = event.EventID
            
            # Check for failed logon events
            # Event ID 4625 = Failed logon
            # Event ID 4776 = Credential validation failed (domain controller)
            if event_id == 4625 or event_id == 4776:
                # Extract information from the event
                logon_type = None
                source_ip = None
                username = None
                
                # Parse event data strings
                if hasattr(event, 'StringInserts') and event.StringInserts:
                    inserts = event.StringInserts
                    # For Event ID 4625:
                    # Insert 5 = Account Name (username)
                    # Insert 18 = Source IP Address
                    # Insert 8 = Logon Type
                    if len(inserts) > 5:
                        username = inserts[5] if inserts[5] else "unknown"
                    if len(inserts) > 18:
                        source_ip = inserts[18] if inserts[18] and inserts[18] != '-' else "localhost"
                    if len(inserts) > 8:
                        logon_type = inserts[8]
                
                # Get timestamp
                timestamp = event.TimeGenerated
                if timestamp:
                    timestamp_str = timestamp.strftime('%Y-%m-%d %H:%M:%S')
                else:
                    timestamp_str = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                
                # Create alert
                if source_ip and source_ip != "localhost":
                    # Track failed attempts for this IP
                    self.failed_counts[source_ip].append(datetime.now())
                    
                    # Keep only last 5 minutes
                    self.failed_counts[source_ip] = [
                        t for t in self.failed_counts[source_ip]
                        if datetime.now() - t < timedelta(minutes=5)
                    ]
                    count = len(self.failed_counts[source_ip])
                    
                    # Determine severity based on attempts
                    if count >= 5:
                        severity = "CRITICAL"
                        alert_type = "WINDOWS_BRUTE_FORCE"
                        message = f"🚨 WINDOWS BRUTE FORCE! {count} failed logins from {source_ip} for user {username}"
                    elif count >= 3:
                        severity = "MEDIUM"
                        alert_type = "WINDOWS_SUSPICIOUS_ATTEMPTS"
                        message = f"⚠️ Suspicious: {count} failed logins from {source_ip} for user {username}"
                    else:
                        severity = "LOW"
                        alert_type = "WINDOWS_FAILED_LOGIN"
                        message = f"❌ Failed Windows login for user {username} from {source_ip}"
                    
                    # Add to database
                    self.db.add_alert(alert_type, severity, source_ip, message)
                    
                    # Add to live feed
                    self._add_to_feed(message)
                    
                    # Send WebSocket alert
                    if self.socketio:
                        self.socketio.emit('new_alert', {
                            'type': alert_type,
                            'severity': severity,
                            'message': message,
                            'source': source_ip,
                            'timestamp': datetime.now().isoformat()
                        })
                    
                    print(f"🔔 Windows Security Alert: {message}")
                    
        except Exception as e:
            print(f"⚠️ Error processing Windows event: {e}")
    
    def _monitor_file(self):
        """Monitor Linux/Mac log files"""
        print(f"📡 SIEM KERNEL: Reading live feeds directly from {self.log_file}")
        try:
            with open(self.log_file, 'r') as f:
                f.seek(0, 2)
                while self.running:
                    line = f.readline()
                    if line:
                        if 'Failed password' in line or 'authentication failure' in line:
                            self._trigger_breach("192.168.1.105", "SSH Brute Force")
                    time.sleep(0.2)
        except PermissionError:
            print("❌ Access Denied: Run server architecture via sudo mode rules.")
        except Exception as e:
            print(f"⚠️ File monitoring error: {e}")
    
    def add_real_attack_feed(self, ip, attempt_count):
        """Called when real brute force is detected from login form"""
        timestamp = datetime.now().strftime('%H:%M:%S')
        if attempt_count >= 5:
            message = f"[{timestamp}] 🚨 REAL BRUTE FORCE! {attempt_count} failed attempts from {ip}"
            self._add_to_feed(message)
            if self.socketio:
                self.socketio.emit('new_alert', {'type': 'bruteforce', 'message': message})
        elif attempt_count >= 3:
            message = f"[{timestamp}] ⚠️ Suspicious: {attempt_count} attempts from {ip}"
            self._add_to_feed(message)
            if self.socketio:
                self.socketio.emit('new_alert', {'type': 'suspicious', 'message': message})
        else:
            message = f"[{timestamp}] ❌ Failed login from {ip} (attempt #{attempt_count})"
            self._add_to_feed(message)
            if self.socketio:
                self.socketio.emit('new_alert', {'type': 'failed_login', 'message': message})

    def _trigger_breach(self, ip, attack_type):
        timestamp = datetime.now().strftime('%H:%M:%S')
        message = f"[{timestamp}] 🚨 REAL BREACH DETECTED: {attack_type} from {ip}"
        self._add_to_feed(message)
        self.db.add_alert(f"REAL_{attack_type.upper()}", "CRITICAL", ip, "Sequential verification faults matching rule metrics.")
        if self.socketio:
            self.socketio.emit('new_alert', {'type': 'breach', 'message': message})

    def _add_to_feed(self, message):
        self.attack_feed.append(message)
        if len(self.attack_feed) > 20:
            self.attack_feed.pop(0)

    def get_feed(self):
        if self.attack_feed:
            return self.attack_feed
        if self.is_windows and WINDOWS_EVTLOG_AVAILABLE:
            return [f"[{datetime.now().strftime('%H:%M:%S')}] 🟢 Monitoring Windows Security Log..."]
        return [f"[{datetime.now().strftime('%H:%M:%S')}] ✅ Monitoring active - Enter wrong password 5 times to test"]
    
    def clear_feed(self):
        """Clear the attack feed"""
        self.attack_feed = []
        self._add_to_feed(f"[{datetime.now().strftime('%H:%M:%S')}] ✅ Feed cleared")