from collections import defaultdict
from datetime import datetime, timedelta
import re
import hashlib

class ThreatDetector:
    def __init__(self, db, socketio=None):
        self.db = db
        self.socketio = socketio
        self.failed_attempts = defaultdict(list)
        
        # SQL Injection patterns
        self.sql_patterns = [
            r"(?i)(\bSELECT\b.*\bFROM\b)",
            r"(?i)(\bINSERT\b.*\bINTO\b)",
            r"(?i)(\bUPDATE\b.*\bSET\b)",
            r"(?i)(\bDELETE\b.*\bFROM\b)",
            r"(?i)(\bDROP\b.*\bTABLE\b)",
            r"(?i)(\bUNION\b.*\bSELECT\b)",
            r"(?i)(\bOR\b.*\b=.*\b)",
            r"(?i)(--|#|;|\bAND\b.*\b=.*\b)",
            r"(?i)(\bEXEC\b.*\bXP_\b)",
            r"(?i)(\bALTER\b.*\bTABLE\b)",
            r"(?i)(\bCREATE\b.*\bTABLE\b)",
            r"(?i)(\bTRUNCATE\b.*\bTABLE\b)",
            r"(?i)(\bMERGE\b.*\bUSING\b)",
            r"(?i)(\bCALL\b.*\bPROCEDURE\b)",
            r"(?i)(\bDECLARE\b.*\bCURSOR\b)",
            r"(?i)(\bEXECUTE\b.*\bIMMEDIATE\b)",
        ]
        
        # XSS patterns
        self.xss_patterns = [
            r"<script.*?>.*?</script>",
            r"onerror\s*=\s*['\"]?[^'\"]*['\"]?",
            r"onload\s*=\s*['\"]?[^'\"]*['\"]?",
            r"onclick\s*=\s*['\"]?[^'\"]*['\"]?",
            r"onmouseover\s*=\s*['\"]?[^'\"]*['\"]?",
            r"javascript\s*:",
            r"alert\s*\(.*?\)",
            r"eval\s*\(.*?\)",
            r"document\.cookie",
            r"<iframe.*?>.*?</iframe>",
            r"<object.*?>.*?</object>",
            r"<embed.*?>.*?</embed>",
            r"onfocus\s*=\s*['\"]?[^'\"]*['\"]?",
            r"onblur\s*=\s*['\"]?[^'\"]*['\"]?",
            r"onchange\s*=\s*['\"]?[^'\"]*['\"]?",
            r"onkeypress\s*=\s*['\"]?[^'\"]*['\"]?",
        ]
        
        # Path traversal patterns
        self.path_patterns = [
            r"\.\./\.\./",
            r"\.\.\\\.\.\\",
            r"\.\.\/\.\.\/",
            r"\.\.\\\.\.\\",
            r"/etc/passwd",
            r"/etc/shadow",
            r"/var/log/",
            r"/proc/self/",
            r"boot\.ini",
            r"\.\.\/\.\.\/\.\.\/",
            r"\.\.\\\.\.\\\.\.\\",
            r"/root/",
            r"/home/",
            r"c:\\windows\\system32",
            r"c:\\inetpub\\wwwroot",
            r"\.\.\/\.\.\/\.\.\/\.\.\/",
        ]
        
        # Suspicious user agents
        self.suspicious_agents = [
            r"curl",
            r"wget",
            r"python-requests",
            r"nmap",
            r"nikto",
            r"sqlmap",
            r"zap",
            r"burp",
            r"dirbuster",
            r"hydra",
            r"ncrack",
            r"medusa",
            r"patator",
        ]
    
    def detect_brute_force(self, ip, username):
        """Enhanced brute force detection with tracking"""
        now = datetime.now()
        self.failed_attempts[ip].append(now)
        
        # Keep only last 5 minutes of attempts
        self.failed_attempts[ip] = [
            t for t in self.failed_attempts[ip] 
            if now - t < timedelta(minutes=5)
        ]
        count = len(self.failed_attempts[ip])
        
        # Enhanced alerting with email trigger
        if count >= 5:
            alert_msg = f'🚨 BRUTE FORCE ATTACK! {count} failed login attempts from {ip} for user {username} in 5 minutes!'
            self.db.add_alert('BRUTE_FORCE_ATTACK', 'CRITICAL', ip, alert_msg)
            self._emit_alert('bruteforce', 'CRITICAL', alert_msg, ip)
            return True
        elif count >= 3:
            alert_msg = f'⚠️ {count} failed login attempts for user {username} from {ip}'
            self.db.add_alert('SUSPICIOUS_LOGIN_ATTEMPTS', 'MEDIUM', ip, alert_msg)
            self._emit_alert('suspicious', 'MEDIUM', alert_msg, ip)
        else:
            alert_msg = f'Failed login attempt for user {username} from {ip}'
            self.db.add_alert('FAILED_LOGIN_ATTEMPT', 'LOW', ip, alert_msg)
            self._emit_alert('failed_login', 'LOW', alert_msg, ip)
        
        return False
    
    def scan_payload_for_threats(self, payload, source_ip):
        """Comprehensive threat scanning for payloads"""
        threats = []
        payload_lower = payload.lower() if isinstance(payload, str) else str(payload).lower()
        
        # Check SQL Injection
        for pattern in self.sql_patterns:
            if re.search(pattern, payload, re.IGNORECASE):
                threats.append({
                    'type': 'SQL_INJECTION',
                    'severity': 'CRITICAL',
                    'message': f'SQL Injection pattern detected in payload from {source_ip}'
                })
                break
        
        # Check XSS
        for pattern in self.xss_patterns:
            if re.search(pattern, payload, re.IGNORECASE):
                threats.append({
                    'type': 'XSS_ATTACK',
                    'severity': 'CRITICAL',
                    'message': f'XSS attack pattern detected in payload from {source_ip}'
                })
                break
        
        # Check Path Traversal
        for pattern in self.path_patterns:
            if re.search(pattern, payload, re.IGNORECASE):
                threats.append({
                    'type': 'PATH_TRAVERSAL',
                    'severity': 'HIGH',
                    'message': f'Path traversal attempt detected from {source_ip}'
                })
                break
        
        return threats
    
    def analyze_packet(self, packet):
        """Analyze network packet for threats"""
        threat_info = None
        packet_data = packet.get('threat', 'Normal')
        
        # Check for port scan activity (multiple SYN packets)
        if 'SYN' in packet_data or 'Port Scan' in packet_data:
            threat_info = {
                'type': 'PORT_SCAN_PACKET',
                'severity': 'HIGH',
                'message': f'Port scan detected from {packet.get("src_ip", "unknown")} to {packet.get("dst_ip", "unknown")}'
            }
        
        # Check for unusual protocols
        protocol = packet.get('protocol', '')
        if protocol in ['ICMP', 'IGMP', 'GRE'] and packet.get('threat') == 'Normal':
            threat_info = {
                'type': 'SUSPICIOUS_PROTOCOL',
                'severity': 'MEDIUM',
                'message': f'Unusual protocol {protocol} detected from {packet.get("src_ip", "unknown")}'
            }
        
        return threat_info
    
    def _emit_alert(self, alert_type, severity, message, source):
        """Emit alert via WebSocket"""
        if self.socketio:
            self.socketio.emit('new_alert', {
                'type': alert_type,
                'severity': severity,
                'message': message,
                'source': source,
                'timestamp': datetime.now().isoformat()
            })