import sqlite3
from datetime import datetime, timedelta
from crypto_utils import CryptoUtils
import json

class Database:
    def __init__(self, db_path="siem.db"):
        self.db_path = db_path
        self.crypto = CryptoUtils()
        self._init_db()
    
    def _get_conn(self):
        return sqlite3.connect(self.db_path, timeout=30, check_same_thread=False)
    
    def _init_db(self):
        conn = self._get_conn()
        cursor = conn.cursor()
        
        # Alerts table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                type TEXT NOT NULL,
                severity TEXT NOT NULL,
                source TEXT,
                message TEXT,
                hash TEXT,
                resolved INTEGER DEFAULT 0
            )
        ''')
        
        # Packets table with all columns
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS packets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                src_ip TEXT,
                dst_ip TEXT,
                protocol TEXT,
                threat TEXT,
                hash TEXT,
                src_port TEXT,
                dst_port TEXT,
                length INTEGER,
                flags TEXT,
                info TEXT,
                raw_flags TEXT
            )
        ''')
        
        # Check if columns exist and add if missing
        cursor.execute("PRAGMA table_info(packets)")
        existing_columns = [col[1] for col in cursor.fetchall()]
        
        columns_to_add = {
            'src_port': 'TEXT',
            'dst_port': 'TEXT',
            'length': 'INTEGER',
            'flags': 'TEXT',
            'info': 'TEXT',
            'raw_flags': 'TEXT'
        }
        
        for col_name, col_type in columns_to_add.items():
            if col_name not in existing_columns:
                try:
                    cursor.execute(f'ALTER TABLE packets ADD COLUMN {col_name} {col_type}')
                    print(f"✅ Added column: {col_name}")
                except Exception as e:
                    print(f"⚠️ Could not add column {col_name}: {e}")
        
        # Users table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                role TEXT DEFAULT 'user',
                created_at TEXT,
                last_login TEXT,
                failed_attempts INTEGER DEFAULT 0,
                locked_until TEXT,
                twofa_secret TEXT,
                twofa_enabled INTEGER DEFAULT 0
            )
        ''')
        
        # Request logs table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS request_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                ip TEXT,
                endpoint TEXT,
                method TEXT,
                user_agent TEXT,
                status_code INTEGER
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def add_alert(self, alert_type, severity, source, message):
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        entry = {
            'timestamp': timestamp,
            'type': alert_type,
            'severity': severity,
            'source': source,
            'message': message
        }
        hash_val = self.crypto.calculate_hash(entry)
        
        conn = self._get_conn()
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO alerts (timestamp, type, severity, source, message, hash)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (timestamp, alert_type, severity, source, message, hash_val))
        conn.commit()
        conn.close()
        return hash_val
    
    def add_packet(self, packet):
        conn = self._get_conn()
        cursor = conn.cursor()
        timestamp = packet.get('timestamp', datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
        
        cursor.execute('''
            INSERT INTO packets 
            (timestamp, src_ip, dst_ip, protocol, threat, hash, 
             src_port, dst_port, length, flags, info, raw_flags)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            timestamp,
            packet.get('src_ip', ''),
            packet.get('dst_ip', ''),
            packet.get('protocol', ''),
            packet.get('threat', 'Normal'),
            self.crypto.calculate_hash(packet),
            packet.get('src_port', ''),
            packet.get('dst_port', ''),
            int(packet.get('length', 0)) if str(packet.get('length', '0')).isdigit() else 0,
            packet.get('flags', ''),
            packet.get('info', ''),
            packet.get('raw_flags', '')
        ))
        conn.commit()
        conn.close()
    
    def get_alerts(self, limit=100, severity='all', source='', offset=0):
        conn = self._get_conn()
        cursor = conn.cursor()
        query = 'SELECT id, timestamp, type, severity, source, message FROM alerts'
        params = []
        
        conditions = []
        if severity != 'all':
            if severity == 'HIGH':
                conditions.append("severity IN ('HIGH', 'CRITICAL')")
            else:
                conditions.append("severity = ?")
                params.append(severity)
        
        if source:
            conditions.append("source LIKE ?")
            params.append(f'%{source}%')
        
        if conditions:
            query += ' WHERE ' + ' AND '.join(conditions)
        
        query += ' ORDER BY id DESC LIMIT ? OFFSET ?'
        params.extend([limit, offset])
        
        cursor.execute(query, params)
        rows = cursor.fetchall()
        conn.close()
        
        return [{
            'id': r[0], 'timestamp': r[1], 'type': r[2],
            'severity': r[3], 'source': r[4], 'message': r[5]
        } for r in rows]
    
    def get_packets(self, limit=50, protocol='all'):
        conn = self._get_conn()
        cursor = conn.cursor()
        
        if protocol != 'all':
            cursor.execute('''
                SELECT id, timestamp, src_ip, dst_ip, protocol, threat, 
                       src_port, dst_port, length, flags, info
                FROM packets WHERE protocol = ? ORDER BY id DESC LIMIT ?
            ''', (protocol, limit))
        else:
            cursor.execute('''
                SELECT id, timestamp, src_ip, dst_ip, protocol, threat, 
                       src_port, dst_port, length, flags, info
                FROM packets ORDER BY id DESC LIMIT ?
            ''', (limit,))
        
        rows = cursor.fetchall()
        conn.close()
        
        return [{
            'id': r[0], 'timestamp': r[1], 'src_ip': r[2],
            'dst_ip': r[3], 'protocol': r[4], 'threat': r[5],
            'src_port': r[6], 'dst_port': r[7], 'length': r[8], 
            'flags': r[9], 'info': r[10]
        } for r in rows]
    
    def get_packet_by_id(self, packet_id):
        conn = self._get_conn()
        cursor = conn.cursor()
        cursor.execute('''
            SELECT id, timestamp, src_ip, dst_ip, protocol, threat, 
                   src_port, dst_port, length, flags, info
            FROM packets WHERE id = ?
        ''', (packet_id,))
        row = cursor.fetchone()
        conn.close()
        
        if row:
            return {
                'id': row[0], 'timestamp': row[1], 'src_ip': row[2],
                'dst_ip': row[3], 'protocol': row[4], 'threat': row[5],
                'src_port': row[6], 'dst_port': row[7], 'length': row[8], 
                'flags': row[9], 'info': row[10]
            }
        return None
    
    def get_alerts_by_type(self, alert_type):
        conn = self._get_conn()
        cursor = conn.cursor()
        cursor.execute('SELECT COUNT(*) FROM alerts WHERE type = ?', (alert_type,))
        count = cursor.fetchone()[0]
        conn.close()
        return count
    
    def get_stats(self):
        conn = self._get_conn()
        cursor = conn.cursor()
        cursor.execute('SELECT COUNT(*) FROM alerts')
        total = cursor.fetchone()[0]
        cursor.execute("SELECT COUNT(*) FROM alerts WHERE severity IN ('HIGH', 'CRITICAL')")
        critical = cursor.fetchone()[0]
        cursor.execute('SELECT COUNT(*) FROM packets')
        packets = cursor.fetchone()[0]
        cursor.execute("SELECT severity, COUNT(*) FROM alerts GROUP BY severity")
        by_severity = dict(cursor.fetchall())
        conn.close()
        
        return {
            'total_alerts': total,
            'active_threats': critical,
            'total_packets': packets,
            'by_severity': by_severity
        }
    
    def get_attack_statistics(self):
        conn = self._get_conn()
        cursor = conn.cursor()
        
        attack_types = ['BRUTE_FORCE_ATTACK', 'SQL_INJECTION', 'XSS_ATTACK', 
                        'PATH_TRAVERSAL', 'PORT_SCAN_PACKET']
        
        stats = {}
        for attack_type in attack_types:
            cursor.execute('SELECT COUNT(*) FROM alerts WHERE type = ?', (attack_type,))
            stats[attack_type.lower()] = cursor.fetchone()[0]
        
        conn.close()
        return stats
    
    def get_integrity_status(self):
        conn = self._get_conn()
        cursor = conn.cursor()
        cursor.execute('SELECT timestamp, type, source, message, hash FROM alerts')
        rows = cursor.fetchall()
        conn.close()
        
        verified = 0
        total = len(rows)
        for row in rows:
            data = {'timestamp': row[0], 'type': row[1], 'source': row[2], 'message': row[3]}
            if self.crypto.verify_integrity(data, row[4]):
                verified += 1
        
        percentage = (verified / total * 100) if total > 0 else 100
        return {
            'total_logs': total,
            'verified': verified,
            'tampered': total - verified,
            'integrity_percentage': int(percentage)
        }
    
    def resolve_alert(self, alert_id):
        conn = self._get_conn()
        cursor = conn.cursor()
        cursor.execute('UPDATE alerts SET resolved = 1 WHERE id = ?', (alert_id,))
        conn.commit()
        conn.close()
        return True
    
    def clear_alerts(self):
        conn = self._get_conn()
        cursor = conn.cursor()
        cursor.execute('DELETE FROM alerts')
        conn.commit()
        conn.close()
        return True
    
    def get_alerts_count(self, severity='all', source=''):
        conn = self._get_conn()
        cursor = conn.cursor()
        query = 'SELECT COUNT(*) FROM alerts'
        params = []
        
        conditions = []
        if severity != 'all':
            if severity == 'HIGH':
                conditions.append("severity IN ('HIGH', 'CRITICAL')")
            else:
                conditions.append("severity = ?")
                params.append(severity)
        
        if source:
            conditions.append("source LIKE ?")
            params.append(f'%{source}%')
        
        if conditions:
            query += ' WHERE ' + ' AND '.join(conditions)
        
        cursor.execute(query, params)
        count = cursor.fetchone()[0]
        conn.close()
        return count
    
    def get_alert_counts_by_severity(self):
        conn = self._get_conn()
        cursor = conn.cursor()
        cursor.execute("SELECT severity, COUNT(*) FROM alerts GROUP BY severity")
        counts = dict(cursor.fetchall())
        conn.close()
        return counts
    
    def get_db_size(self):
        import os
        if os.path.exists(self.db_path):
            return os.path.getsize(self.db_path) // 1024  # KB
        return 0
    
    def get_packets_count(self):
        conn = self._get_conn()
        cursor = conn.cursor()
        cursor.execute('SELECT COUNT(*) FROM packets')
        count = cursor.fetchone()[0]
        conn.close()
        return count
    
    def get_user_count(self):
        conn = self._get_conn()
        cursor = conn.cursor()
        cursor.execute('SELECT COUNT(*) FROM users')
        count = cursor.fetchone()[0]
        conn.close()
        return count
    
    def get_all_users(self):
        conn = self._get_conn()
        cursor = conn.cursor()
        cursor.execute('SELECT id, username, email, role, created_at, last_login FROM users')
        rows = cursor.fetchall()
        conn.close()
        
        return [{
            'id': r[0], 'username': r[1], 'email': r[2],
            'role': r[3], 'created_at': r[4], 'last_login': r[5]
        } for r in rows]
    
    def delete_user(self, user_id):
        conn = self._get_conn()
        cursor = conn.cursor()
        cursor.execute('DELETE FROM users WHERE id = ?', (user_id,))
        conn.commit()
        conn.close()
        return True
    
    def get_alerts_last_24h(self):
        conn = self._get_conn()
        cursor = conn.cursor()
        yesterday = (datetime.now() - timedelta(days=1)).strftime('%Y-%m-%d %H:%M:%S')
        cursor.execute('SELECT COUNT(*) FROM alerts WHERE timestamp > ?', (yesterday,))
        count = cursor.fetchone()[0]
        conn.close()
        return count