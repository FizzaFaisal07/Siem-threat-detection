import hashlib
import secrets
import sqlite3
from datetime import datetime, timedelta
import re
import random
import string
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import threading
import time

class AuthSystem:
    def __init__(self, db_path="siem.db"):
        self.db_path = db_path
        self.sessions = {}
        self.failed_login_attempts = {}
        self.otp_storage = {}
        self._init_users_table()
        self._create_default_admin()
        
        # Email settings for OTP
        self.smtp_server = 'smtp.gmail.com'
        self.smtp_port = 587
        self.sender_email = 'fizzafaisal07@gmail.com'
        self.sender_password = 'motlgvjjifzbzmix'
        self.email_enabled = True
    
    def _init_users_table(self):
        """Create users table with 2FA support"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
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
                twofa_enabled INTEGER DEFAULT 0,
                twofa_type TEXT DEFAULT 'email'
            )
        ''')
        
        # Check and add columns if they don't exist
        cursor.execute("PRAGMA table_info(users)")
        columns = [col[1] for col in cursor.fetchall()]
        
        if 'twofa_enabled' not in columns:
            cursor.execute('ALTER TABLE users ADD COLUMN twofa_enabled INTEGER DEFAULT 0')
            print("✅ Added twofa_enabled column")
        
        if 'twofa_type' not in columns:
            cursor.execute('ALTER TABLE users ADD COLUMN twofa_type TEXT DEFAULT "email"')
            print("✅ Added twofa_type column")
        
        conn.commit()
        conn.close()
    
    def hash_password(self, password):
        return hashlib.sha256(password.encode()).hexdigest()
    
    def _create_default_admin(self):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE username='admin'")
        if not cursor.fetchone():
            pw_hash = self.hash_password('Admin@123')
            cursor.execute('''
                INSERT INTO users (username, email, password_hash, role, created_at, twofa_enabled)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', ('admin', 'fizzafaisal07@gmail.com', pw_hash, 'admin', 
                  datetime.now().isoformat(), 1))
            conn.commit()
            print("✅ Default admin created: admin / Admin@123")
            print("📧 2FA OTP will be sent to: fizzafaisal07@gmail.com")
        conn.close()
    
    def generate_otp(self):
        """Generate a 6-digit OTP"""
        return ''.join(random.choices(string.digits, k=6))
    
    def send_otp_email(self, email, otp, username):
        """Send OTP via email"""
        if not self.email_enabled:
            print(f"📧 Email disabled. OTP for {username}: {otp}")
            return False
        
        def send_thread():
            try:
                msg = MIMEMultipart('alternative')
                msg['From'] = f"SIEM Security <{self.sender_email}>"
                msg['To'] = email
                msg['Subject'] = f"🔐 SIEM 2FA Verification Code"
                
                # Plain text
                text_body = f"""
╔══════════════════════════════════════════════════════════════╗
║              🔐 SIEM 2FA VERIFICATION CODE                  ║
╚══════════════════════════════════════════════════════════════╝

Hello {username},

Your 2FA verification code is:

🔑 {otp}

This code will expire in 5 minutes.

If you didn't request this code, please ignore this email.

───────────────────────────────────────────────────────────────
SIEM Enterprise Security System
SHA-256 Protected | Real-time Threat Detection
"""
                
                # HTML body
                html_body = f"""
<!DOCTYPE html>
<html>
<head>
    <style>
        body {{ font-family: Arial, sans-serif; background: #f0f4f8; padding: 20px; }}
        .container {{ max-width: 500px; margin: 0 auto; background: white; border-radius: 10px; padding: 30px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
        .header {{ background: linear-gradient(135deg,#1a1f3a,#0a0e27); color: white; padding: 20px; border-radius: 10px 10px 0 0; }}
        .code {{ font-size: 48px; font-weight: bold; text-align: center; padding: 20px; background: #f8f9fa; border-radius: 10px; margin: 20px 0; letter-spacing: 10px; color: #00d4ff; }}
        .footer {{ text-align: center; color: #888; font-size: 12px; padding: 20px; border-top: 1px solid #eee; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔐 SIEM 2FA Verification</h1>
        </div>
        <div style="padding: 20px;">
            <p>Hello <strong>{username}</strong>,</p>
            <p>Your 2FA verification code is:</p>
            <div class="code">{otp}</div>
            <p style="color: #666; font-size: 14px;">This code will expire in <strong>5 minutes</strong>.</p>
            <p style="color: #888; font-size: 12px;">If you didn't request this code, please ignore this email.</p>
        </div>
        <div class="footer">
            <p>🔐 SHA-256 Protected | SIEM Enterprise</p>
        </div>
    </div>
</body>
</html>
"""
                
                part1 = MIMEText(text_body, 'plain')
                part2 = MIMEText(html_body, 'html')
                msg.attach(part1)
                msg.attach(part2)
                
                server = smtplib.SMTP(self.smtp_server, self.smtp_port, timeout=30)
                server.starttls()
                server.login(self.sender_email, self.sender_password)
                server.send_message(msg)
                server.quit()
                
                print(f"📧 OTP sent to {email}")
                
            except Exception as e:
                print(f"❌ Failed to send OTP email: {e}")
        
        threading.Thread(target=send_thread, daemon=True).start()
        return True
    
    def request_2fa_otp(self, username):
        """Request 2FA OTP for a user"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('SELECT email, twofa_enabled FROM users WHERE username = ?', (username,))
        user = cursor.fetchone()
        conn.close()
        
        if not user:
            return False, "User not found"
        
        email = user[0]
        twofa_enabled = user[1] if user[1] is not None else 0
        
        if twofa_enabled != 1:
            return False, "2FA not enabled for this user"
        
        # Generate OTP
        otp = self.generate_otp()
        
        # Store OTP with expiration (5 minutes)
        self.otp_storage[username] = {
            'otp': otp,
            'expires': datetime.now() + timedelta(minutes=5),
            'email': email,
            'attempts': 0
        }
        
        # Send OTP via email
        self.send_otp_email(email, otp, username)
        
        return True, "OTP sent to your email"
    
    def verify_2fa_otp(self, username, otp):
        """Verify 2FA OTP"""
        if username not in self.otp_storage:
            return False, "No OTP requested or expired"
        
        stored_data = self.otp_storage[username]
        
        # Check expiration
        if datetime.now() > stored_data['expires']:
            del self.otp_storage[username]
            return False, "OTP expired. Request a new one."
        
        # Check attempts (max 3)
        stored_data['attempts'] += 1
        if stored_data['attempts'] > 3:
            del self.otp_storage[username]
            return False, "Too many failed attempts. Request a new OTP."
        
        # Verify OTP
        if stored_data['otp'] == otp:
            del self.otp_storage[username]
            return True, "OTP verified successfully"
        
        return False, f"Invalid OTP. {3 - stored_data['attempts']} attempts remaining"
    
    def register(self, username, email, password, enable_2fa=True):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Check if user exists
        cursor.execute("SELECT * FROM users WHERE username=? OR email=?", (username, email))
        if cursor.fetchone():
            conn.close()
            return False, "Username or email already exists"
        
        # Validate password strength
        if len(password) < 8:
            conn.close()
            return False, "Password must be at least 8 characters"
        if not any(c.isupper() for c in password):
            conn.close()
            return False, "Password must contain an uppercase letter"
        if not any(c.islower() for c in password):
            conn.close()
            return False, "Password must contain a lowercase letter"
        if not any(c.isdigit() for c in password):
            conn.close()
            return False, "Password must contain a number"
        if not any(c in '!@#$%^&*()_+-=[]{}|;:,.<>?/' for c in password):
            conn.close()
            return False, "Password must contain a special character"
        
        pw_hash = self.hash_password(password)
        twofa_enabled = 1 if enable_2fa else 0
        
        try:
            cursor.execute('''
                INSERT INTO users (username, email, password_hash, created_at, twofa_enabled)
                VALUES (?, ?, ?, ?, ?)
            ''', (username, email, pw_hash, datetime.now().isoformat(), twofa_enabled))
            conn.commit()
            
            if enable_2fa:
                print(f"📧 2FA enabled for {username}. OTP will be sent to {email}")
            
            return True, "Registration successful!" + (" 2FA enabled." if enable_2fa else "")
        except Exception as e:
            return False, str(e)
        finally:
            conn.close()
    
    def login(self, username, password, twofa_code=None, otp_code=None):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT password_hash, role, email, failed_attempts, locked_until, twofa_enabled
            FROM users WHERE username=?
        ''', (username,))
        user = cursor.fetchone()
        conn.close()
        
        if not user:
            return None, "User not found", 0
        
        password_hash = user[0]
        role = user[1]
        email = user[2]
        failed_attempts = user[3] if user[3] is not None else 0
        locked_until = user[4]
        twofa_enabled = user[5] if user[5] is not None else 0
        
        # Check if account is locked
        if locked_until:
            try:
                lock_time = datetime.fromisoformat(locked_until)
                if datetime.now() < lock_time:
                    remaining = int((lock_time - datetime.now()).total_seconds())
                    return None, f"Account locked. Try again in {remaining} seconds", failed_attempts
            except:
                pass
        
        input_hash = self.hash_password(password)
        
        if password_hash != input_hash:
            # Track failed attempts
            if username not in self.failed_login_attempts:
                self.failed_login_attempts[username] = []
            self.failed_login_attempts[username].append(datetime.now())
            
            self.failed_login_attempts[username] = [
                t for t in self.failed_login_attempts[username] 
                if datetime.now() - t < timedelta(minutes=15)
            ]
            attempt_count = len(self.failed_login_attempts[username])
            
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            new_attempts = failed_attempts + 1
            
            if new_attempts >= 5:
                lock_until = (datetime.now() + timedelta(minutes=15)).isoformat()
                cursor.execute('''
                    UPDATE users SET failed_attempts = ?, locked_until = ? 
                    WHERE username = ?
                ''', (new_attempts, lock_until, username))
                message = f"ACCOUNT LOCKED for 15 minutes! Too many failed attempts."
            else:
                cursor.execute('''
                    UPDATE users SET failed_attempts = ? 
                    WHERE username = ?
                ''', (new_attempts, username))
                message = f"Wrong password. {5 - new_attempts} attempts remaining"
            
            conn.commit()
            conn.close()
            return None, message, attempt_count
        
        # Check 2FA if enabled
        if twofa_enabled == 1:
            if not otp_code:
                # Request OTP and return special response
                self.request_2fa_otp(username)
                return None, "2FA_OTP_REQUIRED", 0
            else:
                # Verify OTP
                verified, msg = self.verify_2fa_otp(username, otp_code)
                if not verified:
                    return None, msg, 0
        
        # SUCCESSFUL LOGIN
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('''
            UPDATE users SET failed_attempts = 0, locked_until = NULL, last_login = ? 
            WHERE username = ?
        ''', (datetime.now().isoformat(), username))
        conn.commit()
        conn.close()
        
        if username in self.failed_login_attempts:
            del self.failed_login_attempts[username]
        
        # Create session token
        token = secrets.token_hex(32)
        self.sessions[token] = {
            'username': username,
            'role': role,
            'email': email,
            'expires': datetime.now() + timedelta(hours=2)
        }
        return token, "Login successful", 0

    def verify_session(self, token):
        if token in self.sessions:
            if self.sessions[token]['expires'] > datetime.now():
                return True, self.sessions[token]
            del self.sessions[token]
        return False, None

    def logout(self, token):
        if token in self.sessions:
            del self.sessions[token]
        return True

    def get_brute_force_status(self):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('SELECT username, failed_attempts, locked_until FROM users WHERE failed_attempts > 0')
        rows = cursor.fetchall()
        conn.close()
        return [{'username': r[0], 'attempts': r[1], 'locked': r[2] is not None} for r in rows]

    def enable_2fa(self, username):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('UPDATE users SET twofa_enabled = 1 WHERE username = ?', (username,))
        conn.commit()
        conn.close()
        return True
    
    def disable_2fa(self, username):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('UPDATE users SET twofa_enabled = 0 WHERE username = ?', (username,))
        conn.commit()
        conn.close()
        return True
    
    def get_2fa_status(self, username):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('SELECT twofa_enabled, email FROM users WHERE username = ?', (username,))
        result = cursor.fetchone()
        conn.close()
        if result:
            return {'enabled': result[0] == 1, 'email': result[1]}
        return None