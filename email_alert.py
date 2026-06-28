"""
EMAIL ALERT SYSTEM - Send notifications for critical threats
"""

import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime
import threading
import logging
import json
import os

class EmailAlertSystem:
    def __init__(self, smtp_server='smtp.gmail.com', smtp_port=587, 
                 sender_email='fizzafaisal07@gmail.com', sender_password='motlgvjjifzbzmix'):
        self.smtp_server = smtp_server
        self.smtp_port = smtp_port
        self.sender_email = sender_email
        self.sender_password = sender_password
        self.recipients = ['fizzafaisal07@gmail.com']
        self.enabled = True  # SET TO TRUE to enable email alerts
        self.logger = logging.getLogger(__name__)
        
        # Test connection on startup
        if self.enabled:
            self.test_connection()
    
    def test_connection(self):
        """Test email connection"""
        try:
            server = smtplib.SMTP(self.smtp_server, self.smtp_port, timeout=10)
            server.starttls()
            server.login(self.sender_email, self.sender_password)
            server.quit()
            print(f"✅ Email alerts configured for: {self.sender_email}")
            return True
        except Exception as e:
            print(f"❌ Email configuration failed: {e}")
            print("   Check your email/password or enable 'Less Secure Apps'")
            self.enabled = False
            return False
    
    def send_alert_email(self, subject, message, source_ip, severity='CRITICAL'):
        """Send email alert for critical threats"""
        if not self.enabled:
            self.logger.info(f"Email disabled. Would send: {subject} from {source_ip}")
            return False
        
        def send_thread():
            try:
                msg = MIMEMultipart('alternative')
                msg['From'] = f"SIEM Alert System <{self.sender_email}>"
                msg['To'] = ', '.join(self.recipients)
                msg['Subject'] = f"🔴 SIEM ALERT: {subject}"
                msg['X-Priority'] = '1'
                msg['X-MSMail-Priority'] = 'High'
                
                # Plain text body
                text_body = f"""
╔══════════════════════════════════════════════════════════════╗
║              🛡️ SIEM ENTERPRISE SECURITY ALERT              ║
╚══════════════════════════════════════════════════════════════╝

🔴 SEVERITY: {severity}
⏰ TIME: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
📍 SOURCE: {source_ip}
📝 MESSAGE: {message}

───────────────────────────────────────────────────────────────
⚠️ IMMEDIATE ACTION REQUIRED

Please investigate this security incident immediately.

🔗 Dashboard: http://localhost:5000
👤 Login: admin / Admin@123

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
        .container {{ max-width: 600px; margin: 0 auto; background: white; border-radius: 10px; padding: 30px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
        .header {{ background: linear-gradient(135deg,#1a1f3a,#0a0e27); color: white; padding: 20px; border-radius: 10px 10px 0 0; }}
        .critical {{ color: #ef4444; font-weight: bold; font-size: 20px; }}
        .content {{ padding: 20px; }}
        .field {{ margin: 10px 0; padding: 10px; background: #f8f9fa; border-radius: 5px; }}
        .footer {{ text-align: center; color: #888; font-size: 12px; padding: 20px; border-top: 1px solid #eee; }}
        .button {{ display: inline-block; padding: 10px 20px; background: #00d4ff; color: white; text-decoration: none; border-radius: 5px; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ SIEM Enterprise Alert</h1>
            <p style="opacity:0.8;">Security Information & Event Management</p>
        </div>
        <div class="content">
            <div class="field">
                <span style="color:#ef4444;font-weight:bold;">🔴 SEVERITY: {severity}</span>
            </div>
            <div class="field">
                <span style="color:#666;">⏰ Time:</span> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
            </div>
            <div class="field">
                <span style="color:#666;">📍 Source:</span> {source_ip}
            </div>
            <div class="field">
                <span style="color:#666;">📝 Message:</span><br>
                <strong>{message}</strong>
            </div>
            <div style="background:#fee;padding:15px;border-radius:5px;margin:15px 0;border-left:4px solid #ef4444;">
                ⚠️ <strong>IMMEDIATE ACTION REQUIRED</strong>
            </div>
            <p>
                <a href="http://localhost:5000" class="button">🔗 View Dashboard</a>
            </p>
            <p style="font-size:12px;color:#888;">
                👤 Login: admin / Admin@123
            </p>
        </div>
        <div class="footer">
            <p>🔐 SHA-256 Protected | Real-time Threat Detection</p>
            <p>SIEM Enterprise v3.0</p>
        </div>
    </div>
</body>
</html>
"""
                
                # Attach both plain text and HTML
                part1 = MIMEText(text_body, 'plain')
                part2 = MIMEText(html_body, 'html')
                msg.attach(part1)
                msg.attach(part2)
                
                # Send email
                server = smtplib.SMTP(self.smtp_server, self.smtp_port, timeout=30)
                server.starttls()
                server.login(self.sender_email, self.sender_password)
                server.send_message(msg)
                server.quit()
                
                self.logger.info(f"✅ Email alert sent: {subject}")
                print(f"📧 Email sent: {subject}")
                
            except Exception as e:
                self.logger.error(f"❌ Failed to send email alert: {e}")
                print(f"❌ Email failed: {e}")
        
        threading.Thread(target=send_thread, daemon=True).start()
        return True
    
    def send_test_email(self):
        """Send a test email to verify configuration"""
        return self.send_alert_email(
            "TEST: SIEM Email Configuration",
            "This is a test email from your SIEM system. Configuration is working! ✅",
            "localhost",
            "LOW"
        )