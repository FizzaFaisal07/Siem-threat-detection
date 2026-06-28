# 🛡️ SIEM Enterprise - Advanced Threat Detection System
## 📖 Overview

A comprehensive Security Information and Event Management (SIEM) system with real-time threat detection, packet analysis, and automated alerting. Built with Flask, SocketIO, and Scapy.
---

## 🚀 Features

### 🔐 Security Detection

- **Real-time Brute Force Detection** - Detects and blocks brute force attacks with automatic account lockout after 5 failed attempts
- **SQL Injection Detection** - Identifies SQL injection attempts in real-time
- **XSS Attack Detection** - Detects cross-site scripting attacks
- **Path Traversal Detection** - Identifies path traversal attempts
- **Port Scanning Detection** - Detects network reconnaissance activity

### 📡 Network Monitoring

- **Network Packet Analysis** - Real-time packet capture and analysis (Wireshark-style)
- **Protocol Analysis** - TCP, UDP, DNS, ICMP analysis
- **TCP Flag Analysis** - Detailed SYN, ACK, FIN, RST tracking
- **Traffic Statistics** - Real-time network statistics

### 💻 System Monitoring

- **System Metrics Monitoring** - CPU, Memory, Disk, Network monitoring
- **Live Dashboard** - Real-time visualization with WebSocket updates
- **Threat Trends** - Visual alert timeline with ApexCharts
- **Process Monitoring** - Top processes tracking

### 🔑 Authentication & Security

- **Email Alerts** - Automated alerts for critical threats
- **2FA Support** - Two-factor authentication via email OTP
- **Account Lockout** - Automatic lockout after 5 failed attempts
- **Session Management** - Secure session tokens with expiration
- **SHA-256 Log Integrity** - Cryptographic verification of logs

### 📊 Reporting

- **Export Reports** - HTML, CSV, JSON export
- **Packet Export** - Detailed packet captures
- **Real-time Analytics** - Live attack visualization

---

## 📋 Prerequisites

- Python 3.8+
- Windows/Linux/Mac
- Npcap (Windows) or libpcap (Linux/Mac)
- Nmap (optional, for port scanning)

---

## 🔧 Installation

### Quick Install

```bash
# Clone the repository
git clone https://github.com/FizzaFaisal07/Siem-threat-detection.git
cd Siem-threat-detection

# Install dependencies
pip install -r requirements.txt

# Run the application
python app.py
