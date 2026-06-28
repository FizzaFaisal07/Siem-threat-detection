"""
PACKET CAPTURE MODULE - Real Network Analysis with Live Streaming
REAL packet capture using Scapy + Npcap (Windows) or libpcap (Linux/Mac)
"""

import threading
import time
from datetime import datetime
from collections import defaultdict
import platform
import os
import subprocess
import sys

# Import scapy for real capture
try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP, DNS, Raw, Ether, conf
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    print("❌ Scapy not installed. Install with: pip install scapy")
    print("   For Windows, also install Npcap from: https://npcap.com/")

# Import netifaces for interface detection
try:
    import netifaces
    NETIFACES_AVAILABLE = True
except ImportError:
    NETIFACES_AVAILABLE = False
    print("⚠️ netifaces not installed. Install with: pip install netifaces")

class PacketCapture:
    def __init__(self):
        self.capturing = False
        self.packets = []
        self.packet_count = 0
        self.scan_tracker = defaultdict(lambda: defaultdict(int))
        self._stop_capture = False
        self.current_interface = 'any'
        self.live_packets = []
        self.max_live_packets = 100
        self.socketio = None
        self.npcap_installed = self._check_npcap()
        self.scapy_ready = SCAPY_AVAILABLE and self.npcap_installed
        
        if self.scapy_ready:
            print("✅ Scapy and Npcap ready for REAL packet capture!")
            print("📡 Capturing REAL network packets...")
        else:
            print("❌ Cannot capture REAL packets!")
            if not SCAPY_AVAILABLE:
                print("   - Install Scapy: pip install scapy")
            if not self.npcap_installed:
                print("   - Install Npcap from: https://npcap.com/")
                print("   - MUST check 'WinPcap API-compatible Mode' during installation")
                print("   - Then restart your computer")
            print("   ⚠️ You will NOT see real packets until these are installed!")
        
    def _check_npcap(self):
        """Check if Npcap is installed on Windows"""
        if platform.system() == 'Windows':
            npcap_paths = [
                r'C:\Windows\System32\Npcap',
                r'C:\Program Files\Npcap',
                r'C:\Windows\SysWOW64\Npcap',
                r'C:\Windows\System32\wpcap.dll',
                r'C:\Windows\SysWOW64\wpcap.dll'
            ]
            for path in npcap_paths:
                if os.path.exists(path):
                    print(f"✅ Found Npcap at: {path}")
                    return True
            
            # Also check via registry
            try:
                import winreg
                key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r'SOFTWARE\WOW6432Node\Npcap')
                if key:
                    winreg.CloseKey(key)
                    print("✅ Found Npcap in registry")
                    return True
            except:
                pass
            
            print("❌ Npcap NOT found!")
            print("   Download from: https://npcap.com/")
            print("   Install with 'WinPcap API-compatible Mode' checked")
            return False
        return True  # Linux/Mac usually have libpcap
    
    def set_socketio(self, socketio):
        self.socketio = socketio
        
    def get_interfaces(self):
        """Get all available network interfaces for REAL capture"""
        interfaces = ['any']
        
        if NETIFACES_AVAILABLE:
            try:
                for iface in netifaces.interfaces():
                    addrs = netifaces.ifaddresses(iface)
                    if netifaces.AF_INET in addrs:
                        ip = addrs[netifaces.AF_INET][0].get('addr', '')
                        if ip and ip != '127.0.0.1':
                            interfaces.append(iface)
                return interfaces
            except:
                pass
        
        # Fallback methods
        if platform.system() == 'Windows':
            try:
                result = subprocess.run(['ipconfig'], capture_output=True, text=True)
                current_iface = None
                for line in result.stdout.split('\n'):
                    if 'Ethernet adapter' in line or 'Wireless LAN adapter' in line:
                        current_iface = line.split('adapter')[1].strip().strip(':')
                        if current_iface and current_iface not in interfaces:
                            interfaces.append(current_iface)
                return interfaces
            except:
                pass
        else:
            try:
                result = subprocess.run(['ip', 'link', 'show'], capture_output=True, text=True)
                for line in result.stdout.split('\n'):
                    if ': ' in line and not line.startswith(' '):
                        iface = line.split(': ')[1].split(':')[0]
                        if iface and iface not in interfaces:
                            interfaces.append(iface)
                return interfaces
            except:
                pass
        
        # Default interfaces
        default_interfaces = ['any', 'lo', 'eth0', 'wlan0', 'en0', 'en1']
        if platform.system() == 'Windows':
            default_interfaces = ['any', 'Ethernet', 'Wi-Fi', 'Local Area Connection']
        
        return default_interfaces
    
    def is_capturing(self):
        return self.capturing
    
    def get_packet_count(self):
        return self.packet_count
    
    def get_interface(self):
        return self.current_interface
    
    def start_capture(self, interface="any", packet_limit=30, timeout=15):
        """Start REAL packet capture"""
        if not self.scapy_ready:
            print("❌ Cannot start REAL capture. Install Npcap first!")
            return []
        
        self.capturing = True
        self._stop_capture = False
        self.current_interface = interface
        captured_list = []
        self.live_packets = []
        
        print(f"📡 Starting REAL packet capture on interface: {interface}")
        print(f"   Capturing {packet_limit} packets with {timeout}s timeout")
        print("   Press 'Stop Capture' to end early")
        
        return self._start_real_capture(interface, packet_limit, timeout)
    
    def _start_real_capture(self, interface, packet_limit, timeout):
        """REAL packet capture using Scapy + Npcap"""
        captured_list = []
        packet_count = 0
        start_time = time.time()
        
        def packet_handler(pkt):
            nonlocal packet_count
            
            if self._stop_capture:
                return
            
            if IP in pkt:
                packet_data = self._parse_packet_like_wireshark(pkt)
                captured_list.append(packet_data)
                self.live_packets.append(packet_data)
                packet_count += 1
                
                if len(self.live_packets) > self.max_live_packets:
                    self.live_packets.pop(0)
                
                # Send to dashboard in real-time
                if self.socketio:
                    self.socketio.emit('new_packet', {
                        'packet': packet_data,
                        'timestamp': datetime.now().isoformat(),
                        'count': packet_count
                    })
                
                self._detect_port_scan(packet_data)
                
                # Check if we've reached the limit
                if packet_count >= packet_limit:
                    return True
            return False

        # Map interface
        if interface == "any" or interface == "all":
            iface_param = None
        else:
            iface_param = interface

        try:
            # Start REAL packet sniffing
            sniff(
                iface=iface_param, 
                prn=packet_handler, 
                timeout=timeout,
                store=False
            )
            
            print(f"✅ Captured {len(captured_list)} REAL packets on {interface}")
            
        except PermissionError:
            print("❌ Permission denied! Run as Administrator/Sudo")
            self.capturing = False
            return []
        except Exception as e:
            print(f"❌ Real capture error: {e}")
            print("   Make sure Npcap is installed with 'WinPcap API-compatible Mode'")
            self.capturing = False
            return []
            
        self.packets = captured_list
        self.packet_count = len(captured_list)
        self.capturing = False
        return captured_list
    
    def _parse_packet_like_wireshark(self, pkt):
        """Parse REAL packet with Wireshark-like detail"""
        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst
        
        protocol = 'OTHER'
        src_port = ''
        dst_port = ''
        threat_status = '✅ Normal'
        length = len(pkt)
        flags_display = ''
        info = ''
        
        # TCP Analysis
        if TCP in pkt:
            protocol = 'TCP'
            src_port = str(pkt[TCP].sport)
            dst_port = str(pkt[TCP].dport)
            flags = pkt[TCP].flags
            flags_str = []
            
            if flags & 0x01: flags_str.append('FIN')
            if flags & 0x02: flags_str.append('SYN')
            if flags & 0x04: flags_str.append('RST')
            if flags & 0x08: flags_str.append('PSH')
            if flags & 0x10: flags_str.append('ACK')
            if flags & 0x20: flags_str.append('URG')
            if flags & 0x40: flags_str.append('ECE')
            if flags & 0x80: flags_str.append('CWR')
            
            flags_display = ' '.join(flags_str) if flags_str else 'None'
            
            # Threat detection on real packets
            if flags & 0x02 and not (flags & 0x10):
                threat_status = "⚠️ SYN (Port Scan)"
                self.scan_tracker[src_ip][dst_port] += 1
            elif flags & 0x01:
                threat_status = "⚠️ FIN Scan"
            elif flags & 0x04:
                threat_status = "⚠️ RST"
            elif flags & 0x12:  # SYN-ACK
                threat_status = "✅ SYN-ACK"
            
            # Application layer detection
            if pkt[TCP].dport == 80 or pkt[TCP].sport == 80:
                info = "HTTP"
                if Raw in pkt:
                    try:
                        payload = pkt[Raw].load[:200].decode('utf-8', errors='ignore')
                        if 'GET' in payload or 'POST' in payload:
                            first_line = payload.split('\n')[0][:50]
                            info += f" - {first_line}"
                    except:
                        pass
            elif pkt[TCP].dport == 443 or pkt[TCP].sport == 443:
                info = "HTTPS"
            elif pkt[TCP].dport == 22 or pkt[TCP].sport == 22:
                info = "SSH"
            elif pkt[TCP].dport == 21 or pkt[TCP].sport == 21:
                info = "FTP"
            elif pkt[TCP].dport == 25 or pkt[TCP].sport == 25:
                info = "SMTP"
            elif pkt[TCP].dport == 53 or pkt[TCP].sport == 53:
                info = "DNS"
                
        # UDP Analysis
        elif UDP in pkt:
            protocol = 'UDP'
            src_port = str(pkt[UDP].sport)
            dst_port = str(pkt[UDP].dport)
            
            if pkt[UDP].dport == 53 or pkt[UDP].sport == 53:
                protocol = 'DNS'
                if DNS in pkt:
                    dns = pkt[DNS]
                    if dns.qd:
                        qname = dns.qd.qname
                        if hasattr(qname, 'decode'):
                            info = f"DNS Query: {qname.decode()}"
                        else:
                            info = f"DNS Query: {qname}"
            elif pkt[UDP].dport == 67 or pkt[UDP].sport == 67 or pkt[UDP].dport == 68 or pkt[UDP].sport == 68:
                protocol = 'DHCP'
                info = "DHCP"
            elif pkt[UDP].dport == 123 or pkt[UDP].sport == 123:
                protocol = 'NTP'
                info = "NTP"
                
        # ICMP Analysis
        elif ICMP in pkt:
            protocol = 'ICMP'
            icmp_type = pkt[ICMP].type
            
            if icmp_type == 0:
                info = "Echo Reply"
                threat_status = "✅ ICMP Reply"
            elif icmp_type == 8:
                info = "Echo Request (Ping)"
                threat_status = "⚠️ ICMP Ping"
            elif icmp_type == 3:
                info = "Destination Unreachable"
            elif icmp_type == 11:
                info = "Time Exceeded"
        
        packet = {
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3],
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'protocol': protocol,
            'src_port': src_port,
            'dst_port': dst_port,
            'length': str(length),
            'threat': threat_status,
            'flags': flags_display,
            'info': info,
            'raw_flags': str(flags) if TCP in pkt else ''
        }
        return packet
    
    def _detect_port_scan(self, packet):
        """Detect port scanning patterns from REAL packets"""
        src_ip = packet.get('src_ip', '')
        dst_port = packet.get('dst_port', '')
        
        if 'SYN' in packet.get('threat', ''):
            self.scan_tracker[src_ip][dst_port] += 1
            
            # If same IP has SYN on multiple ports, it's a port scan
            if len(self.scan_tracker[src_ip]) >= 5:
                packet['threat'] = "🚨 PORT SCAN DETECTED!"
                if self.socketio:
                    self.socketio.emit('new_alert', {
                        'type': 'PORT_SCAN',
                        'severity': 'HIGH',
                        'message': f'Port scan detected from {src_ip} on {len(self.scan_tracker[src_ip])} ports',
                        'source': src_ip,
                        'timestamp': datetime.now().isoformat()
                    })
    
    def stop_capture(self):
        """Stop REAL packet capture"""
        self._stop_capture = True
        self.capturing = False
        print("⏹️ Real packet capture stopped")
    
    def get_live_packets(self, limit=50):
        return self.live_packets[-limit:] if self.live_packets else []
    
    def get_stats(self):
        if not self.packets and not self.live_packets:
            return {'total': 0, 'protocols': {}, 'threats': 0, 'live_count': 0}
        
        packets = self.packets if self.packets else self.live_packets
        protocols = defaultdict(int)
        threats = 0
        
        for p in packets:
            protocols[p.get('protocol', 'unknown')] += 1
            if '⚠️' in p.get('threat', '') or '🚨' in p.get('threat', ''):
                threats += 1
        
        return {
            'total': len(packets),
            'protocols': dict(protocols),
            'threats': threats,
            'live_count': len(self.live_packets),
            'real_capture': True
        }