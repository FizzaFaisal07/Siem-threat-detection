import subprocess
import shutil
import re
from datetime import datetime
import platform

class NmapScanner:
    def __init__(self):
        self.nmap_installed = self._check_nmap()
        if not self.nmap_installed:
            print("⚠️ Nmap not found! Install from: https://nmap.org/download.html")
    
    def _check_nmap(self):
        try:
            result = subprocess.run(['nmap', '--version'], capture_output=True, timeout=5)
            return result.returncode == 0
        except:
            return False
    
    def get_interfaces(self):
        try:
            if platform.system() == 'Windows':
                result = subprocess.run(['ipconfig'], capture_output=True, text=True)
                interfaces = []
                for line in result.stdout.split('\n'):
                    if 'Ethernet adapter' in line or 'Wireless LAN adapter' in line:
                        name = line.split('adapter')[1].strip().strip(':')
                        if name:
                            interfaces.append(name)
                return interfaces if interfaces else ['any']
            else:
                result = subprocess.run(['ip', 'link', 'show'], capture_output=True, text=True)
                interfaces = re.findall(r'\d+:\s+(\w+):', result.stdout)
                return interfaces if interfaces else ['any']
        except:
            return ['any', 'lo', 'eth0', 'wlan0']
    
    def quick_scan(self, target="127.0.0.1"):
        if not self.nmap_installed:
            return self._get_fallback_scan(target)
        
        try:
            result = subprocess.run(['nmap', '-F', target], capture_output=True, text=True, timeout=20)
            ports = re.findall(r'(\d+)/tcp\s+open', result.stdout)
            
            # Try to get service names
            services = {}
            for port in ports[:10]:
                try:
                    svc_result = subprocess.run(['nmap', '-sV', '-p', port, target], 
                                              capture_output=True, text=True, timeout=10)
                    match = re.search(rf'{port}/tcp\s+open\s+(\S+)', svc_result.stdout)
                    if match:
                        services[port] = match.group(1)
                except:
                    services[port] = 'unknown'
            
            open_ports = [{'port': p, 'service': services.get(p, 'unknown')} for p in ports[:10]]
            
            return {
                'target': target,
                'scan_type': 'quick',
                'timestamp': datetime.now().isoformat(),
                'open_ports': open_ports,
                'total_open': len(ports),
                'risk_level': 'HIGH' if len(ports) > 5 else 'MEDIUM' if len(ports) > 2 else 'LOW',
                'nmap_installed': True
            }
        except subprocess.TimeoutExpired:
            return self._get_fallback_scan(target, 'Timeout')
        except Exception as e:
            return self._get_fallback_scan(target, str(e))
    
    def _get_fallback_scan(self, target, error=None):
        return {
            'target': target,
            'scan_type': 'fallback',
            'timestamp': datetime.now().isoformat(),
            'open_ports': [
                {'port': '22', 'service': 'ssh (simulated)'},
                {'port': '80', 'service': 'http (simulated)'},
                {'port': '443', 'service': 'https (simulated)'}
            ],
            'total_open': 3,
            'risk_level': 'MEDIUM',
            'nmap_installed': False,
            'note': 'Nmap not installed. Using simulated data.',
            'error': error
        }
    
    def comprehensive_scan(self, target="127.0.0.1"):
        if not self.nmap_installed:
            return self._get_fallback_scan(target)
        
        try:
            result = subprocess.run(['nmap', '-sV', '-sC', '-p-', target], 
                                  capture_output=True, text=True, timeout=60)
            ports = re.findall(r'(\d+)/tcp\s+open', result.stdout)
            return {
                'target': target,
                'scan_type': 'comprehensive',
                'timestamp': datetime.now().isoformat(),
                'open_ports': [{'port': p, 'service': 'detected'} for p in ports[:20]],
                'total_open': len(ports),
                'risk_level': 'HIGH' if len(ports) > 10 else 'MEDIUM' if len(ports) > 3 else 'LOW',
                'nmap_installed': True
            }
        except:
            return self._get_fallback_scan(target)
    
    def vulnerability_scan(self, target="127.0.0.1"):
        if not self.nmap_installed:
            return self._get_fallback_scan(target)
        
        try:
            result = subprocess.run(['nmap', '--script', 'vuln', target], 
                                  capture_output=True, text=True, timeout=120)
            return {
                'target': target,
                'scan_type': 'vulnerability',
                'timestamp': datetime.now().isoformat(),
                'vulnerabilities': re.findall(r'\|_\s+([^:]+):', result.stdout),
                'nmap_installed': True
            }
        except:
            return self._get_fallback_scan(target)