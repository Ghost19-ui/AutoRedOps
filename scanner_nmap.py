import nmap
import os
import yaml
import socket
import fcntl
import struct

class NmapScanner:
    def __init__(self, config_path='config.yaml'):
        with open(config_path, 'r') as f:
            self.config = yaml.safe_load(f)
        
        # Point to the Nmap executable from config
        self.nm = nmap.PortScanner(nmap_search_path=(self.config['nmap']['path'],))
        self.scans_dir = self.config['paths']['scans']
        
        if not os.path.exists(self.scans_dir):
            os.makedirs(self.scans_dir)

    def get_local_subnet(self):
        """Auto-detects the local IP and calculates the /24 subnet."""
        try:
            # Connect to an external IP (doesn't send data) to find our route
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
            
            # Assume /24 subnet (standard for home/labs)
            subnet = ".".join(local_ip.split('.')[:3]) + ".0/24"
            return subnet
        except Exception:
            return self.config['default_subnet'] # Fallback to config

    def discover_hosts(self):
        """Scans the detected subnet for live hosts."""
        subnet = self.get_local_subnet()
        print(f"[*] Auto-Detected Network: {subnet}")
        print(f"[*] Scanning for live hosts... (Please wait)")
        
        try:
            self.nm.scan(hosts=subnet, arguments='-sn', sudo=True)
            hosts = [host for host in self.nm.all_hosts() if self.nm[host].state() == 'up']
            return hosts
        except Exception as e:
            print(f"[-] Discovery failed: {e}")
            return []

    def scan_target(self, target_ip):
        print(f"[*] Starting full scan on {target_ip}...")
        args = "-sS -sV -O --script vuln"
        try:
            self.nm.scan(hosts=target_ip, arguments=args, sudo=True)
            
            # --- FIX: Handle Bytes vs String for File Writing ---
            output_file = os.path.join(self.scans_dir, f"{target_ip}_full.xml")
            raw_data = self.nm.get_nmap_last_output()
            
            if isinstance(raw_data, bytes):
                with open(output_file, 'wb') as f:
                    f.write(raw_data)
            else:
                with open(output_file, 'w') as f:
                    f.write(raw_data)
                    
            return self.parse_results(target_ip)
        except Exception as e:
            print(f"[-] Scan failed: {e}")
            return {'ip': target_ip, 'ports': []}

    def parse_results(self, target_ip):
        if target_ip not in self.nm.all_hosts():
            return {'ip': target_ip, 'ports': []}

        host_data = self.nm[target_ip]
        parsed = {'ip': target_ip, 'os': 'Unknown', 'ports': []}
        
        if 'osmatch' in host_data and host_data['osmatch']:
            parsed['os'] = host_data['osmatch'][0]['name']

        if 'tcp' in host_data:
            for port, info in host_data['tcp'].items():
                cves = []
                if 'script' in info:
                    for output in info['script'].values():
                        if "CVE-" in output:
                            import re
                            cves.extend(re.findall(r'CVE-\d{4}-\d{4,}', output))
                            
                parsed['ports'].append({
                    'port': port,
                    'service': info.get('name', 'unknown'),
                    'product': info.get('product', ''),
                    'version': info.get('version', ''),
                    'cves': cves
                })
        return parsed