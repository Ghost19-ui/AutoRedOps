import nmap
import os
import yaml

class NmapScanner:
    def __init__(self, config_path='config.yaml'):
        with open(config_path, 'r') as f:
            self.config = yaml.safe_load(f)
        
        # Point to the Nmap executable from config
        self.nm = nmap.PortScanner(nmap_search_path=(self.config['nmap']['path'],))
        self.scans_dir = self.config['paths']['scans']
        
        if not os.path.exists(self.scans_dir):
            os.makedirs(self.scans_dir)

    def discover_hosts(self):
        subnet = self.config['default_subnet']
        print(f"[*] Discovering hosts on {subnet}...")
        self.nm.scan(hosts=subnet, arguments='-sn', sudo=True)
        return [host for host in self.nm.all_hosts() if self.nm[host].state() == 'up']

    def scan_target(self, target_ip):
        print(f"[*] Starting full scan on {target_ip}...")
        # Using -sS (Stealth), -sV (Versions), -O (OS), and vuln scripts
        args = "-sS -sV -O --script vuln"
        self.nm.scan(hosts=target_ip, arguments=args, sudo=True)
        
        # Save XML for record
        output_file = os.path.join(self.scans_dir, f"{target_ip}_full.xml")
        with open(output_file, 'w') as f:
            f.write(self.nm.get_nmap_last_output())
            
        return self.parse_results(target_ip)

    def parse_results(self, target_ip):
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