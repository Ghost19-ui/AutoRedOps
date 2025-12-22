import os
from datetime import datetime

class Reporter:
    def __init__(self, config):
        self.reports_dir = config['paths']['reports']
        if not os.path.exists(self.reports_dir):
            os.makedirs(self.reports_dir)

    def generate_report(self, target_data, exploit_results):
        ip = target_data.get('ip', 'Unknown')
        timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        filename = os.path.join(self.reports_dir, f"report_{ip}_{timestamp}.html")
        
        html = f"<html><body><h1>Report for {ip}</h1><h2>Scan Results</h2><ul>"
        for p in target_data['ports']:
            html += f"<li>Port {p['port']}: {p['service']} {p['product']} (CVEs: {p['cves']})</li>"
        html += "</ul><h2>Exploitation</h2>"
        
        if exploit_results:
            html += f"<p>Status: {'Success' if exploit_results['success'] else 'Failed'}</p>"
        else:
            html += "<p>No exploitation attempted.</p>"
            
        html += "</body></html>"
        
        with open(filename, 'w') as f:
            f.write(html)
        print(f"[+] Report generated: {filename}")