import os
from datetime import datetime

class Reporter:
    def __init__(self, config):
        self.reports_dir = config['paths']['reports']
        if not os.path.exists(self.reports_dir):
            os.makedirs(self.reports_dir)

    def generate_enhanced_report(self, target_data, exploit_results, ai_checklists):
        ip = target_data.get('ip', 'Unknown')
        timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        filename = os.path.join(self.reports_dir, f"Engagement_{ip}_{timestamp}.html")
        
        # CSS for professional look
        css = """
        body { font-family: 'Segoe UI', sans-serif; background: #1e1e1e; color: #d4d4d4; margin: 40px; }
        h1 { color: #569cd6; border-bottom: 1px solid #333; padding-bottom: 10px; }
        .card { background: #252526; padding: 15px; margin-bottom: 20px; border-radius: 5px; border-left: 5px solid #007acc; }
        .success { border-left-color: #4ec9b0; }
        .fail { border-left-color: #f44747; }
        code { background: #111; padding: 2px 5px; color: #ce9178; }
        """

        html = f"<html><head><style>{css}</style></head><body>"
        html += f"<h1>🚀 AutoRedOps Engagement Report: {ip}</h1>"
        html += f"<p>Generated: {timestamp}</p>"

        # Section 1: Scan Results
        html += "<h2>🔎 Reconnaissance Data</h2>"
        for p in target_data['ports']:
            checklist = ai_checklists.get(p['port'], ["No data"])
            checklist_html = "".join([f"<li><code>{item.strip()}</code></li>" for item in checklist])
            
            html += f"""
            <div class='card'>
                <h3>Port {p['port']} - {p['service']}</h3>
                <p><strong>Product:</strong> {p['product']}</p>
                <p><strong>CVEs Detected:</strong> {', '.join(p['cves']) if p['cves'] else 'None detected'}</p>
                <hr style='border: 0; border-top: 1px solid #333;'>
                <p><strong>🤖 AI Manual Checklist:</strong></p>
                <ul>{checklist_html}</ul>
            </div>
            """

        # Section 2: Exploitation
        html += "<h2>⚔️ Exploitation Log</h2>"
        if exploit_results:
            status_class = "success" if exploit_results['success'] else "fail"
            html += f"""
            <div class='card {status_class}'>
                <h3>Module: {exploit_results.get('module', 'Unknown')}</h3>
                <p><strong>Result:</strong> {'Success' if exploit_results['success'] else 'Failed'}</p>
                <p><strong>Session ID:</strong> {exploit_results.get('session_id', 'N/A')}</p>
            </div>
            """
        else:
            html += "<p>No automated exploitation attempts recorded.</p>"

        html += "</body></html>"
        
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(html)
        print(f"[+] Professional Report generated: {filename}")