import openai
import os

class AIBrain:
    def __init__(self, api_key=None):
        self.api_key = api_key or os.getenv("OPENAI_API_KEY")
        self.client = None
        if self.api_key:
            self.client = openai.OpenAI(api_key=self.api_key)

    def generate_manual_checklist(self, service, port):
        """
        Generates a concise, technical checklist for manual verification.
        """
        if not self.client: return ["AI Unavailable"]

        prompt = f"""
        Act as a Senior Pentester. 
        I found service '{service}' on Port {port}.
        List 3 specific manual commands or tools I should run to enumerate this service.
        Format as a Python list of strings. Do not explain, just list the commands.
        Example: ["nikto -h <ip>", "curl -I <ip>", "dirb http://<ip>"]
        """
        
        try:
            response = self.client.chat.completions.create(
                model="gpt-3.5-turbo",
                messages=[{"role": "user", "content": prompt}],
                temperature=0.3
            )
            # Simple cleaning of response to ensure it looks like a list
            content = response.choices[0].message.content.strip()
            return content.replace('[','').replace(']','').replace('"','').split(',')
        except:
            return ["Error retrieving checklist"]

    def generate_executive_summary(self, scan_data, exploit_results):
        if not self.client: return "Summary Unavailable"
        
        status = "Compromised" if exploit_results and exploit_results['success'] else "Secure (Automated checks failed)"
        
        prompt = f"""
        Write a professional Pentest Executive Summary.
        Target IP: {scan_data['ip']}
        Status: {status}
        Open Ports: {len(scan_data['ports'])}
        
        Write 3 sentences: 1 on findings, 1 on risk, 1 on recommendation.
        """
        try:
            response = self.client.chat.completions.create(
                model="gpt-3.5-turbo",
                messages=[{"role": "user", "content": prompt}]
            )
            return response.choices[0].message.content
        except:
            return "Summary Error"