import openai
import os
import json

class AIBrain:
    def __init__(self, api_key=None):
        self.api_key = api_key or os.getenv("OPENAI_API_KEY")
        self.client = None
        if self.api_key:
            self.client = openai.OpenAI(api_key=self.api_key)

    def decide_best_attack(self, scan_data):
        """
        Analyzes the scan and decides the SINGLE BEST attack to run.
        Returns a JSON object with the module and configuration.
        """
        if not self.client: return None

        # Filter pertinent data to save tokens
        ports_summary = [f"{p['port']}/{p['service']} ({p['product']})" for p in scan_data['ports']]
        
        prompt = f"""
        You are an Autonomous Red Team AI. 
        Target Data: {ports_summary}
        
        DECISION TASK:
        1. Analyze the open ports.
        2. Select the ONE most likely Metasploit module to succeed (e.g., 'exploit/windows/smb/ms17_010_eternalblue').
        3. If no exploits are likely, return "action": "skip".
        
        OUTPUT FORMAT (Strict JSON):
        {{
            "reasoning": "Port 445 is open on Windows 7, high probability of EternalBlue.",
            "action": "exploit",
            "module": "exploit/windows/smb/ms17_010_eternalblue",
            "port": 445
        }}
        """
        
        try:
            response = self.client.chat.completions.create(
                model="gpt-3.5-turbo",
                messages=[{"role": "user", "content": prompt}],
                temperature=0.2 # Low temp for precise JSON
            )
            # Parse the JSON response
            content = response.choices[0].message.content.strip()
            # Clean potential markdown wrappers
            if "```json" in content:
                content = content.split("```json")[1].split("```")[0]
            
            return json.loads(content)
        except Exception as e:
            print(f"[-] AI Decision Error: {e}")
            return None

    def generate_manual_checklist(self, service, port):
        # (Keep your existing checklist logic here)
        if not self.client: return []
        prompt = f"List 3 manual commands to enumerate {service} on port {port}. Format: Just commands, comma separated."
        try:
            response = self.client.chat.completions.create(
                model="gpt-3.5-turbo",
                messages=[{"role": "user", "content": prompt}]
            )
            return response.choices[0].message.content.split(',')
        except:
            return []