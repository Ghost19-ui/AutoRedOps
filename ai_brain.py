import openai
import os

class AIBrain:
    def __init__(self, api_key=None):
        # Tries to get key from args or environment variable
        self.api_key = api_key or os.getenv("OPENAI_API_KEY")
        if not self.api_key:
            print("[-] Warning: No OpenAI API Key found. AI features disabled.")
            self.client = None
        else:
            self.client = openai.OpenAI(api_key=self.api_key)

    def generate_executive_summary(self, scan_data, exploit_results):
        if not self.client:
            return "AI Summary Unavailable (No API Key)"

        # Construct a prompt for the LLM
        prompt = f"""
        You are a Senior Penetration Tester. Write a professional Executive Summary based on this data:
        
        Target IP: {scan_data.get('ip')}
        OS: {scan_data.get('os')}
        Open Ports: {[f"{p['port']}/{p['service']}" for p in scan_data['ports']]}
        Exploitation Status: {'Success' if exploit_results else 'Failed'}
        
        Focus on business impact and risk. Keep it under 200 words.
        """
        
        try:
            response = self.client.chat.completions.create(
                model="gpt-3.5-turbo", # Use gpt-4 for better results if available
                messages=[{"role": "user", "content": prompt}]
            )
            return response.choices[0].message.content
        except Exception as e:
            return f"Error generating summary: {e}"

    def analyze_vulnerability(self, service, port, cves):
        """
        Ask AI how to exploit a specific service if our local DB fails.
        """
        if not self.client:
            return None
            
        prompt = f"""
        I found service '{service}' on port {port} with CVEs: {cves}. 
        Suggest a specific Metasploit module path (e.g., exploit/windows/smb/ms17_010_eternalblue) 
        and a payload type. Format: Module: <path> | Payload: <path>
        """
        
        try:
            response = self.client.chat.completions.create(
                model="gpt-3.5-turbo",
                messages=[{"role": "user", "content": prompt}]
            )
            return response.choices[0].message.content
        except:
            return None