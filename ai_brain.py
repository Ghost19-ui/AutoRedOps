import openai
import os
import json

# --- INDUSTRY UPGRADE: RAG SIMULATION ---
# In a full production version, this would query a Vector Database (ChromaDB)
# populated with the content from:
# 1. https://github.com/HackTricks-wiki/hacktricks
# 2. https://github.com/swisskyrepo/PayloadsAllTheThings

class KnowledgeBase:
    """
    Simulates a RAG retrieval system.
    """
    def retrieve_context(self, keyword):
        # MOCK DATABASE LOOKUP
        # In reality, you would use: collection.query(query_texts=[keyword])
        knowledge_map = {
            "ftp": "HackTricks Suggestion: Check for anonymous login. Check vsftpd versions for backdoors.",
            "http": "HackTricks Suggestion: Run Nikto. Check robots.txt. Look for SQLi in parameters. Common tool: sqlmap.",
            "smb": "HackTricks Suggestion: Check for EternalBlue (MS17-010) or Null Session enumeration using enum4linux."
        }
        return knowledge_map.get(keyword.lower(), "Standard Enumeration")

class AIBrain:
    def __init__(self, api_key=None):
        self.api_key = api_key or os.getenv("OPENAI_API_KEY")
        if not self.api_key:
            print("[-] Warning: No OpenAI API Key found. AI features disabled.")
            self.client = None
        else:
            self.client = openai.OpenAI(api_key=self.api_key)
            
        self.rag = KnowledgeBase()

    def analyze_vulnerability(self, service, port, cves):
        if not self.client:
            return None
        
        # 1. Retrieve Expert Knowledge (RAG Step)
        context = self.rag.retrieve_context(service)
        
        # 2. Prompt Engineering (The "Agent" Persona)
        system_prompt = """
        You are an elite Red Team Operator and Exploit Researcher. 
        You have deep knowledge of 'PayloadsAllTheThings' and 'HackTricks'.
        Your goal is to suggest high-probability attack vectors.
        Be concise, technical, and focus on Metasploit modules or specific manual commands.
        """
        
        user_prompt = f"""
        Target Service: {service} (Port {port})
        Detected CVEs: {cves}
        Contextual Knowledge: {context}
        
        Task: Suggest the exact Metasploit module path (e.g., exploit/...) OR a specific manual command.
        """
        
        try:
            response = self.client.chat.completions.create(
                model="gpt-3.5-turbo",
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt}
                ],
                temperature=0.3 # Low temperature for more factual/technical answers
            )
            return response.choices[0].message.content
        except Exception as e:
            return None

    def generate_executive_summary(self, scan_data, exploit_results):
        if not self.client:
            return "AI Summary Unavailable."

        prompt = f"""
        Generate a Pentest Executive Summary.
        Target: {scan_data.get('ip')}
        Open Ports: {[p['port'] for p in scan_data.get('ports', [])]}
        Exploitation Result: {exploit_results}
        
        Format:
        1. Executive Summary (Business Risk)
        2. Technical Findings
        3. Remediation (Short)
        """
        
        try:
            response = self.client.chat.completions.create(
                model="gpt-3.5-turbo",
                messages=[{"role": "user", "content": prompt}]
            )
            return response.choices[0].message.content
        except:
            return "Error generating report."