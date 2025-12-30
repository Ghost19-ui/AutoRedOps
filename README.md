# 💀 AutoRedOps Pro: AI-Powered Red Team Orchestrator

**AutoRedOps** is an automated red-teaming framework that combines **Nmap** (reconnaissance), **Metasploit** (exploitation), and **OpenAI** (analysis) into a single "Mission Control" dashboard.

> **⚠️ DISCLAIMER:** This tool is for **educational purposes and authorized virtual labs only**. Do not use against systems you do not own.

## 🚀 Key Features
- **🤖 AI Attack Analysis:** Uses OpenAI (GPT) to analyze open ports and generate executive risk reports.
- **⚔️ Automated Exploitation:** Connects to Metasploit RPC to launch attacks on discovered vulnerabilities (e.g., vsftpd, EternalBlue).
- **🛡️ Smart Recon:** Automates Nmap scanning with vulnerability scripts (`--script vuln`).
- **📊 Web Dashboard:** A modern Streamlit UI to manage operations without using the CLI.

## 🛠️ Installation

### Prerequisites
1. **Python 3.10+**
2. **Nmap** (Must be in your system PATH)
3. **Metasploit Framework** (specifically `msfrpcd`)

### Setup
```bash
# 1. Clone the repository
git clone [https://github.com/Ghost19-ui/AutoRedOps.git](https://github.com/Ghost19-ui/AutoRedOps.git)
cd AutoRedOps

# 2. Install dependencies
pip install -r requirements.txt

# 3. Configure the tool
cp config.example.yaml config.yaml
# Edit config.yaml with your API keys and paths