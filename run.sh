#!/bin/bash

# ANSI Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}[*] AutoRedOps Launcher initialized...${NC}"

# 1. Check/Create Virtual Environment
if [ ! -d "venv" ]; then
    echo -e "${BLUE}[*] Creating Python Virtual Environment (First Run)...${NC}"
    python3 -m venv venv
fi

# 2. Quietly Install Dependencies (hides output unless error)
echo -e "${BLUE}[*] Verifying Dependencies...${NC}"
./venv/bin/pip install -r requirements.txt > /dev/null 2>&1
if [ $? -ne 0 ]; then
    echo "[-] Error installing requirements. Retrying with output..."
    ./venv/bin/pip install -r requirements.txt
fi

# 3. Launch the Tool with Sudo
# We use the python INSIDE the venv so it sees the libraries
echo -e "${GREEN}[+] Launching AutoRedOps Pro...${NC}"
sudo ./venv/bin/python3 auto_pentest.py