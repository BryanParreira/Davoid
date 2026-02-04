#!/bin/bash

# Davoid Stylized Logo
clear
echo -e "\033[1;31m"
echo "      ██████╗  █████╗ ██╗   ██╗ ██████╗ ██╗██████╗ "
echo "      ██╔══██╗██╔══██╗██║   ██║██╔═══██╗██║██╔══██╗"
echo "      ██║  ██║███████║██║   ██║██║   ██║██║██║  ██║"
echo "      ██║  ██║██╔══██║╚██╗ ██╔╝██║   ██║██║██║  ██║"
echo "      ██████╔╝██║  ██║ ╚████╔╝ ╚██████╔╝██║██████╔╝"
echo "      ╚═════╝ ╚═╝  ╚═╝  ╚═══╝   ╚═════╝ ╚═╝╚═════╝ "
echo "             [ D A V O I D : I N S T A L L E R ]"
echo -e "\033[0m"

# 1. Configuration
INSTALL_DIR="/opt/davoid"
REPO_URL="https://github.com/BryanParreira/Davoid.git"
BINARY_PATH="/usr/local/bin/davoid"

# Detect OS and set correct ownership group
if [[ "$OSTYPE" == "darwin"* ]]; then
    OWNER_GROUP="staff"
    OS_TYPE="mac"
    echo -e "\033[1;34m[*] Detected macOS Environment...\033[0m"
else
    OWNER_GROUP=$(id -gn)
    OS_TYPE="linux"
    echo -e "\033[1;34m[*] Detected Linux Environment...\033[0m"
fi

echo -e "\033[1;34m[*] Requesting sudo for system directory setup...\033[0m"

# 2. Setup Directory with proper permissions
sudo mkdir -p $INSTALL_DIR
sudo chown $USER:$OWNER_GROUP $INSTALL_DIR

# ------------------------------------------------------------------
# [NEW] 2.5. Install Critical Security Dependencies
# ------------------------------------------------------------------
echo -e "\033[1;34m[*] Installing operational dependencies (Nmap, Tor, WiFi Tools)...\033[0m"

if [[ "$OS_TYPE" == "linux" ]]; then
    # Debian/Ubuntu/Kali Logic
    if command -v apt-get &> /dev/null; then
        echo "    -> Updating package lists..."
        sudo apt-get update -qq
        
        echo "    -> Installing Tools via apt..."
        # Added: nmap, tcpdump, aircrack-ng, net-tools, wireless-tools, git
        sudo apt-get install -y tor macchanger python3-venv libpcap-dev \
                                nmap tcpdump aircrack-ng net-tools wireless-tools git
        
        # Ensure Tor service is started
        if ! systemctl is-active --quiet tor; then
            echo "    -> Starting Tor Service..."
            sudo systemctl enable tor
            sudo systemctl start tor
        fi
    else
        echo -e "\033[1;33m[!] Warning: 'apt-get' not found. Manually install: tor, nmap, macchanger, aircrack-ng\033[0m"
    fi

elif [[ "$OS_TYPE" == "mac" ]]; then
    # macOS Logic (Homebrew)
    if command -v brew &> /dev/null; then
        echo "    -> Installing Tools via Homebrew..."
        # Added: nmap, tcpdump, aircrack-ng, git
        brew install tor macchanger nmap tcpdump aircrack-ng git
        
        # Start Tor service on macOS
        echo "    -> Starting Tor Service..."
        brew services start tor
    else
        echo -e "\033[1;31m[!] Error: Homebrew not found. Dependencies cannot be installed automatically.\033[0m"
        echo -e "\033[1;33m[!] Please install Homebrew or manually install: tor nmap aircrack-ng\033[0m"
    fi
fi
# ------------------------------------------------------------------


# 3. Clone or Update Repository
echo -e "\033[1;34m[*] Syncing Davoid source code...\033[0m"
if [ -d "$INSTALL_DIR/.git" ]; then
    cd $INSTALL_DIR
    sudo git pull origin main
    sudo chown -R $USER:$OWNER_GROUP $INSTALL_DIR
else
    sudo rm -rf $INSTALL_DIR
    sudo git clone $REPO_URL $INSTALL_DIR
    sudo chown -R $USER:$OWNER_GROUP $INSTALL_DIR
fi

# 4. Setup Virtual Environment
cd $INSTALL_DIR
echo -e "\033[1;34m[*] Building isolated Python environment...\033[0m"

python3 -m venv venv
./venv/bin/pip install --upgrade pip > /dev/null

if [ -f "requirements.txt" ]; then
    # Install dependencies with SOCKS support for Tor
    ./venv/bin/pip install -r requirements.txt
    ./venv/bin/pip install requests[socks] 
else
    ./venv/bin/pip install scapy rich requests[socks] cryptography
fi

# 5. Create the Global Launcher
echo -e "\033[1;34m[*] Creating global 'davoid' command...\033[0m"
sudo bash -c "cat << 'EOF' > $BINARY_PATH
#!/bin/bash
# Davoid Entry Point
# Auto-escalate to sudo if not already root (Required for Scapy/WiFi)
if [ \"\$EUID\" -ne 0 ]; then
  exec sudo \"\$0\" \"\$@\"
  exit
fi

# Ensure Tor is running for Stealth Mode
if ! pgrep -x \"tor\" > /dev/null; then
    echo \"[*] Starting background Tor service...\"
    service tor start 2>/dev/null || systemctl start tor 2>/dev/null || tor &
fi

# Absolute path to the venv python and main script
/opt/davoid/venv/bin/python3 /opt/davoid/main.py \"\$@\"
EOF"

sudo chmod +x $BINARY_PATH

echo -e "\033[1;32m[+] DEPLOYMENT COMPLETE: Type 'davoid' to enter the mainframe.\033[0m"