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

# Ensure script is run as root for initial installation
if [ "$EUID" -ne 0 ]; then
  echo -e "\033[1;31m[-] Please run the installer with sudo: sudo bash install.sh\033[0m"
  exit 1
fi

# 1. Configuration
INSTALL_DIR="/opt/davoid"
REPO_URL="https://github.com/BryanParreira/Davoid.git"
BINARY_PATH="/usr/local/bin/davoid"

# Detect OS and assign correct root group
if [[ "$OSTYPE" == "darwin"* ]]; then
    OS_TYPE="mac"
    ROOT_GROUP="wheel"
    echo -e "\033[1;34m[*] Detected macOS Environment...\033[0m"
else
    OS_TYPE="linux"
    ROOT_GROUP="root"
    echo -e "\033[1;34m[*] Detected Linux Environment...\033[0m"
fi

# 2. Setup Directory
mkdir -p $INSTALL_DIR

# ------------------------------------------------------------------
# 2.5. Install Critical Security Dependencies
# ------------------------------------------------------------------
echo -e "\033[1;34m[*] Installing operational dependencies (Nmap, Tor, WiFi Tools, libcap2-bin)...\033[0m"

if [[ "$OS_TYPE" == "linux" ]]; then
    # Debian/Ubuntu/Kali Logic
    if command -v apt-get &> /dev/null; then
        echo "    -> Updating package lists..."
        apt-get update -qq < /dev/null
        
        echo "    -> Installing Tools via apt..."
        apt-get install -y tor macchanger python3-venv libpcap-dev libcap2-bin \
                                nmap tcpdump aircrack-ng net-tools wireless-tools git < /dev/null
        
        if ! systemctl is-active --quiet tor; then
            echo "    -> Starting Tor Service..."
            systemctl enable tor < /dev/null
            systemctl start tor < /dev/null
        fi
    else
        echo -e "\033[1;33m[!] Warning: 'apt-get' not found. Manually install: tor, nmap, macchanger, aircrack-ng, libcap2-bin\033[0m"
    fi

elif [[ "$OS_TYPE" == "mac" ]]; then
    # macOS Logic (Homebrew)
    
    # Determine the correct brew path for Apple Silicon vs Intel
    if [ -x "/opt/homebrew/bin/brew" ]; then
        BREW_BIN="/opt/homebrew/bin/brew"
    elif [ -x "/usr/local/bin/brew" ]; then
        BREW_BIN="/usr/local/bin/brew"
    else
        BREW_BIN="brew"
    fi

    if sudo -u $SUDO_USER command -v $BREW_BIN &> /dev/null; then
        echo "    -> Installing Tools via Homebrew..."
        # Drop root privileges just for Homebrew to prevent the fatal error
        sudo -u $SUDO_USER $BREW_BIN install tor macchanger nmap tcpdump aircrack-ng git exploitdb < /dev/null
        
        echo "    -> Starting Tor Service..."
        sudo -u $SUDO_USER $BREW_BIN services start tor < /dev/null
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
    git fetch --all < /dev/null
    git reset --hard origin/main < /dev/null
    git pull origin main < /dev/null
else
    rm -rf $INSTALL_DIR
    git clone $REPO_URL $INSTALL_DIR < /dev/null
fi

# 4. Setup Virtual Environment
cd $INSTALL_DIR
echo -e "\033[1;34m[*] Building isolated Python environment...\033[0m"

# FIX: macOS Python 3.14 `ensurepip` bug workaround
if ! python3 -m venv venv; then
    echo -e "\033[1;33m[*] Standard venv creation failed. Attempting fallback method...\033[0m"
    python3 -m venv --without-pip venv
    curl -sS https://bootstrap.pypa.io/get-pip.py | ./venv/bin/python
fi

./venv/bin/pip install --upgrade pip > /dev/null

echo -e "\033[1;34m[*] Installing Next-Gen Framework Dependencies...\033[0m"
if [ -f "requirements.txt" ]; then
    if ! ./venv/bin/pip install -r requirements.txt; then
        echo -e "\033[1;31m[!] CRITICAL ERROR: Python dependencies failed to install.\033[0m"
        exit 1
    fi
    ./venv/bin/pip install requests[socks] 
else
    # Fallback installation if requirements.txt is missing
    if ! ./venv/bin/pip install scapy rich requests[socks] cryptography jinja2 questionary PyYAML; then
        echo -e "\033[1;31m[!] CRITICAL ERROR: Fallback dependencies failed to install.\033[0m"
        exit 1
    fi
fi

# 5. Lock Down Permissions and Apply Capabilities (Rootless Execution)
echo -e "\033[1;34m[*] Securing directory permissions and applying Network Capabilities...\033[0m"
# FIX: Using dynamic group (root on Linux, wheel on Mac)
chown -R root:$ROOT_GROUP $INSTALL_DIR
chmod -R 755 $INSTALL_DIR

if [[ "$OS_TYPE" == "linux" ]]; then
    setcap cap_net_raw,cap_net_admin=eip $INSTALL_DIR/venv/bin/python3
fi

# 6. Create the Global Launcher
echo -e "\033[1;34m[*] Creating global 'davoid' command...\033[0m"
bash -c "cat << 'EOF' > $BINARY_PATH
#!/bin/bash
# Davoid Entry Point

# Ensure Tor is running for Stealth Mode
if ! pgrep -x \"tor\" > /dev/null; then
    echo \"[*] Starting background Tor service...\"
    sudo service tor start 2>/dev/null || sudo systemctl start tor 2>/dev/null || tor &
fi

# Absolute path to the venv python and main script
/opt/davoid/venv/bin/python3 /opt/davoid/main.py \"\$@\"
EOF"

chmod +x $BINARY_PATH

echo ""
echo -e "\033[1;32m[+] ========================================================\033[0m"
echo -e "\033[1;32m[+] DEPLOYMENT COMPLETE!\033[0m"
if [[ "$OS_TYPE" == "linux" ]]; then
    echo -e "\033[1;33m[!] SECURITY NOTICE: You no longer need 'sudo' to run Davoid on Linux.\033[0m"
    echo -e "\033[1;32m[+] Type 'davoid' to enter the mainframe as a standard user.\033[0m"
else
    echo -e "\033[1;33m[!] SECURITY NOTICE: macOS requires 'sudo' for packet manipulation.\033[0m"
    echo -e "\033[1;32m[+] Type 'sudo davoid' to enter the mainframe.\033[0m"
fi
echo -e "\033[1;32m[+] ========================================================\033[0m"