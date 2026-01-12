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
# macOS uses 'staff', Linux usually uses the username as the group
if [[ "$OSTYPE" == "darwin"* ]]; then
    OWNER_GROUP="staff"
    echo -e "\033[1;34m[*] Detected macOS Environment...\033[0m"
else
    OWNER_GROUP=$(id -gn)
    echo -e "\033[1;34m[*] Detected Linux Environment...\033[0m"
fi

echo -e "\033[1;34m[*] Requesting sudo for system directory setup...\033[0m"

# 2. Setup Directory with proper permissions
# We create it as root, then hand ownership to the current user
sudo mkdir -p $INSTALL_DIR
sudo chown $USER:$OWNER_GROUP $INSTALL_DIR

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

# Check if venv module exists (Linux specific common issue)
if ! python3 -m venv --help > /dev/null 2>&1; then
    echo -e "\033[1;33m[!] Python venv module missing. Attempting to install...\033[0m"
    sudo apt-get update && sudo apt-get install -y python3-venv
fi

# Create venv and install dependencies
python3 -m venv venv
./venv/bin/pip install --upgrade pip > /dev/null

if [ -f "requirements.txt" ]; then
    ./venv/bin/pip install -r requirements.txt
else
    ./venv/bin/pip install scapy rich requests cryptography
fi

# 5. Create the Global Launcher
echo -e "\033[1;34m[*] Creating global 'davoid' command...\033[0m"
# The 'cat' heredoc uses quotes around EOF to prevent shell variable expansion
sudo bash -c "cat << 'EOF' > $BINARY_PATH
#!/bin/bash
# Davoid Entry Point
# Auto-escalate to sudo if not already root (Required for Scapy)
if [ \"\$EUID\" -ne 0 ]; then
  exec sudo \"\$0\" \"\$@\"
  exit
fi

# Absolute path to the venv python and main script
/opt/davoid/venv/bin/python3 /opt/davoid/main.py \"\$@\"
EOF"

sudo chmod +x $BINARY_PATH

echo -e "\033[1;32m[+] DEPLOYMENT COMPLETE: Type 'davoid' to enter the mainframe.\033[0m"