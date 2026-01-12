#!/bin/bash

# Davoid Stylized Logo - EXACTLY AS YOU DESIGNED IT
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
# Get the actual user who is running this script (even if via sudo)
REAL_USER=${SUDO_USER:-$USER}

echo -e "\033[1;34m[*] Requesting system access for setup...\033[0m"

# 2. Setup Directory with absolute clean slate if needed
if [ -d "$INSTALL_DIR" ] && [ ! -d "$INSTALL_DIR/.git" ]; then
    echo -e "\033[1;33m[!] Found non-git directory at $INSTALL_DIR. Cleaning up...\033[0m"
    sudo rm -rf $INSTALL_DIR
fi

sudo mkdir -p $INSTALL_DIR
sudo chown $REAL_USER:$REAL_USER $INSTALL_DIR

# 3. Clone or Update Repository
echo -e "\033[1;34m[*] Syncing Davoid source code...\033[0m"
if [ -d "$INSTALL_DIR/.git" ]; then
    cd $INSTALL_DIR
    # Reset any local changes to avoid merge conflicts during install
    git reset --hard HEAD > /dev/null 2>&1
    git pull origin main
else
    git clone $REPO_URL $INSTALL_DIR
    sudo chown -R $REAL_USER:$REAL_USER $INSTALL_DIR
fi

# 4. Setup Virtual Environment (The "Production" way)
cd $INSTALL_DIR
echo -e "\033[1;34m[*] Building isolated Python environment...\033[0m"

# Ensure python3-venv is available (common failure point on Ubuntu/Kali)
if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    sudo apt-get update -qq && sudo apt-get install -y python3-venv -qq > /dev/null 2>&1
fi

python3 -m venv venv
./venv/bin/pip install --upgrade pip > /dev/null 2>&1

if [ -f "requirements.txt" ]; then
    ./venv/bin/pip install -r requirements.txt
else
    # Fallback to current required power-tools
    ./venv/bin/pip install scapy rich requests cryptography
fi

# 5. Create the Global Launcher
# We use sudo here to write to /usr/local/bin
echo -e "\033[1;34m[*] Linking global 'davoid' command...\033[0m"
sudo bash -c "cat <<EOF > $BINARY_PATH
#!/bin/bash
# Check if running as root (needed for Scapy/Network tools)
if [ \"\$EUID\" -ne 0 ]; then
  exec sudo \"\$0\" \"\$@\"
  exit
fi
# Execute the app using the isolated environment
$INSTALL_DIR/venv/bin/python3 $INSTALL_DIR/main.py \"\$@\"
EOF"

sudo chmod +x $BINARY_PATH

echo -e "\033[1;32m[+] DEPLOYMENT COMPLETE: Type 'davoid' from any folder to enter the mainframe.\033[0m"