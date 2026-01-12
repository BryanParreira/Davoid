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

echo -e "\033[1;34m[*] Requesting root access for installation...\033[0m"

# 2. Setup Directory with proper permissions
sudo mkdir -p $INSTALL_DIR
sudo chown $USER "$INSTALL_DIR"

# 3. Clone Repository
echo -e "\033[1;34m[*] Cloning Davoid repository...\033[0m"
if [ -d "$INSTALL_DIR/.git" ]; then
    cd $INSTALL_DIR && git pull
else
    sudo rm -rf $INSTALL_DIR
    sudo git clone $REPO_URL $INSTALL_DIR
    sudo chown -R $USER "$INSTALL_DIR"
fi

# 4. Setup Virtual Environment
cd $INSTALL_DIR
echo -e "\033[1;34m[*] Building isolated Python environment...\033[0m"
python3 -m venv venv
./venv/bin/pip install --upgrade pip
if [ -f "requirements.txt" ]; then
    ./venv/bin/pip install -r requirements.txt
else
    # Safety fallback
    ./venv/bin/pip install scapy rich requests
fi

# 5. Create the Global Launcher (Works on Mac & Linux)
echo -e "\033[1;34m[*] Creating global 'davoid' command...\033[0m"
sudo bash -c "cat <<EOF > $BINARY_PATH
#!/bin/bash
sudo $INSTALL_DIR/venv/bin/python3 $INSTALL_DIR/main.py \"\$@\"
EOF"

sudo chmod +x $BINARY_PATH

echo -e "\033[1;32m[+] DEPLOYMENT COMPLETE: Type 'davoid' to enter the mainframe.\033[0m"