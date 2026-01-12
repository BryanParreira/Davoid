#!/bin/bash

# Davoid Stylized Logo for Installation
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

# 1. Define Installation Path
INSTALL_DIR="/opt/davoid"
REPO_URL="https://github.com/BryanParreira/Davoid.git"

echo -e "\033[1;34m[*] Cloning Davoid repository to $INSTALL_DIR...\033[0m"
sudo git clone $REPO_URL $INSTALL_DIR
sudo chown -R $USER:$USER $INSTALL_DIR

# 2. Setup Virtual Environment
cd $INSTALL_DIR
echo -e "\033[1;34m[*] Building isolated Python environment...\033[0m"
python3 -m venv venv
source venv/bin/activate

# 3. Run Global Setup
echo -e "\033[1;34m[*] Configuring root-level permissions...\033[0m"
sudo ./venv/bin/python3 setup.py

echo -e "\033[1;32m[+] DEPLOYMENT COMPLETE: Type 'davoid' to enter the mainframe.\033[0m"