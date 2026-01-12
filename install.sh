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
echo -e "\033[1;37m[*] Initializing Global System Deployment...\033[0m"

# Setup Directory
INSTALL_DIR="/opt/davoid"
sudo mkdir -p $INSTALL_DIR
sudo chown $USER:$USER $INSTALL_DIR

# Python Environment
echo -e "\033[1;34m[*] Building isolated Python environment...\033[0m"
python3 -m venv $INSTALL_DIR/venv
source $INSTALL_DIR/venv/bin/activate

# Install Dependencies and Run Setup
echo -e "\033[1;34m[*] Configuring root-level permissions...\033[0m"
sudo python3 setup.py

echo -e "\033[1;32m[+] DEPLOYMENT COMPLETE: Type 'davoid' to enter the mainframe.\033[0m"