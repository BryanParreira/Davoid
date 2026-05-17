#!/bin/bash
set -e

# ─────────────────────────────────────────────────────────────────────────────
#  DAVOID INSTALLER
# ─────────────────────────────────────────────────────────────────────────────
clear
echo -e "\033[1;36m"
echo "      ██████╗  █████╗ ██╗   ██╗ ██████╗ ██╗██████╗ "
echo "      ██╔══██╗██╔══██╗██║   ██║██╔═══██╗██║██╔══██╗"
echo "      ██║  ██║███████║██║   ██║██║   ██║██║██║  ██║"
echo "      ██║  ██║██╔══██║╚██╗ ██╔╝██║   ██║██║██║  ██║"
echo "      ██████╔╝██║  ██║ ╚████╔╝ ╚██████╔╝██║██████╔╝"
echo "      ╚═════╝ ╚═╝  ╚═╝  ╚═══╝   ╚═════╝ ╚═╝╚═════╝ "
echo "             [ D A V O I D  v2.0.0  I N S T A L L E R ]"
echo -e "\033[0m"

if [ "$EUID" -ne 0 ]; then
  echo -e "\033[1;31m[-] Run as root: sudo bash install.sh\033[0m"
  exit 1
fi

# ─── Config ───────────────────────────────────────────────────────────────────
INSTALL_DIR="/opt/davoid"
REPO_URL="https://github.com/BryanParreira/Davoid.git"
BINARY_PATH="/usr/local/bin/davoid"
GO_MIN_VERSION="1.21"

if [[ "$OSTYPE" == "darwin"* ]]; then
    OS_TYPE="mac"
    ROOT_GROUP="wheel"
    echo -e "\033[1;34m[*] macOS detected\033[0m"
else
    OS_TYPE="linux"
    ROOT_GROUP="root"
    echo -e "\033[1;34m[*] Linux detected\033[0m"
fi

# ─── System dependencies ──────────────────────────────────────────────────────
echo -e "\033[1;34m[*] Installing system dependencies...\033[0m"

if [[ "$OS_TYPE" == "linux" ]]; then
    if command -v apt-get &>/dev/null; then
        apt-get update -qq </dev/null
        apt-get install -y tor macchanger python3-venv libpcap-dev libcap2-bin \
            nmap tcpdump aircrack-ng net-tools wireless-tools git curl wget </dev/null
        systemctl enable tor 2>/dev/null; systemctl start tor 2>/dev/null || true
    fi

elif [[ "$OS_TYPE" == "mac" ]]; then
    if [ -x "/opt/homebrew/bin/brew" ]; then BREW_BIN="/opt/homebrew/bin/brew"
    elif [ -x "/usr/local/bin/brew" ]; then BREW_BIN="/usr/local/bin/brew"
    else BREW_BIN="brew"; fi

    if sudo -u "$SUDO_USER" command -v "$BREW_BIN" &>/dev/null; then
        sudo -u "$SUDO_USER" "$BREW_BIN" install tor nmap git go 2>/dev/null || true
        sudo -u "$SUDO_USER" "$BREW_BIN" services start tor 2>/dev/null || true
    fi
fi

# ─── Go installation ──────────────────────────────────────────────────────────
echo -e "\033[1;34m[*] Checking Go installation...\033[0m"

GO_BIN=""
for candidate in /usr/local/go/bin/go /opt/homebrew/bin/go /usr/local/bin/go $(command -v go 2>/dev/null); do
    if [ -x "$candidate" ]; then
        GO_BIN="$candidate"
        break
    fi
done

if [ -z "$GO_BIN" ]; then
    echo "    -> Go not found — installing Go 1.24..."
    if [[ "$OS_TYPE" == "linux" ]]; then
        GO_ARCHIVE="go1.24.0.linux-amd64.tar.gz"
        curl -sLO "https://go.dev/dl/${GO_ARCHIVE}"
        rm -rf /usr/local/go
        tar -C /usr/local -xzf "${GO_ARCHIVE}"
        rm "${GO_ARCHIVE}"
        GO_BIN="/usr/local/go/bin/go"
        echo 'export PATH=$PATH:/usr/local/go/bin' >> /etc/profile.d/go.sh
    elif [[ "$OS_TYPE" == "mac" ]]; then
        echo -e "\033[1;31m[!] Go not found. Install it with: brew install go\033[0m"
        exit 1
    fi
fi
echo "    -> Go: $($GO_BIN version)"

# ─── Clone / update repository ───────────────────────────────────────────────
echo -e "\033[1;34m[*] Syncing Davoid source to ${INSTALL_DIR}...\033[0m"
mkdir -p "$INSTALL_DIR"
chown -R "$SUDO_USER:$ROOT_GROUP" "$INSTALL_DIR"
cd "$INSTALL_DIR"

if [ -d ".git" ]; then
    sudo -u "$SUDO_USER" git fetch --all </dev/null
    sudo -u "$SUDO_USER" git reset --hard origin/main </dev/null
    sudo -u "$SUDO_USER" git pull origin main </dev/null
else
    rm -rf ./* ./.git
    sudo -u "$SUDO_USER" git clone "$REPO_URL" . </dev/null
fi

# ─── Python virtual environment ───────────────────────────────────────────────
echo -e "\033[1;34m[*] Building Python environment (for security modules)...\033[0m"

PYTHON_EXE=""
if [[ "$OS_TYPE" == "mac" ]]; then
    for candidate in /usr/bin/python3 /usr/bin/python3.12 /usr/bin/python3.11 /usr/bin/python3.10; do
        if [ -x "$candidate" ]; then PYTHON_EXE="$candidate"; break; fi
    done
else
    PYTHON_EXE="python3"
fi

if [ -z "$PYTHON_EXE" ]; then
    echo -e "\033[1;31m[!] Python 3 not found. Install Python 3.9–3.12.\033[0m"
    exit 1
fi
echo "    -> Python: $PYTHON_EXE"

rm -rf "$INSTALL_DIR/venv"
sudo -u "$SUDO_USER" "$PYTHON_EXE" -m venv --without-pip venv

echo "    -> Installing pip..."
curl -sS https://bootstrap.pypa.io/get-pip.py -o /tmp/get-pip.py
sudo -u "$SUDO_USER" "$INSTALL_DIR/venv/bin/python3" /tmp/get-pip.py
rm -f /tmp/get-pip.py
sudo -u "$SUDO_USER" "$INSTALL_DIR/venv/bin/pip" install --upgrade pip -q

echo "    -> Installing Python dependencies..."
if [ -f "requirements.txt" ]; then
    sudo -u "$SUDO_USER" "$INSTALL_DIR/venv/bin/pip" install -r requirements.txt -q
else
    sudo -u "$SUDO_USER" "$INSTALL_DIR/venv/bin/pip" install -q \
        scapy rich requests[socks] cryptography jinja2 questionary PyYAML
fi

# ─── Network capabilities (Linux rootless) ────────────────────────────────────
if [[ "$OS_TYPE" == "linux" ]]; then
    echo -e "\033[1;34m[*] Applying network capabilities for rootless packet capture...\033[0m"
    setcap cap_net_raw,cap_net_admin=eip "$INSTALL_DIR/venv/bin/python3" 2>/dev/null || true
fi

# ─── Build Go binary ──────────────────────────────────────────────────────────
echo -e "\033[1;34m[*] Building Davoid Go binary...\033[0m"
cd "$INSTALL_DIR"
export HOME="/root"
"$GO_BIN" build -ldflags "-s -w" -o "$BINARY_PATH" ./cmd/davoid/
chmod +x "$BINARY_PATH"
echo "    -> Binary installed: $BINARY_PATH"

# ─── Lock down permissions ────────────────────────────────────────────────────
chown -R root:"$ROOT_GROUP" "$INSTALL_DIR"
chmod -R 755 "$INSTALL_DIR"

# ─────────────────────────────────────────────────────────────────────────────
echo ""
echo -e "\033[1;32m[+] ══════════════════════════════════════════════════\033[0m"
echo -e "\033[1;32m[+]  DAVOID v2.0.0 INSTALLED SUCCESSFULLY\033[0m"
echo -e "\033[1;32m[+] ══════════════════════════════════════════════════\033[0m"
echo ""
echo -e "\033[1;36m  davoid new \"Engagement Name\" --target 10.0.0.0/24\033[0m"
echo -e "\033[1;36m  davoid list\033[0m"
echo -e "\033[1;36m  sudo davoid          # opens the TUI\033[0m"
echo ""
if [[ "$OS_TYPE" == "linux" ]]; then
    echo -e "\033[1;33m  Note: sudo required for raw socket operations (MITM, sniff)\033[0m"
else
    echo -e "\033[1;33m  Note: macOS requires sudo for packet manipulation\033[0m"
fi
echo ""
