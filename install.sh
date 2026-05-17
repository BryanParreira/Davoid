#!/bin/bash
set -e

# ─────────────────────────────────────────────────────────────────────────────
#  Davoid Installer — builds from source, installs single binary
#  Usage: sudo bash install.sh
# ─────────────────────────────────────────────────────────────────────────────

RED='\033[1;31m'
GREEN='\033[1;32m'
CYAN='\033[1;36m'
YELLOW='\033[1;33m'
RESET='\033[0m'

banner() {
echo -e "${CYAN}"
echo "      ██████╗  █████╗ ██╗   ██╗ ██████╗ ██╗██████╗"
echo "      ██╔══██╗██╔══██╗██║   ██║██╔═══██╗██║██╔══██╗"
echo "      ██║  ██║███████║██║   ██║██║   ██║██║██║  ██║"
echo "      ██║  ██║██╔══██║╚██╗ ██╔╝██║   ██║██║██║  ██║"
echo "      ██████╔╝██║  ██║ ╚████╔╝ ╚██████╔╝██║██████╔╝"
echo "      ╚═════╝ ╚═╝  ╚═╝  ╚═══╝   ╚═════╝ ╚═╝╚═════╝"
echo -e "             [ D A V O I D  v2.0.0  I N S T A L L E R ]${RESET}"
echo
}

info()  { echo -e "${CYAN}[*]${RESET} $*"; }
ok()    { echo -e "${GREEN}[+]${RESET} $*"; }
warn()  { echo -e "${YELLOW}[!]${RESET} $*"; }
die()   { echo -e "${RED}[-]${RESET} $*"; exit 1; }

# ─── Detect OS & architecture ─────────────────────────────────────────────────
OS="$(uname -s)"
ARCH="$(uname -m)"

case "$OS" in
    Linux)  OS_TYPE="linux"  ;;
    Darwin) OS_TYPE="darwin" ;;
    *)      die "Unsupported OS: $OS" ;;
esac

case "$ARCH" in
    x86_64)          GO_ARCH="amd64" ;;
    aarch64|arm64)   GO_ARCH="arm64" ;;
    *)               die "Unsupported architecture: $ARCH" ;;
esac

clear
banner
info "Detected: ${OS_TYPE}/${GO_ARCH}"
echo

# ─── Determine install path ───────────────────────────────────────────────────
# Prefer Homebrew bin on macOS, fallback to /usr/local/bin
BINARY_PATH="/usr/local/bin/davoid"
if [ "$OS_TYPE" = "darwin" ] && [ -d "/opt/homebrew/bin" ]; then
    BINARY_PATH="/opt/homebrew/bin/davoid"
fi

# Determine the actual user (handles both sudo and direct root)
ACTUAL_USER="${SUDO_USER:-$(whoami)}"
if [ "$ACTUAL_USER" = "root" ]; then
    ACTUAL_USER="root"
fi

# ─── Check privileges ─────────────────────────────────────────────────────────
# On Linux we need root for /usr/local/bin and capabilities
# On macOS with Homebrew, root is not required
if [ "$OS_TYPE" = "linux" ] && [ "$EUID" -ne 0 ]; then
    die "Linux install requires root. Run: sudo bash install.sh"
fi
if [ "$OS_TYPE" = "darwin" ] && [ "$BINARY_PATH" = "/usr/local/bin/davoid" ] && [ "$EUID" -ne 0 ]; then
    die "Run: sudo bash install.sh  (or install Homebrew first — no sudo needed)"
fi

INSTALL_DIR="/opt/davoid"
REPO_URL="https://github.com/BryanParreira/Davoid.git"

# ─── Optional security tools ──────────────────────────────────────────────────
info "Installing optional security tools..."
if [ "$OS_TYPE" = "linux" ]; then
    if command -v apt-get &>/dev/null; then
        apt-get update -qq </dev/null
        apt-get install -y nmap tcpdump dsniff git curl </dev/null || true
    elif command -v dnf &>/dev/null; then
        dnf install -y nmap tcpdump git curl || true
    elif command -v pacman &>/dev/null; then
        pacman -Sy --noconfirm nmap tcpdump git curl || true
    fi
elif [ "$OS_TYPE" = "darwin" ]; then
    if command -v brew &>/dev/null; then
        sudo -u "$ACTUAL_USER" brew install nmap git 2>/dev/null || true
    else
        warn "Homebrew not found. Install optional tools manually: nmap, tcpdump, dsniff"
    fi
fi

# ─── Go installation ──────────────────────────────────────────────────────────
info "Checking Go..."
GO_BIN=""
for candidate in \
    /opt/homebrew/bin/go \
    /usr/local/go/bin/go \
    /usr/bin/go \
    "$(command -v go 2>/dev/null)"; do
    if [ -x "$candidate" ]; then
        GO_BIN="$candidate"
        break
    fi
done

if [ -z "$GO_BIN" ]; then
    if [ "$OS_TYPE" = "linux" ]; then
        info "Go not found — downloading Go 1.24.0..."
        GO_ARCHIVE="go1.24.0.linux-${GO_ARCH}.tar.gz"
        declare -A GO_SHA256=(
            ["amd64"]="dea9ca38a0b852a74e81c26134671af7c0fbe65d81b0dc1c5afcf9386f0da0a7"
            ["arm64"]="c694dce20e9d8399a04b893c20e0b16561a4afa79671ed2bde1f7e9ef79200e6"
        )
        curl -sLO "https://go.dev/dl/${GO_ARCHIVE}"
        echo "${GO_SHA256[$GO_ARCH]}  ${GO_ARCHIVE}" | sha256sum -c - || \
            die "Go archive checksum FAILED — download may be tampered."
        rm -rf /usr/local/go
        tar -C /usr/local -xzf "${GO_ARCHIVE}"
        rm "${GO_ARCHIVE}"
        export PATH=$PATH:/usr/local/go/bin
        echo 'export PATH=$PATH:/usr/local/go/bin' >> /etc/profile.d/go.sh
        GO_BIN="/usr/local/go/bin/go"
    else
        die "Go not found. Install with: brew install go"
    fi
fi

GO_VERSION="$("$GO_BIN" version)"
ok "Go: ${GO_VERSION}"

# ─── Clone / update Davoid ────────────────────────────────────────────────────
info "Syncing Davoid to ${INSTALL_DIR}..."
mkdir -p "$INSTALL_DIR"
[ "$ACTUAL_USER" != "root" ] && chown "$ACTUAL_USER" "$INSTALL_DIR"
cd "$INSTALL_DIR"

if [ -d ".git" ]; then
    info "Updating existing install..."
    if [ "$ACTUAL_USER" = "root" ]; then
        git fetch --all
        git reset --hard origin/main
        git pull origin main
    else
        sudo -u "$ACTUAL_USER" git fetch --all
        sudo -u "$ACTUAL_USER" git reset --hard origin/main
        sudo -u "$ACTUAL_USER" git pull origin main
    fi
else
    info "Cloning Davoid..."
    rm -rf ./* ./.git 2>/dev/null || true
    if [ "$ACTUAL_USER" = "root" ]; then
        git clone "$REPO_URL" .
    else
        sudo -u "$ACTUAL_USER" git clone "$REPO_URL" .
    fi
fi

# ─── Build ────────────────────────────────────────────────────────────────────
info "Building Davoid binary..."
export HOME="/root"
export GOPATH="/root/go"
"$GO_BIN" build -ldflags "-s -w" -o "$BINARY_PATH" ./cmd/davoid/
chmod +x "$BINARY_PATH"

# ─── Runtime directories ──────────────────────────────────────────────────────
for dir in payloads logs reports wordlists; do
    mkdir -p "$INSTALL_DIR/$dir"
done
[ "$ACTUAL_USER" != "root" ] && chown -R "$ACTUAL_USER" "$INSTALL_DIR"

# ─── Network capabilities (Linux — enables sniff/mitm without sudo) ───────────
if [ "$OS_TYPE" = "linux" ]; then
    info "Setting network capabilities (enables packet capture without sudo)..."
    if setcap cap_net_raw,cap_net_admin=eip "$BINARY_PATH" 2>/dev/null; then
        ok "Network capabilities set — you can run davoid without sudo."
    else
        warn "setcap failed — some modules (sniff, mitm) will require sudo."
    fi
fi

# ─── Done ─────────────────────────────────────────────────────────────────────
echo
echo -e "${GREEN}╔══════════════════════════════════════════════╗${RESET}"
echo -e "${GREEN}║   Davoid v2.0.0 installed successfully!     ║${RESET}"
echo -e "${GREEN}╚══════════════════════════════════════════════╝${RESET}"
echo
echo -e "  Binary:  ${CYAN}${BINARY_PATH}${RESET}"
echo
echo -e "  ${CYAN}davoid${RESET}                          # open TUI"
echo -e "  ${CYAN}davoid new \"Corp Assessment\" --target 10.0.0.0/24${RESET}"
echo -e "  ${CYAN}davoid run scanner${RESET}              # run module directly"
echo -e "  ${CYAN}davoid modules${RESET}                  # list all modules"
echo
if [ "$OS_TYPE" = "linux" ]; then
    warn "sniff / mitm modules may need sudo on systems without setcap support."
else
    warn "sniff / mitm require sudo on macOS (raw socket access)."
fi
echo
