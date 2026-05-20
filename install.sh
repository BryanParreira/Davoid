#!/bin/bash
set -e

REPO="BryanParreira/Davoid"
BINARY="davoid"
BASE_URL="https://github.com/${REPO}/releases/latest/download"

# ── Detect OS ────────────────────────────────────────────────────────────────
OS="$(uname -s)"
ARCH="$(uname -m)"

case "$OS" in
  Linux)  OS_KEY="linux"  ;;
  Darwin) OS_KEY="darwin" ;;
  *)      echo "Unsupported OS: $OS"; exit 1 ;;
esac

case "$ARCH" in
  x86_64)        ARCH_KEY="amd64" ;;
  aarch64|arm64) ARCH_KEY="arm64" ;;
  *)             echo "Unsupported architecture: $ARCH"; exit 1 ;;
esac

ASSET="${BINARY}-${OS_KEY}-${ARCH_KEY}"

# ── Install path ─────────────────────────────────────────────────────────────
if [ "$OS_KEY" = "darwin" ] && [ -d "/opt/homebrew/bin" ]; then
  INSTALL_PATH="/opt/homebrew/bin/${BINARY}"
elif [ -d "/usr/local/bin" ]; then
  INSTALL_PATH="/usr/local/bin/${BINARY}"
else
  INSTALL_PATH="/usr/bin/${BINARY}"
fi

# Detect whether we actually need sudo by testing write access to the dir
needs_sudo() {
  local dir
  dir="$(dirname "$1")"
  # Try creating a temp file in the target directory
  local probe
  probe="$(mktemp "${dir}/.davoid-probe-XXXXXX" 2>/dev/null)" && rm -f "$probe" && return 1
  return 0
}

if needs_sudo "$INSTALL_PATH"; then
  NEEDS_SUDO=1
else
  NEEDS_SUDO=0
fi

# ── Download ─────────────────────────────────────────────────────────────────
TMP="$(mktemp)"
TMP_CHECKSUMS="$(mktemp)"

echo "[*] Downloading ${ASSET}..."
curl -fsSL "${BASE_URL}/${ASSET}" -o "$TMP"
if [ $? -ne 0 ]; then
  echo "[-] Download failed. Check your connection or visit:"
  echo "    https://github.com/${REPO}/releases/latest"
  rm -f "$TMP" "$TMP_CHECKSUMS"
  exit 1
fi

curl -fsSL "${BASE_URL}/checksums.txt" -o "$TMP_CHECKSUMS"

# ── Verify checksum ──────────────────────────────────────────────────────────
echo "[*] Verifying checksum..."
EXPECTED="$(grep "${ASSET}" "$TMP_CHECKSUMS" | awk '{print $1}')"

if [ -z "$EXPECTED" ]; then
  echo "[-] Checksum entry not found for ${ASSET}. Aborting."
  rm -f "$TMP" "$TMP_CHECKSUMS"
  exit 1
fi

if command -v sha256sum &>/dev/null; then
  ACTUAL="$(sha256sum "$TMP" | awk '{print $1}')"
else
  ACTUAL="$(shasum -a 256 "$TMP" | awk '{print $1}')"
fi

if [ "$EXPECTED" != "$ACTUAL" ]; then
  echo "[-] Checksum mismatch — download may be corrupted. Aborting."
  rm -f "$TMP" "$TMP_CHECKSUMS"
  exit 1
fi
echo "[+] Checksum OK"

# ── Install ──────────────────────────────────────────────────────────────────
chmod +x "$TMP"
rm -f "$TMP_CHECKSUMS"

if [ "$NEEDS_SUDO" = "1" ]; then
  echo "[*] Installing to ${INSTALL_PATH} (requires sudo)..."
  sudo mv "$TMP" "$INSTALL_PATH"
else
  mv "$TMP" "$INSTALL_PATH"
fi

echo "[+] Installed: ${INSTALL_PATH}"
echo ""
echo "  Run: davoid"
echo ""
