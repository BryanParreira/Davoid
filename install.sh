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
  NEEDS_SUDO=0
else
  INSTALL_PATH="/usr/local/bin/${BINARY}"
  NEEDS_SUDO=1
fi

# ── Download ─────────────────────────────────────────────────────────────────
TMP="$(mktemp)"
TMP_CHECKSUMS="$(mktemp)"

echo "[*] Downloading ${ASSET}..."
curl -sSL "${BASE_URL}/${ASSET}" -o "$TMP"
curl -sSL "${BASE_URL}/checksums.txt" -o "$TMP_CHECKSUMS"

# ── Verify checksum ──────────────────────────────────────────────────────────
echo "[*] Verifying checksum..."
EXPECTED="$(grep "${ASSET}" "$TMP_CHECKSUMS" | awk '{print $1}')"
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
if [ "$NEEDS_SUDO" = "1" ]; then
  sudo mv "$TMP" "$INSTALL_PATH"
else
  mv "$TMP" "$INSTALL_PATH"
fi
rm -f "$TMP_CHECKSUMS"

echo "[+] Installed: ${INSTALL_PATH}"
echo ""
echo "  Run: davoid"
echo ""
