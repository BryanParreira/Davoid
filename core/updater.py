import os
import sys
import subprocess
import requests
from rich.console import Console

console = Console()

# --- CONFIGURATION ---
VERSION = "1.1.0"  # Increment this on GitHub to trigger update notifications
REPO_URL = "https://raw.githubusercontent.com/BryanParreira/Davoid/main/core/updater.py"
INSTALL_DIR = "/opt/davoid"

def check_version():
    """
    Checks the remote updater file on GitHub to compare version strings.
    Returns True if an update is available, False otherwise.
    """
    try:
        response = requests.get(REPO_URL, timeout=5)
        if response.status_code == 200:
            for line in response.text.splitlines():
                if "VERSION =" in line:
                    latest = line.split('"')[1]
                    if latest != VERSION:
                        console.print(f"\n[bold yellow][!] UPDATE AVAILABLE: {latest}[/bold yellow]")
                        console.print(f"[dim]Current version: {VERSION}. Run 'davoid --update' to sync.[/dim]\n")
                        return True
    except Exception:
        # Silent fail to prevent crashing if there is no internet connection
        pass
    return False

def perform_update():
    """
    Performs a clean sync with the GitHub repository.
    1. Resets local changes to prevent merge conflicts.
    2. Pulls the latest code from the main branch.
    3. Updates the Python virtual environment dependencies.
    """
    console.print("\n[bold cyan][*] Ghost-Update Sequence Initiated...[/bold cyan]")

    try:
        # Navigate to the app directory
        if not os.path.exists(INSTALL_DIR):
            console.print(f"[bold red][!] Error:[/bold red] Installation directory {INSTALL_DIR} not found.")
            return

        os.chdir(INSTALL_DIR)

        # 1. Clear any local modifications (Critical for automated tools)
        console.print("[*] Reverting local modifications to prevent conflicts...")
        subprocess.run(["git", "fetch", "--all"], check=True, capture_output=True)
        subprocess.run(["git", "reset", "--hard", "origin/main"], check=True, capture_output=True)

        # 2. Pull latest code
        console.print("[*] Downloading latest mainframe components...")
        subprocess.run(["git", "pull", "origin", "main"], check=True, capture_output=True)

        # 3. Update the Virtual Environment dependencies
        console.print("[*] Synchronizing environment dependencies...")
        pip_path = os.path.join(INSTALL_DIR, "venv/bin/pip")
        requirements_path = os.path.join(INSTALL_DIR, "requirements.txt")
        
        if os.path.exists(requirements_path):
            subprocess.run([pip_path, "install", "-r", requirements_path], check=True, capture_output=True)
        else:
            # Fallback if requirements.txt is missing
            subprocess.run([pip_path, "install", "rich", "scapy", "requests", "cryptography"], check=True, capture_output=True)

        console.print("[bold green][+] Update Complete![/bold green]")
        console.print("[bold yellow][!] Please restart Davoid to load the new modules.[/bold yellow]\n")
        sys.exit(0)

    except subprocess.CalledProcessError as e:
        console.print(f"[bold red][!] Git/Pip Error:[/bold red] {e}")
        console.print("[dim]Ensure you have a stable internet connection and sudo privileges.[/dim]")
    except Exception as e:
        console.print(f"[bold red][!] Critical Failure:[/bold red] {e}")

if __name__ == "__main__":
    # If run directly, perform update
    perform_update()