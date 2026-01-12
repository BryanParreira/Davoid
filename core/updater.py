import os
import sys
import subprocess
import requests
from rich.console import Console

console = Console()

VERSION = "1.1"
REPO_URL = "https://raw.githubusercontent.com/BryanParreira/Davoid/main/core/updater.py"

def check_version():
    try:
        response = requests.get(REPO_URL, timeout=5)
        if response.status_code == 200:
            for line in response.text.splitlines():
                if "VERSION =" in line:
                    latest = line.split('"')[1]
                    if latest != VERSION:
                        console.print(f"\n[bold yellow][!] Update Available: {latest} (Current: {VERSION})[/bold yellow]")
                        console.print("[dim]Run 'davoid --update' or use the menu to sync.[/dim]\n")
                        return True
    except:
        pass
    return False

def perform_update():
    console.print("[bold cyan][*] Initializing Ghost-Update sequence...[/bold cyan]")
    
    # We create a small bash/batch script to handle the overwrite and restart
    update_script = "update.sh" if os.name != "nt" else "update.bat"
    
    if os.name != "nt": # Linux/macOS
        commands = f"""#!/bin/bash
        sleep 2
        git fetch --all
        git reset --hard origin/main
        python3 main.py
        rm update.sh
        """
    else: # Windows
        commands = f"""
        @echo off
        timeout /t 2 /nobreak > nul
        git fetch --all
        git reset --hard origin/main
        python main.py
        del update.bat
        """

    with open(update_script, "w") as f:
        f.write(commands)

    console.print("[bold green][+] Update script ready. Restarting Davoid...[/bold green]")
    
    if os.name != "nt":
        os.chmod(update_script, 0o755)
        subprocess.Popen(["/bin/bash", "./update.sh"], shell=False)
    else:
        subprocess.Popen([update_script], shell=True)
    
    sys.exit(0) # Exit the current process so files can be overwritten