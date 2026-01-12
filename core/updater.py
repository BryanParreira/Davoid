import requests
import subprocess
import os
from rich.console import Console
from rich.panel import Panel

console = Console()

VERSION = "2.6"
RAW_VERSION_URL = "https://raw.githubusercontent.com/BryanParreira/Davoid/main/version.txt"
INSTALL_DIR = "/opt/davoid"


def check_version():
    try:
        response = requests.get(RAW_VERSION_URL, timeout=2)
        if response.status_code == 200:
            latest = response.text.strip()
            if latest != VERSION:
                console.print(Panel(
                    f"[bold yellow]UPDATE FOUND:[/bold yellow] Davoid v{latest} is available!\n"
                    f"[white]Run [bold red]davoid --update[/bold red] to pull the latest tools.[/white]",
                    border_style="yellow",
                    expand=False
                ))
    except:
        pass


def perform_update():
    """Logic to pull latest code and update dependencies."""
    console.print(
        "[bold blue][*][/bold blue] Pulling latest changes from GitHub...")
    try:
        # Change directory to the install path to ensure git pull works
        os.chdir(INSTALL_DIR)

        # 1. Pull latest code
        subprocess.check_call(["git", "pull"])

        # 2. Update dependencies inside the venv
        console.print(
            "[bold blue][*][/bold blue] Synchronizing dependencies...")
        subprocess.check_call(
            [f"{INSTALL_DIR}/venv/bin/pip", "install", "-r", "requirements.txt"])

        console.print(
            "[bold green][+] Davoid updated successfully! Restarting...[/bold green]")
    except Exception as e:
        console.print(f"[bold red][!] Update failed:[/bold red] {e}")
