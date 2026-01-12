import requests
import subprocess
import os
from rich.console import Console
from rich.panel import Panel

console = Console()

# Current version of the local code
VERSION = "2.6"
# GitHub link for the version file
RAW_VERSION_URL = "https://raw.githubusercontent.com/BryanParreira/Davoid/main/version.txt"
INSTALL_DIR = "/opt/davoid"


def check_version():
    """Passive check to notify user of updates."""
    try:
        response = requests.get(RAW_VERSION_URL, timeout=3)
        if response.status_code == 200:
            latest = response.text.strip()
            if latest != VERSION:
                console.print(Panel(
                    f"[bold yellow]UPDATE FOUND:[/bold yellow] Davoid v{latest} is available!\n"
                    f"[white]Run [bold red]davoid --update[/bold red] to pull the latest tools.[/white]",
                    border_style="yellow",
                    expand=False
                ))
    except Exception:
        pass  # Fail silently if no internet


def perform_update():
    """Active check to pull latest code and sync dependencies."""
    console.print(
        "[bold blue][*][/bold blue] Pulling latest changes from GitHub...")
    try:
        # Change to the install directory
        os.chdir(INSTALL_DIR)

        # Ensure git recognizes the directory as safe
        subprocess.check_call(
            ["sudo", "git", "config", "--global", "--add", "safe.directory", INSTALL_DIR])

        # Force a pull from the main branch
        subprocess.check_call(["sudo", "git", "fetch", "--all"])
        subprocess.check_call(
            ["sudo", "git", "reset", "--hard", "origin/main"])

        # Update dependencies
        console.print(
            "[bold blue][*][/bold blue] Synchronizing dependencies...")
        subprocess.check_call(
            [f"{INSTALL_DIR}/venv/bin/pip", "install", "-r", "requirements.txt"])

        console.print(
            "[bold green][+] Davoid updated successfully! Restarting...[/bold green]")
    except Exception as e:
        console.print(f"[bold red][!] Update failed:[/bold red] {e}")
