import subprocess
import os
import requests
from rich.console import Console

console = Console()
VERSION = "2.7"
INSTALL_DIR = "/opt/davoid"


def perform_update():
    console.print(
        "[bold blue][*][/bold blue] Pulling latest changes from GitHub...")
    try:
        # Change to the install directory
        os.chdir(INSTALL_DIR)

        # 1. Force Git to reset and pull (Fixes ownership/local change issues)
        subprocess.check_call(
            ["sudo", "git", "config", "--global", "--add", "safe.directory", INSTALL_DIR])
        subprocess.check_call(
            ["sudo", "git", "reset", "--hard", "origin/main"])
        subprocess.check_call(["sudo", "git", "pull", "origin", "main"])

        # 2. Refresh dependencies
        console.print("[bold blue][*][/bold blue] Syncing dependencies...")
        subprocess.check_call(
            [f"{INSTALL_DIR}/venv/bin/pip", "install", "-r", "requirements.txt"])

        console.print(
            "[bold green][+] Update successful! Please restart Davoid.[/bold green]")
    except Exception as e:
        console.print(f"[bold red][!] Update failed:[/bold red] {e}")
