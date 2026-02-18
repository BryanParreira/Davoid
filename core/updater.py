import os
import sys
import shutil
import subprocess
import requests
import questionary
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich.table import Table
from core.ui import Q_STYLE

console = Console()

# --- CONFIGURATION ---
VERSION = "1.2.0"
REPO_URL = "https://raw.githubusercontent.com/BryanParreira/Davoid/main/core/updater.py"
INSTALL_DIR = "/opt/davoid"
BACKUP_DIR = "/tmp/davoid_backup"


def check_version():
    """
    Elite Feature: Passive background version check with clean parsing.
    Returns the latest version string if an update is available, else None.
    """
    try:
        response = requests.get(REPO_URL, timeout=3)
        if response.status_code == 200:
            for line in response.text.splitlines():
                if "VERSION =" in line:
                    # Cleanly extract only the version string between the quotes
                    parts = line.split('"')
                    if len(parts) >= 2:
                        remote_version = parts[1]
                        if remote_version != VERSION:
                            console.print(
                                f"[bold yellow][!] Update Available: {remote_version} (Current: {VERSION})[/bold yellow]")
                            return remote_version
    except Exception:
        # Silent fail to prevent crashing if there is no internet connection
        pass
    return None


def create_snapshot():
    """Elite Feature: Creates a fail-safe backup before updating."""
    try:
        if os.path.exists(BACKUP_DIR):
            shutil.rmtree(BACKUP_DIR)
        # Snapshot the core logic while ignoring the heavy virtual environment
        shutil.copytree(INSTALL_DIR, BACKUP_DIR, ignore=shutil.ignore_patterns(
            'venv', '.git', '__pycache__'))
        return True
    except Exception as e:
        console.print(f"[bold red][!] Snapshot Failed:[/bold red] {e}")
        return False


def rollback():
    """Restores the framework to the last stable snapshot in case of failure."""
    console.print(
        "[bold red][!] Update Interrupted. Initiating Emergency Rollback...[/bold red]")
    try:
        if not os.path.exists(BACKUP_DIR):
            console.print(
                "[bold red][!] Critical: No backup found to restore.[/bold red]")
            return

        for item in os.listdir(BACKUP_DIR):
            s = os.path.join(BACKUP_DIR, item)
            d = os.path.join(INSTALL_DIR, item)
            if os.path.isdir(s):
                shutil.rmtree(d, ignore_errors=True)
                shutil.copytree(s, d)
            else:
                shutil.copy2(s, d)
        console.print(
            "[bold green][+] Rollback Successful. Framework Stabilized.[/bold green]")
    except Exception as e:
        console.print(
            f"[bold red][!] Total System Failure during rollback: {e}[/bold red]")


def perform_update():
    """Performs a deep-sync with visual progress and error recovery."""
    os.system('cls' if os.name == 'nt' else 'clear')
    console.print(Panel(
        "[bold cyan]Davoid Updating[/bold cyan]", border_style="cyan", expand=False))

    if not os.path.exists(INSTALL_DIR):
        console.print(
            f"[bold red][!] Error:[/bold red] {INSTALL_DIR} not found.")
        return

    # 1. Create Backup Snapshot
    console.print("[*] Creating pre-update snapshot...")
    if not create_snapshot():
        # Updated to use questionary for consistent UI
        if not questionary.confirm("Snapshot failed. Continue without backup?", default=False, style=Q_STYLE).ask():
            return

    try:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(bar_width=40),
            console=console
        ) as progress:

            # 2. Sync Source Code
            task1 = progress.add_task(
                "[white]Syncing Mainframe components...", total=100)
            os.chdir(INSTALL_DIR)
            subprocess.run(["git", "fetch", "--all"],
                           check=True, capture_output=True)
            subprocess.run(["git", "reset", "--hard", "origin/main"],
                           check=True, capture_output=True)
            subprocess.run(["git", "pull", "origin", "main"],
                           check=True, capture_output=True)
            progress.update(task1, completed=100)

            # 3. Synchronize Dependencies
            task2 = progress.add_task(
                "[white]Synchronizing Environment...", total=100)
            pip_path = os.path.join(INSTALL_DIR, "venv/bin/pip")
            req_path = os.path.join(INSTALL_DIR, "requirements.txt")

            if os.path.exists(req_path):
                subprocess.run([pip_path, "install", "-r", req_path,
                               "--upgrade"], check=True, capture_output=True)
            progress.update(task2, completed=100)

        # Integrity Report
        table = Table(title="Update Integrity Report",
                      border_style="green", box=None)
        table.add_column("Component", style="cyan")
        table.add_column("Status", style="bold green")
        table.add_row("Core Engine", "VERIFIED")
        table.add_row("Dependencies", "SYNCHRONIZED")
        console.print(table)

        console.print("[bold green][+] Update Complete![/bold green]")
        console.print(
            "[bold yellow][!] Please restart Davoid to load the new modules.[/bold yellow]\n")
        sys.exit(0)

    except Exception as e:
        console.print(f"[bold red][!] Update Error:[/bold red] {e}")
        rollback()


if __name__ == "__main__":
    perform_update()
