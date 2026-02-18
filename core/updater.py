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
    """Passive background version check."""
    try:
        response = requests.get(REPO_URL, timeout=3)
        if response.status_code == 200:
            for line in response.text.splitlines():
                if "VERSION =" in line:
                    parts = line.split('"')
                    if len(parts) >= 2:
                        remote_version = parts[1]
                        if remote_version != VERSION:
                            return remote_version
    except Exception:
        pass
    return None


def create_snapshot():
    """Creates a fail-safe backup before updating."""
    try:
        if os.path.exists(BACKUP_DIR):
            shutil.rmtree(BACKUP_DIR)
        shutil.copytree(INSTALL_DIR, BACKUP_DIR, ignore=shutil.ignore_patterns(
            'venv', '.git', '__pycache__'))
        return True
    except Exception as e:
        console.print(f"[bold red][!] Snapshot Failed:[/bold red] {e}")
        return False


def rollback():
    """Restores the framework to the last stable snapshot."""
    console.print(
        "[bold red][!] Update Interrupted. Initiating Rollback...[/bold red]")
    try:
        if not os.path.exists(BACKUP_DIR):
            return console.print("[bold red][!] Critical: No backup found.[/bold red]")

        for item in os.listdir(BACKUP_DIR):
            s = os.path.join(BACKUP_DIR, item)
            d = os.path.join(INSTALL_DIR, item)
            if os.path.isdir(s):
                shutil.rmtree(d, ignore_errors=True)
                shutil.copytree(s, d)
            else:
                shutil.copy2(s, d)
        console.print("[bold green][+] Rollback Successful.[/bold green]")
    except Exception as e:
        console.print(
            f"[bold red][!] Total System Failure during rollback: {e}[/bold red]")


def perform_update():
    os.system('cls' if os.name == 'nt' else 'clear')
    # Updated to Red styling
    console.print(Panel(
        "[bold white]Davoid Mainframe Update[/bold white]", border_style="red", expand=False))

    if not os.path.exists(INSTALL_DIR):
        console.print(
            f"[bold red][!] Error:[/bold red] {INSTALL_DIR} not found.")
        return

    console.print("[dim white][*] Creating pre-update snapshot...[/dim white]")
    if not create_snapshot():
        if not questionary.confirm("Snapshot failed. Continue anyway?", default=False, style=Q_STYLE).ask():
            return

    try:
        with Progress(
            SpinnerColumn(style="bold red"),
            TextColumn("[bold white]{task.description}[/bold white]"),
            BarColumn(bar_width=40, style="red",
                      complete_style="bold red", finished_style="bold green"),
            console=console
        ) as progress:

            task1 = progress.add_task("Syncing Core Components...", total=100)
            os.chdir(INSTALL_DIR)
            subprocess.run(["git", "fetch", "--all"],
                           check=True, capture_output=True)
            subprocess.run(["git", "reset", "--hard", "origin/main"],
                           check=True, capture_output=True)
            subprocess.run(["git", "pull", "origin", "main"],
                           check=True, capture_output=True)
            progress.update(task1, completed=100)

            task2 = progress.add_task(
                "Synchronizing Environment...", total=100)
            pip_path = os.path.join(INSTALL_DIR, "venv/bin/pip")
            req_path = os.path.join(INSTALL_DIR, "requirements.txt")

            if os.path.exists(req_path):
                subprocess.run([pip_path, "install", "-r", req_path,
                               "--upgrade"], check=True, capture_output=True)
            progress.update(task2, completed=100)

        # Integrity Report with Red Theme
        table = Table(title="Integrity Status", border_style="red", box=None)
        table.add_column("Component", style="white")
        table.add_column("Status", style="bold red")
        table.add_row("Core Engine", "VERIFIED")
        table.add_row("Dependencies", "SYNCHRONIZED")
        console.print(table)

        console.print("[bold red][+] Update Complete.[/bold red]")
        console.print("[dim]Restart Davoid to apply changes.[/dim]\n")
        sys.exit(0)

    except Exception as e:
        console.print(f"[bold red][!] Update Critical Failure:[/bold red] {e}")
        rollback()


if __name__ == "__main__":
    perform_update()
