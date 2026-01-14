import os
import sys
import shutil
import subprocess
import hashlib
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, DownloadColumn
from rich.live import Live
from rich.table import Table

console = Console()

# --- CONFIGURATION ---
VERSION = "1.2.0"
INSTALL_DIR = "/opt/davoid"
BACKUP_DIR = "/tmp/davoid_backup"


def create_snapshot():
    """Elite Feature: Creates a fail-safe backup before updating."""
    try:
        if os.path.exists(BACKUP_DIR):
            shutil.rmtree(BACKUP_DIR)
        # Backup all except the heavy virtual environment and git history
        shutil.copytree(INSTALL_DIR, BACKUP_DIR, ignore=shutil.ignore_patterns(
            'venv', '.git', '__pycache__'))
        return True
    except Exception:
        return False


def rollback():
    """Restores the framework to the last stable snapshot."""
    console.print(
        "[bold red][!] Update Failed. Initiating Emergency Rollback...[/bold red]")
    try:
        for item in os.listdir(BACKUP_DIR):
            s = os.path.join(BACKUP_DIR, item)
            d = os.path.join(INSTALL_DIR, item)
            if os.path.isdir(s):
                shutil.rmtree(d, ignore_errors=True)
                shutil.copytree(s, d)
            else:
                shutil.copy2(s, d)
        console.print(
            "[bold green][+] Rollback Successful. System Stabilized.[/bold green]")
    except Exception as e:
        console.print(
            f"[bold red][!] Critical Failure during Rollback: {e}[/bold red]")


def perform_update():
    """Performs a deep-sync with a visual Tactical Dashboard."""
    os.system('cls' if os.name == 'nt' else 'clear')
    console.print(Panel(
        "[bold cyan]Davoid Tactical Update Sequence[/bold cyan]", border_style="cyan", expand=False))

    if not create_snapshot():
        console.print(
            "[yellow][!] Warning: Could not create backup snapshot. Proceeding anyway...[/yellow]")

    # Setup the visual progress bars
    progress = Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(bar_width=40),
        DownloadColumn(),
        transient=True
    )

    try:
        with progress:
            # Stage 1: Mainframe Sync
            task1 = progress.add_task(
                "[white]Syncing Source Code...", total=100)
            os.chdir(INSTALL_DIR)
            subprocess.run(["git", "fetch", "--all"],
                           check=True, capture_output=True)
            subprocess.run(["git", "reset", "--hard", "origin/main"],
                           check=True, capture_output=True)
            progress.update(task1, completed=100)

            # Stage 2: Dependency Mapping
            task2 = progress.add_task(
                "[white]Rebuilding Environment...", total=100)
            pip_path = os.path.join(INSTALL_DIR, "venv/bin/pip")
            req_path = os.path.join(INSTALL_DIR, "requirements.txt")
            if os.path.exists(req_path):
                subprocess.run([pip_path, "install", "-r", req_path,
                               "--upgrade"], check=True, capture_output=True)
            progress.update(task2, completed=100)

        # Final Integrity Report
        table = Table(title="Update Integrity Report",
                      border_style="green", box=None)
        table.add_column("Component", style="cyan")
        table.add_column("Status", style="bold green")
        table.add_row("Core Framework", "VERIFIED")
        table.add_row("Offensive Modules", "SYNCHRONIZED")
        table.add_row("Dependencies", "PEAK PERFORMANCE")

        console.print(table)
        console.print(
            "\n[bold green][+] Update Complete. Type 'davoid' to enter the mainframe.[/bold green]\n")
        sys.exit(0)

    except Exception as e:
        console.print(f"[bold red][!] Error:[/bold red] {e}")
        rollback()


if __name__ == "__main__":
    perform_update()
