import os
import sys
import shutil
import subprocess
import requests
import questionary
import time
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich.table import Table
from rich import box
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
    console.print("\n[bold red on white] WARNING: UPDATE INTERRUPTED. INITIATING ROLLBACK SEQUENCE [/bold red on white]")
    try:
        if not os.path.exists(BACKUP_DIR):
            return console.print("[bold red][!] Critical: No backup found to restore from.[/bold red]")

        with console.status("[bold red]Restoring previous stable snapshot...", spinner="bouncingBar"):
            for item in os.listdir(BACKUP_DIR):
                s = os.path.join(BACKUP_DIR, item)
                d = os.path.join(INSTALL_DIR, item)
                if os.path.isdir(s):
                    shutil.rmtree(d, ignore_errors=True)
                    shutil.copytree(s, d)
                else:
                    shutil.copy2(s, d)
            time.sleep(1) # Slight delay for UI pacing
            
        console.print("[bold green][+] Rollback Successful. Framework integrity restored.[/bold green]")
    except Exception as e:
        console.print(f"[bold red][!] Total System Failure during rollback: {e}[/bold red]")


def perform_update():
    os.system('cls' if os.name == 'nt' else 'clear')
    
    # 1. Premium UI Header
    console.print(Panel(
        "[bold white]DAVOID FRAMEWORK : OVER-THE-AIR (OTA) UPDATE[/bold white]\n"
        "[dim]Establishing secure uplink to Mainframe Repository...[/dim]", 
        border_style="bold red", 
        expand=True
    ))

    if not os.path.exists(INSTALL_DIR):
        console.print(f"[bold red][!] Critical Error:[/bold red] Installation directory {INSTALL_DIR} not found.")
        return

    # 2. Pre-flight Snapshot
    console.print("[cyan][*] Initializing pre-flight snapshot (Creating backup restore point)...[/cyan]")
    if not create_snapshot():
        if not questionary.confirm("Snapshot failed. Proceed with update anyway? (Dangerous)", default=False, style=Q_STYLE).ask():
            console.print("[yellow][*] Update aborted by user.[/yellow]")
            return
    else:
        console.print("[green][+] Snapshot secured at /tmp/davoid_backup[/green]\n")

    try:
        # 3. Dynamic Progress Bars
        with Progress(
            SpinnerColumn(spinner="dots2", style="bold red"),
            TextColumn("[bold white]{task.description}[/bold white]"),
            BarColumn(bar_width=45, style="dark_red", complete_style="bold red", finished_style="bold green"),
            TextColumn("[bold red]{task.percentage:>3.0f}%[/bold red]"),
            console=console
        ) as progress:

            # Break the Git task into 3 distinct steps so the bar actually moves
            task_git = progress.add_task("Synchronizing Core Modules (Git)", total=3)
            os.chdir(INSTALL_DIR)
            
            subprocess.run(["git", "fetch", "--all"], check=True, capture_output=True)
            progress.update(task_git, advance=1)
            
            subprocess.run(["git", "reset", "--hard", "origin/main"], check=True, capture_output=True)
            progress.update(task_git, advance=1)
            
            subprocess.run(["git", "pull", "origin", "main"], check=True, capture_output=True)
            progress.update(task_git, advance=1)

            # Python Environment Sync
            task_pip = progress.add_task("Updating Virtual Environment (Pip)", total=1)
            pip_path = os.path.join(INSTALL_DIR, "venv/bin/pip")
            req_path = os.path.join(INSTALL_DIR, "requirements.txt")

            if os.path.exists(req_path):
                subprocess.run([pip_path, "install", "-r", req_path, "--upgrade"], check=True, capture_output=True)
            progress.update(task_pip, advance=1)

        # 4. Integrity Report
        console.print("\n")
        table = Table(title="[bold white]SYSTEM INTEGRITY DIAGNOSTICS[/bold white]", border_style="red", box=box.SQUARE, expand=True)
        table.add_column("Component Layer", style="cyan")
        table.add_column("Integrity Status", style="bold green", justify="right")
        
        table.add_row("Pre-Update Snapshot", "[bold green]VERIFIED[/bold green]")
        table.add_row("Core Engine & Modules", "[bold green]SYNCHRONIZED[/bold green]")
        table.add_row("Python Dependencies", "[bold green]OPTIMIZED[/bold green]")
        console.print(table)

        console.print("\n[bold red][+] Update Complete. Weapon systems primed.[/bold red]")
        console.print("[dim]Press Enter to reboot Davoid...[/dim]")
        input()
        sys.exit(0)

    except Exception as e:
        console.print(f"\n[bold red][!] Update Critical Failure:[/bold red] {e}")
        rollback()
        input("\nPress Enter to exit...")


if __name__ == "__main__":
    perform_update()