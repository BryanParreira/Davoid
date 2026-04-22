"""
core/updater.py — Enterprise Update Manager
Self-aware updater that handles native pulls or provides Docker rebuild instructions.
"""

import os
import sys
import time
import subprocess
import questionary
from rich.console import Console
from rich.panel import Panel
from core.ui import Q_STYLE

console = Console()

def is_running_in_docker() -> bool:
    """Detects if the framework is currently sandboxed."""
    return os.path.exists('/.dockerenv')

def check_version():
    """Placeholder for future remote version checking against GitHub API."""
    pass

def perform_update():
    console.print("\n[bold cyan][*] Initiating Framework Update Sequence...[/bold cyan]")

    # 1. Handle Docker Environment
    if is_running_in_docker():
        console.print(Panel(
            "[bold yellow]Docker Environment Detected[/bold yellow]\n\n"
            "Because Davoid is securely sandboxed in a container, it cannot safely overwrite host files.\n"
            "To install the latest updates, exit the framework and run the following on your host terminal:\n\n"
            "[bold cyan]cd davoid[/bold cyan]\n"
            "[bold cyan]git pull origin main[/bold cyan]\n"
            "[bold cyan]./install.sh[/bold cyan]",
            border_style="yellow"
        ))
        questionary.press_any_key_to_continue("Press any key to return...", style=Q_STYLE).ask()
        return

    # 2. Handle Native Environment
    try:
        console.print("[dim]Pulling latest changes from GitHub...[/dim]")
        # Run git pull
        result = subprocess.run(["git", "pull", "origin", "main"], capture_output=True, text=True)
        console.print(f"[white]{result.stdout}[/white]")
        
        if "Already up to date." in result.stdout:
            questionary.press_any_key_to_continue("Press any key to return...", style=Q_STYLE).ask()
            return

        console.print("[dim]Updating Python dependencies...[/dim]")
        subprocess.run([sys.executable, "-m", "pip", "install", "-r", "requirements.txt"], check=True)
        
        console.print("\n[bold green][+] Update complete! Restarting framework...[/bold green]")
        time.sleep(1.5)
        
        # Restart the application
        os.execv(sys.executable, ['python'] + sys.argv)
        
    except FileNotFoundError:
        console.print("[bold red][!] Git is not installed or not in PATH.[/bold red]")
        questionary.press_any_key_to_continue("Press any key to return...", style=Q_STYLE).ask()
    except Exception as e:
        console.print(f"[bold red][!] Update failed:[/bold red] {e}")
        questionary.press_any_key_to_continue("Press any key to return...", style=Q_STYLE).ask()