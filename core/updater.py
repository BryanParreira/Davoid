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
from core.ui import draw_header, Q_STYLE

console = Console()

def is_running_in_docker() -> bool:
    """Detects if the framework is currently sandboxed."""
    return os.path.exists('/.dockerenv')

def check_version():
    """Placeholder for future remote version checking against GitHub API."""
    pass

def perform_update():
    draw_header("NEXUS COMMAND CENTER: SYSTEM UPDATE")

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

    try:
        BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
        
        console.print(Panel("Initiating secure sync with remote GitHub repository...", border_style="cyan"))

        # 1. Fetch updates silently
        with console.status("[bold cyan]Fetching latest telemetry from origin...[/bold cyan]", spinner="bouncingBar"):
            subprocess.run(["git", "fetch", "origin", "main"], cwd=BASE_DIR, capture_output=True, check=True)
            time.sleep(0.8) # Slight delay for visual smoothness
        
        # 2. FORCE a hard reset silently
        with console.status("[bold cyan]Applying hotfixes and syncing core modules...[/bold cyan]", spinner="bouncingBar"):
            result = subprocess.run(
                ["git", "reset", "--hard", "origin/main"], 
                cwd=BASE_DIR, 
                capture_output=True, 
                text=True,
                check=True
            )
            time.sleep(0.8)

        # 3. Update dependencies silently
        with console.status("[bold cyan]Compiling and upgrading Python dependencies...[/bold cyan]", spinner="bouncingBar"):
            subprocess.run(
                [sys.executable, "-m", "pip", "install", "--quiet", "--no-cache-dir", "-r", "requirements.txt"], 
                cwd=BASE_DIR, 
                capture_output=True,
                check=True
            )
            time.sleep(1)
        
        # 4. Success Panel
        console.print(Panel(
            f"[bold green]System Upgrade Successful![/bold green]\n\n"
            f"[dim]{result.stdout.strip()}[/dim]\n\n"
            f"[cyan]Rebooting Nexus Command Center...[/cyan]",
            title="Update Complete",
            border_style="green"
        ))
        time.sleep(2)
        
        main_script = os.path.join(BASE_DIR, "main.py")
        os.execv(sys.executable, [sys.executable, main_script] + sys.argv[1:])
        
    except FileNotFoundError:
        console.print("[bold red][!] Git is not installed or not in PATH.[/bold red]")
        questionary.press_any_key_to_continue("Press any key to return...", style=Q_STYLE).ask()
    except subprocess.CalledProcessError as e:
        # If a command fails, unhide the error output so the user knows what broke
        error_msg = e.stderr.decode() if hasattr(e, 'stderr') and e.stderr else str(e)
        console.print(f"\n[bold red][!] Update process encountered a critical error:[/bold red]\n{error_msg}")
        questionary.press_any_key_to_continue("Press any key to return...", style=Q_STYLE).ask()
    except Exception as e:
        console.print(f"\n[bold red][!] Unexpected failure during update:[/bold red] {e}")
        questionary.press_any_key_to_continue("Press any key to return...", style=Q_STYLE).ask()