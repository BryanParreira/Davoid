import os
import shutil
from rich.console import Console
from rich.table import Table
from core.ui import draw_header

console = Console()

def check_command(cmd):
    """Checks if a system command exists in the PATH."""
    return shutil.which(cmd) is not None

def check_injection():
    """Checks for tools required for packet injection testing."""
    if check_command("aireplay-ng"):
        return "[bold green]Supported (via Aircrack-ng)[/bold green]"
    return "[bold yellow]Unknown (Install aircrack-ng for deep test)[/bold yellow]"

def run_auditor():
    draw_header("System & Interface Auditor")
    
    table = Table(title="Davoid Health Report", border_style="bold cyan")
    table.add_column("Component", style="white")
    table.add_column("Status", style="bold")
    table.add_column("Recommendation", style="dim")

    # 1. Core Dependency Audit
    deps = {
        "git": "Required for Ghost-Updates",
        "python3": "Core Engine",
        "tcpdump": "Required for Raw Sniffing",
        "nmap": "Recommended for Advanced Scanning",
        "aireplay-ng": "Required for Injection & Wifi Testing"
    }

    for dep, reason in deps.items():
        exists = check_command(dep)
        status = "[bold green]INSTALLED[/bold green]" if exists else "[bold red]MISSING[/bold red]"
        rec = "None" if exists else f"sudo apt install {dep}"
        table.add_row(dep, status, rec)

    # 2. Permission Audit
    is_root = os.geteuid() == 0
    perm_status = "[bold green]ROOT[/bold green]" if is_root else "[bold red]USER[/bold red]"
    perm_rec = "None" if is_root else "Always run davoid with sudo"
    table.add_row("Execution Privilege", perm_status, perm_rec)

    # 3. Network Hardware Audit
    table.add_row("Packet Injection", check_injection(), "Check driver compatibility")

    console.print(table)

    if not is_root:
        console.print("\n[bold red][!] WARNING:[/bold red] Running without root. Raw socket modules will fail.")
    
    console.print("\n[bold white]Press Enter to return to Command Center...[/bold white]", end="")
    input()