import os
import shutil
import subprocess
from rich.console import Console
from rich.table import Table
from scapy.all import conf
from core.ui import draw_header

console = Console()

def check_command(cmd):
    """Checks if a system command exists in the PATH."""
    return shutil.which(cmd) is not None

def get_wifi_capabilities(iface):
    """
    Attempts to verify Monitor Mode and Injection support for a WLAN interface.
    Requires 'iw' or 'iwconfig' to be installed.
    """
    if not check_command("iw"):
        return "[bold yellow]Unknown (Install 'iw')[/bold yellow]"
    
    try:
        # Check if interface exists in 'iw dev'
        output = subprocess.check_output(["iw", "dev", iface, "info"], stderr=subprocess.STDOUT).decode()
        if "type monitor" in output.lower():
            return "[bold green]Active (Monitor Mode)[/bold green]"
        else:
            return "[bold cyan]Managed (Injection Ready?)[/bold cyan]"
    except:
        return "[bold red]Offline/Not Found[/bold red]"

def run_auditor():
    draw_header("System & WLAN Auditor")
    
    table = Table(title="Davoid Production Health Report", border_style="bold cyan")
    table.add_column("Component", style="white")
    table.add_column("Status", style="bold")
    table.add_column("Recommendation", style="dim")

    # 1. Core Tools & Wireless Dependencies
    deps = {
        "git": "Required for updates",
        "tcpdump": "Required for sniffing",
        "nmap": "Advanced port discovery",
        "iw": "WLAN hardware info",
        "aireplay-ng": "Packet injection engine",
        "airmon-ng": "Monitor mode control"
    }

    for dep, reason in deps.items():
        exists = check_command(dep)
        status = "[bold green]INSTALLED[/bold green]" if exists else "[bold red]MISSING[/bold red]"
        rec = "None" if exists else f"sudo apt install {dep}"
        table.add_row(dep, status, rec)

    # 2. Permission Audit
    is_root = os.geteuid() == 0
    perm_status = "[bold green]ROOT[/bold green]" if is_root else "[bold red]USER[/bold red]"
    perm_rec = "None" if is_root else "Run Davoid with 'sudo'"
    table.add_row("Execution Privilege", perm_status, perm_rec)

    # 3. WLAN Hardware Verification
    # Identify wireless interfaces from Scapy config
    wlan_ifaces = [i.name for i in conf.ifaces.data.values() if "wlan" in i.name.lower() or "wlp" in i.name.lower() or "en" in i.name.lower()]
    
    if not wlan_ifaces:
        table.add_row("Wireless Interface", "[bold red]NONE FOUND[/bold red]", "Check USB Wi-Fi adapter")
    else:
        for iface in wlan_ifaces:
            status = get_wifi_capabilities(iface)
            table.add_row(f"WLAN: {iface}", status, "Use airmon-ng start for monitor mode")

    console.print(table)

    # Critical Warnings
    if not is_root:
        console.print("\n[bold red][!] WARNING:[/bold red] Many WLAN functions require root to access hardware.")
    
    if not wlan_ifaces:
        console.print("[bold yellow][!] NOTE:[/bold yellow] No wireless cards detected. Davoid will use Ethernet mode.")

    console.print("\n[bold white]Press Enter to return to Command Center...[/bold white]", end="")
    input()