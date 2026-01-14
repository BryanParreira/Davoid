import socket
import threading
import warnings
import requests
from scapy.all import ARP, Ether, srp, IP, sr1
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
from core.ui import draw_header

# Suppress warnings for cleaner TUI
warnings.filterwarnings("ignore", category=UserWarning, module='scapy')
console = Console()

# --- INTELLIGENCE HELPERS ---


def get_vendor(mac):
    """Identifies manufacturer via MAC OUI."""
    try:
        url = f"https://api.macvendors.com/{mac}"
        response = requests.get(url, timeout=1)
        if response.status_code == 200:
            return response.text
    except:
        pass
    return "Unknown"


def get_os_guess(ip):
    """Stealth OS Fingerprinting via TTL signatures."""
    try:
        pkt = sr1(IP(dst=ip), timeout=1, verbose=0)
        if pkt:
            ttl = pkt.getlayer(IP).ttl
            if ttl <= 64:
                return "Linux/Unix"
            elif ttl <= 128:
                return "Windows"
            else:
                return "Network Device"
    except:
        pass
    return "Unknown"


def auto_cve_check(ip, port):
    """Banner Grabbing + Automated Vuln Matching."""
    # Hardcoded known vulnerable banners for instant speed
    vuln_signatures = {
        "vsFTPd 2.3.4": "CVE-2011-2523 (Backdoor)",
        "Apache/2.4.49": "CVE-2021-41773 (Path Traversal)",
        "OpenSSH_7.2p2": "CVE-2016-6210 (User Enum)"
    }
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.7)
            if s.connect_ex((ip, port)) == 0:
                s.send(b"HEAD / HTTP/1.1\r\n\r\n")
                banner = s.recv(1024).decode().strip()
                for sig, cve in vuln_signatures.items():
                    if sig in banner:
                        return f"[bold red]{cve}[/bold red]"
                return f"Port {port} Open"
    except:
        pass
    return None

# --- MAIN SCANNER LOGIC ---


def network_discovery():
    draw_header("Root Discovery & Vuln-Hunter")

    # Auto-detect local subnet
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        subnet_hint = ".".join(s.getsockname()[0].split('.')[:-1]) + ".0/24"
        s.close()
        console.print(f"[dim]Suggested Subnet: {subnet_hint}[/dim]")
    except:
        subnet_hint = "192.168.1.0/24"

    ip_range = console.input(
        f"[bold yellow]Enter IP Range: [/bold yellow]").strip() or subnet_hint
    do_vuln = console.input(
        "[bold cyan]Hunt for Vulnerabilities (Slower)? (y/N): [/bold cyan]").lower() == 'y'

    try:
        packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip_range)
        table = Table(
            title=f"Network Intelligence: {ip_range}", border_style="bold red")
        table.add_column("IP Address", style="cyan")
        table.add_column("OS/Vendor", style="white")
        table.add_column("Vulnerability/Service", style="bold yellow")
        table.add_column("MAC Address", style="magenta")

        with Progress(SpinnerColumn(), TextColumn("{task.description}"), console=console) as progress:
            task = progress.add_task("[cyan]Scanning Layers...", total=None)
            ans, _ = srp(packet, timeout=2, verbose=False)

            for _, rcv in ans:
                ip, mac = rcv.psrc, rcv.hwsrc
                progress.update(task, description=f"[yellow]Analysing {ip}...")

                vendor = get_vendor(mac)
                os_type = get_os_guess(ip)

                vuln_info = "[dim]Scan Skipped[/dim]"
                if do_vuln:
                    # Automatically checks critical ports (80, 21, 22) for CVEs
                    for p in [80, 21, 22]:
                        found = auto_cve_check(ip, p)
                        if found:
                            vuln_info = found
                            break
                    if vuln_info == "[dim]Scan Skipped[/dim]":
                        vuln_info = "Secure/Filtered"

                table.add_row(ip, f"{os_type} ({vendor})", vuln_info, mac)

        console.print(table)
    except Exception as e:
        console.print(f"[red]Error:[/red] {e}")
    input("\nPress Enter...")
