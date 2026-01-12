import socket
import threading
import warnings
from scapy.all import ARP, Ether, srp, IP, sr1
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
from core.ui import draw_header
import requests
from modules.cve_search import lookup_cves, display_vulnerabilities

warnings.filterwarnings("ignore", category=UserWarning, module='scapy')
console = Console()

def get_vendor(mac):
    try:
        url = f"https://api.macvendors.com/{mac}"
        response = requests.get(url, timeout=1)
        if response.status_code == 200: return response.text
    except: pass
    return "Unknown"

def get_os_guess(ip):
    try:
        pkt = sr1(IP(dst=ip), timeout=1, verbose=0)
        if pkt:
            ttl = pkt.getlayer(IP).ttl
            if ttl <= 64: return "Linux/Unix"
            elif ttl <= 128: return "Windows"
    except: pass
    return "Unknown"

def grab_banner(ip, port):
    """Attempts to grab the service banner for CVE matching."""
    try:
        with socket.socket() as s:
            s.settimeout(1)
            s.connect((ip, port))
            # 
            s.send(b"HEAD / HTTP/1.1\r\n\r\n")
            banner = s.recv(1024).decode().strip()
            return banner.split('\n')[0][:30] if banner else "Unknown Service"
    except:
        return "Unknown Service"

def network_discovery():
    draw_header("Root Discovery Mode")
    
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        subnet_hint = ".".join(local_ip.split('.')[:-1]) + ".0/24"
    except:
        subnet_hint = "192.168.1.0/24"

    ip_range = console.input(f"[bold yellow]Enter Subnet [[white]{subnet_hint}[/white]]: [/bold yellow]").strip() or subnet_hint
    do_intel = console.input("[bold cyan]Perform Advanced Intelligence (OS/Ports/CVE)? (y/N): [/bold cyan]").lower() == 'y'

    try:
        packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip_range)
        ans, _ = srp(packet, timeout=2, verbose=False)
        
        table = Table(title=f"Advanced Recon: {ip_range}", border_style="bold red", expand=True)
        table.add_column("IP Address", style="cyan")
        table.add_column("OS Guess", style="bold green")
        table.add_column("Vendor", style="white")
        table.add_column("Vuln Found?", style="bold yellow")
        table.add_column("MAC Address", style="magenta")

        discovered_vulns = []

        with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), console=console) as progress:
            task = progress.add_task("[cyan]Scanning network layers...", total=len(ans))
            
            for _, rcv in ans:
                ip, mac = rcv.psrc, rcv.hwsrc
                vendor = get_vendor(mac)
                vuln_flag = "[dim]N/A[/dim]"
                
                if do_intel:
                    progress.update(task, description=f"[yellow]Analysing {ip}...")
                    os_type = get_os_guess(ip)
                    # Use Port 80 as a test case for banner grabbing
                    banner = grab_banner(ip, 80)
                    cves = lookup_cves(banner)
                    if cves:
                        vuln_flag = f"[bold red]YES ({len(cves)})[/bold red]"
                        discovered_vulns.append((banner, cves))
                    table.add_row(ip, os_type, vendor, vuln_flag, mac)
                else:
                    table.add_row(ip, "[dim]N/A[/dim]", vendor, "[dim]N/A[/dim]", mac)
                progress.advance(task)

        console.print(table)
        
        # Display CVE details if found
        for service, cves in discovered_vulns:
            display_vulnerabilities(service, cves)

    except Exception as e:
        console.print(f"[bold red]Critical Error:[/bold red] {e}")

    console.print("\n[bold white]Press Enter to return to Command Center...[/bold white]", end="")
    input()