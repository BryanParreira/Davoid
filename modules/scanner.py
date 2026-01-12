import socket
import threading
import warnings
from scapy.all import ARP, Ether, srp, IP, sr1
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
from core.ui import draw_header
import requests

# Suppress Scapy IPv6 warnings for a cleaner interface
warnings.filterwarnings("ignore", category=UserWarning, module='scapy')

console = Console()

# --- INTELLIGENCE TOOLS ---

def get_vendor(mac):
    """Identifies device manufacturer via MAC OUI."""
    try:
        url = f"https://api.macvendors.com/{mac}"
        response = requests.get(url, timeout=1)
        if response.status_code == 200:
            return response.text
    except:
        pass
    return "Unknown"

def get_os_guess(ip):
    """
    Stealth OS Fingerprinting via TTL (Time To Live).
    Windows: ~128 | Linux/Unix: ~64 | Network Devices: ~255
    """
    try:
        # Send a single ICMP packet with a short timeout
        pkt = sr1(IP(dst=ip), timeout=1, verbose=0)
        if pkt:
            ttl = pkt.getlayer(IP).ttl
            if ttl <= 64: return "Linux/Unix"
            elif ttl <= 128: return "Windows"
            else: return "Network/Cisco"
    except:
        pass
    return "Unknown"

def scan_port(ip, port, open_ports):
    """Fast TCP connect scan for a single port."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.5)
            if s.connect_ex((ip, port)) == 0:
                open_ports.append(str(port))
    except:
        pass

def get_open_ports(ip):
    """Scans top 10 most critical security ports."""
    common_ports = [21, 22, 23, 25, 80, 139, 443, 445, 3306, 3389]
    open_ports = []
    threads = []
    
    for port in common_ports:
        t = threading.Thread(target=scan_port, args=(ip, port, open_ports))
        t.start()
        threads.append(t)
    
    for t in threads:
        t.join()
        
    return ", ".join(open_ports) if open_ports else "[dim]None[/dim]"

# --- MAIN MODULE ---

def network_discovery():
    draw_header("Root Discovery Mode")
    
    # Improved Interface Detection
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        subnet_hint = ".".join(local_ip.split('.')[:-1]) + ".0/24"
        console.print(f"[dim]Interface IP: {local_ip} | Suggested: {subnet_hint}[/dim]")
    except:
        subnet_hint = "192.168.1.0/24"

    ip_range = console.input(f"[bold yellow]Enter Subnet [[white]{subnet_hint}[/white]]: [/bold yellow]").strip()
    if not ip_range: ip_range = subnet_hint

    do_intel = console.input("[bold cyan]Perform Advanced Intelligence (OS/Ports)? (y/N): [/bold cyan]").lower() == 'y'

    try:
        # Layer 2 Discovery
        packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip_range)
        
        table = Table(
            title=f"Advanced Reconnaissance: {ip_range}", 
            border_style="bold red",
            header_style="bold magenta",
            expand=True
        )
        table.add_column("IP Address", style="cyan")
        table.add_column("OS Guess", style="bold green")
        table.add_column("Vendor", style="white")
        table.add_column("Open Ports", style="bold yellow")
        table.add_column("MAC Address", style="magenta", overflow="fold")

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console
        ) as progress:
            
            task = progress.add_task("[cyan]Scanning network layers...", total=None)
            ans, _ = srp(packet, timeout=2, verbose=False, retry=1)
            
            progress.update(task, description=f"[bold green]Found {len(ans)} hosts. Fingerprinting...")
            
            for _, rcv in ans:
                ip = rcv.psrc
                mac = rcv.hwsrc
                
                vendor = get_vendor(mac)
                
                if do_intel:
                    progress.update(task, description=f"[yellow]Analysing {ip}...")
                    os_type = get_os_guess(ip)
                    ports = get_open_ports(ip)
                    table.add_row(ip, os_type, vendor, ports, mac)
                else:
                    table.add_row(ip, "[dim]N/A[/dim]", vendor, "[dim]N/A[/dim]", mac)

        if ans:
            console.print(table)
            console.print(f"\n[bold green][+] Discovery Complete. Intelligence gathered on {len(ans)} nodes.[/bold green]")
        else:
            console.print("[bold red][!] No response. The network may be isolating your ARP requests.[/bold red]")

    except Exception as e:
        console.print(f"[bold red]Critical Error:[/bold red] {e}")

    input("\n[bold white]Press Enter to return to Command Center...[/bold white]")