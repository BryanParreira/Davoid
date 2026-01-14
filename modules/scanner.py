import socket
import threading
import warnings
import requests
from scapy.all import ARP, Ether, srp, IP, sr1, ICMP
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
from concurrent.futures import ThreadPoolExecutor
from core.ui import draw_header

warnings.filterwarnings("ignore", category=UserWarning, module='scapy')
console = Console()

COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 139, 443, 445, 3306, 3389, 8080]


def get_vendor(mac):
    try:
        url = f"https://api.macvendors.com/{mac}"
        response = requests.get(url, timeout=1)
        return response.text if response.status_code == 200 else "Unknown"
    except:
        return "Unknown"


def get_os_intel(ip):
    try:
        pkt = sr1(IP(dst=ip)/ICMP(), timeout=1, verbose=0)
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


def scan_service(ip, port):
    """Attempts to grab a service banner for version detection."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1)
            if s.connect_ex((ip, port)) == 0:
                s.send(b"HELP\r\n")  # Generic trigger
                banner = s.recv(1024).decode().strip()
                return f"Port {port}: {banner[:30]}" if banner else f"Port {port}: Open"
    except:
        pass
    return None


def network_discovery():
    draw_header("Root Discovery & Deep Intelligence")

    target_range = console.input(
        "[bold yellow]Enter IP Range (e.g. 192.168.1.0/24): [/bold yellow]").strip()
    if not target_range:
        return

    table = Table(
        title=f"Infrastructure Intel: {target_range}", border_style="bold red")
    table.add_column("IP Address", style="cyan")
    table.add_column("OS/Vendor", style="white")
    table.add_column("Discovered Services", style="bold yellow")
    table.add_column("MAC Address", style="magenta")

    try:
        ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") /
                     ARP(pdst=target_range), timeout=2, verbose=False)

        with Progress(SpinnerColumn(), TextColumn("{task.description}"), console=console) as progress:
            task = progress.add_task(
                "[cyan]Mapping Network...", total=len(ans))

            for _, rcv in ans:
                ip, mac = rcv.psrc, rcv.hwsrc
                vendor = get_vendor(mac)
                os_type = get_os_intel(ip)

                # Multi-threaded Service Scanning
                services = []
                with ThreadPoolExecutor(max_workers=10) as executor:
                    futures = [executor.submit(scan_service, ip, p)
                               for p in COMMON_PORTS]
                    for f in futures:
                        res = f.result()
                        if res:
                            services.append(res)

                service_str = "\n".join(
                    services) if services else "No Common Ports"
                table.add_row(ip, f"{os_type}\n({vendor})", service_str, mac)
                progress.update(task, advance=1)

        console.print(table)
    except Exception as e:
        console.print(f"[red]Scan Failed: {e}[/red]")
    input("\nPress Enter...")
