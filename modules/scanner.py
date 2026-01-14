import socket
import threading
import warnings
import requests
from scapy.all import ARP, Ether, srp, IP, ICMP, sr1, conf
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
from concurrent.futures import ThreadPoolExecutor
from core.ui import draw_header

# Suppress Scapy warnings for a cleaner TUI experience across OSs
warnings.filterwarnings("ignore", category=UserWarning, module='scapy')
console = Console()

# Top 20 most common ports for deep service discovery
COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143,
                443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080, 8443]


def get_vendor(mac):
    """Identifies manufacturer via MAC OUI using a public API."""
    try:
        url = f"https://api.macvendors.com/{mac}"
        response = requests.get(url, timeout=1)
        if response.status_code == 200:
            return response.text
    except:
        pass
    return "Unknown"


def get_os_intel(ip):
    """
    Stealth OS Fingerprinting via TTL (Time To Live) signatures.
    Works cross-platform to distinguish between Windows and Linux/Unix.
    """
    try:
        # Send a single ICMP packet to check TTL
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


def ping_host(ip):
    """Sends an ICMP Echo Request to wake up sleeping devices (e.g., cellphones)."""
    try:
        # Use a short timeout to keep the sweep fast
        sr1(IP(dst=ip)/ICMP(), timeout=0.5, verbose=0)
    except:
        pass


def scan_service(ip, port):
    """Attempts to grab a service banner to identify what is running on a port."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.7)
            if s.connect_ex((ip, port)) == 0:
                # Basic banner grab
                s.send(b"\r\n")
                banner = s.recv(512).decode().strip()
                return f"P{port}: {banner[:20]}..." if banner else f"P{port}: Open"
    except:
        pass
    return None


def network_discovery():
    draw_header("Root Discovery & Deep Intelligence")

    # Detect local subnet hints based on the active interface
    try:
        local_ip = get_if_addr(conf.iface)
        subnet_hint = ".".join(local_ip.split('.')[:-1]) + ".0/24"
        console.print(
            f"[dim]Active Interface: {conf.iface} | Suggested Subnet: {subnet_hint}[/dim]")
    except:
        subnet_hint = "192.168.1.0/24"

    ip_range = console.input(
        f"[bold yellow]Enter IP Range (Default {subnet_hint}): [/bold yellow]").strip() or subnet_hint
    do_deep_scan = console.input(
        "[bold cyan]Perform Deep Service Discovery (Slower)? (y/N): [/bold cyan]").lower() == 'y'

    # Prepare results table
    table = Table(
        title=f"Infrastructure Intel: {ip_range}", border_style="bold red", expand=True)
    table.add_column("IP Address", style="cyan", no_wrap=True)
    table.add_column("OS / Vendor", style="white")
    table.add_column("Services/Vulnerabilities", style="bold yellow")
    table.add_column("MAC Address", style="magenta")

    try:
        with Progress(SpinnerColumn(), TextColumn("{task.description}"), console=console) as progress:
            # STEP 1: Ping Sweep (Wake-on-LAN)
            # This is critical for finding mobile devices that go into sleep mode
            progress.add_task(
                "[cyan]Waking up sleeping devices (ICMP Sweep)...", total=None)
            ips_to_ping = []
            if "/" in ip_range:
                # Basic expansion for /24 networks
                base = ".".join(ip_range.split('.')[:-1])
                ips_to_ping = [f"{base}.{i}" for i in range(1, 255)]
            else:
                ips_to_ping = [ip_range]

            with ThreadPoolExecutor(max_workers=50) as executor:
                executor.map(ping_host, ips_to_ping)

            # STEP 2: ARP Discovery
            task_scan = progress.add_task(
                "[yellow]Scanning for active hosts...", total=None)
            ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") /
                         ARP(pdst=ip_range), timeout=2, verbose=False)

            # STEP 3: Analysis and Service Mapping
            for _, rcv in ans:
                ip, mac = rcv.psrc, rcv.hwsrc
                progress.update(
                    task_scan, description=f"[magenta]Analyzing {ip}...")

                vendor = get_vendor(mac)
                os_type = get_os_intel(ip)

                service_info = "Scan Skipped"
                if do_deep_scan:
                    found_services = []
                    # Multi-threaded port scan for current host
                    with ThreadPoolExecutor(max_workers=10) as executor:
                        results = list(executor.map(
                            lambda p: scan_service(ip, p), COMMON_PORTS))
                        found_services = [r for r in results if r]

                    service_info = "\n".join(
                        found_services) if found_services else "No Open Ports"

                table.add_row(ip, f"{os_type}\n({vendor})", service_info, mac)

        console.print("\n", table)
    except Exception as e:
        console.print(f"[bold red][!] Scan Failed:[/bold red] {e}")

    input("\nPress Enter to return to menu...")
