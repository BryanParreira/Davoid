import socket
import threading
import warnings
import requests
import time
import random
from scapy.all import ARP, Ether, srp, IP, ICMP, TCP, sr, sr1, conf, get_if_addr
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
from rich.panel import Panel
from rich.prompt import Prompt, Confirm
from concurrent.futures import ThreadPoolExecutor, as_completed
from netaddr import IPNetwork
from core.ui import draw_header

# Suppress Scapy IPv6 and Layer 2 warnings for a cleaner output
warnings.filterwarnings("ignore", category=UserWarning, module='scapy')
console = Console()

# Professional VulnDB Mapping for Banner Grabbing
VULN_DB = {
    "vsFTPd 2.3.4": "CVE-2011-2523 (Backdoor)",
    "Apache/2.4.49": "CVE-2021-41773 (Path Traversal)",
    "OpenSSH_7.2p2": "CVE-2016-6210 (User Enum)",
    "SMBv1": "WannaCry/EternalBlue Risk",
    "IIS/6.0": "CVE-2017-7269 (RCE)",
    "Werkzeug": "Potential Debugger RCE",
    "HFS 2.3": "CVE-2014-6287 (RCE)"
}

# Auditing common high-value ports
TOP_PORTS = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139,
             143, 443, 445, 993, 995, 1723, 3306, 3389, 5432, 5900, 8000, 8080, 8443]


class ScannerEngine:
    def __init__(self):
        self.results = []
        self.vendor_cache = {}  # Prevent repeated API calls
        self.lock = threading.Lock()
        self.stealth_delay = 0  # Default to no delay

    def get_vendor(self, mac):
        """Identifies manufacturer via MAC OUI with local caching."""
        if mac in self.vendor_cache:
            return self.vendor_cache[mac]

        if mac == "Unknown" or ":" not in mac:
            return "Unknown"

        try:
            url = f"https://api.macvendors.com/{mac}"
            res = requests.get(url, timeout=2)
            vendor = res.text if res.status_code == 200 else "Unknown"
            self.vendor_cache[mac] = vendor
            return vendor
        except:
            return "Unknown"

    def os_fingerprint(self, ip):
        """Advanced OS Fingerprinting using TTL and TCP Window behavior."""
        try:
            # Add randomized jitter to the probe timing for stealth
            if self.stealth_delay > 0:
                time.sleep(random.uniform(0.1, self.stealth_delay))

            # Probe common ports to elicit a TCP response
            pkt = sr1(
                IP(dst=ip)/TCP(dport=[80, 443, 22, 445], flags="S"), timeout=1, verbose=0)

            if pkt and pkt.haslayer(TCP):
                ttl = pkt.getlayer(IP).ttl
                window = pkt.getlayer(TCP).window

                # TTL + Window Size Analysis (Nmap-style heuristics)
                if ttl <= 64:
                    if window == 5840 or window == 29200:
                        return "Linux (Kernel 2.6+ / 3.x)"
                    if window <= 1024:
                        return "iOS / Apple Embedded"
                    return "Linux / IoT / Android"
                elif ttl <= 128:
                    if window == 8192:
                        return "Windows 7 / 10 / Server"
                    if window == 65535:
                        return "Windows XP / 2003"
                    return "Windows (Generic)"
                elif ttl <= 255:
                    return "Network Device (Cisco/Solaris/FreeBSD)"

            # Fallback to ICMP TTL discovery if TCP fails
            pkt_icmp = sr1(IP(dst=ip)/ICMP(), timeout=0.8, verbose=0)
            if pkt_icmp:
                ttl = pkt_icmp.getlayer(IP).ttl
                if ttl <= 64:
                    return "Linux / IoT (ICMP Guess)"
                elif ttl <= 128:
                    return "Windows (ICMP Guess)"
                else:
                    return "Network Infrastructure"
        except:
            pass
        return "Unknown / Shielded"

    def service_audit(self, ip, port):
        """Performs banner grabbing and matches against VULN_DB."""
        try:
            # Stealth: Randomized delay before banner grabbing
            if self.stealth_delay > 0:
                time.sleep(random.uniform(0.5, self.stealth_delay * 2))

            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(1.5)
                if s.connect_ex((ip, port)) == 0:
                    if port in [80, 8080, 8000]:
                        s.send(b"GET / HTTP/1.1\r\nHost: davoid\r\n\r\n")
                    elif port == 443:
                        s.send(b"\r\n")
                    else:
                        s.send(b"\r\n")

                    banner = s.recv(1024).decode(
                        'utf-8', errors='ignore').strip()
                    if banner:
                        for version, cve in VULN_DB.items():
                            if version.lower() in banner.lower():
                                return f"[bold red]{port}: {version} -> {cve}[/bold red]"

                        clean_banner = banner.split(
                            '\n')[0].replace('\r', '')[:35]
                        return f"[green]{port}:[/green] {clean_banner}"
                    return f"[green]{port}:[/green] Open"
        except:
            pass
        return None

    def stealth_probe(self, ip):
        """TCP SYN Discovery to find hosts that block ICMP (Stealth)."""
        # Stealth: Half-open scan avoids establishing full TCP sessions
        syn_pkt = IP(dst=ip)/TCP(dport=[80, 443, 22, 53], flags="S")
        ans, _ = sr(syn_pkt, timeout=0.8, verbose=0)
        if ans:
            return True
        return sr1(IP(dst=ip)/ICMP(), timeout=0.8, verbose=0) is not None

    def network_discovery(self):
        draw_header("Root Discovery & Deep Intelligence")

        # --- Dynamic Variable Configuration ---
        try:
            local_ip = get_if_addr(conf.iface)
            subnet_hint = str(IPNetwork(f"{local_ip}/24").cidr)
            console.print(Panel(
                f"Interface: [bold cyan]{conf.iface}[/bold cyan] | Local IP: [bold cyan]{local_ip}[/bold cyan]\nDefault Subnet: [bold cyan]{subnet_hint}[/bold cyan]",
                title="Network Context", border_style="dim"))
        except:
            subnet_hint = "192.168.1.0/24"

        # User Input for Scan Variables
        target = Prompt.ask(
            "[bold yellow]Scan Range[/bold yellow]", default=subnet_hint).strip()

        port_choice = Prompt.ask(
            "[bold yellow]Ports to audit[/bold yellow]",
            choices=["common", "all", "custom"],
            default="common"
        )

        if port_choice == "all":
            scan_ports = list(range(1, 1025))
        elif port_choice == "custom":
            custom_input = console.input(
                "[bold cyan]Enter ports (e.g. 80,443,8080): [/bold cyan]")
            scan_ports = [int(p.strip()) for p in custom_input.split(",")]
        else:
            scan_ports = TOP_PORTS

        intensity = int(Prompt.ask(
            "[bold yellow]Scan Intensity (Threads)[/bold yellow]", default="40"))

        # --- NEW STEALTH CONFIGURATION ---
        stealth_mode = Confirm.ask(
            "[bold magenta]Enable Stealth Timing (Slow/Safe Scan)?[/bold magenta]", default=False)
        if stealth_mode:
            self.stealth_delay = float(Prompt.ask(
                "[bold magenta]Max Delay between packets (seconds)[/bold magenta]", default="2.0"))
            # Force low thread count for stealth
            intensity = min(intensity, 10)
            console.print(
                "[dim magenta][*] Stealth Active: Throttling scan to 10 threads max.[/dim magenta]")

        do_deep = Confirm.ask(
            "[bold cyan]Enable Deep Service Fingerprinting? (-sV)[/bold cyan]", default=False)

        active_hosts = []

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TimeElapsedColumn(),
            console=console
        ) as progress:

            # Phase 1: Layer 2 ARP Mapping
            task1 = progress.add_task(
                "[cyan]L2 ARP Mapping (Subnet Discovery)...", total=None)
            ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") /
                         ARP(pdst=target), timeout=2, verbose=False)
            for _, rcv in ans:
                active_hosts.append({"ip": rcv.psrc, "mac": rcv.hwsrc})
            progress.update(task1, completed=100,
                            description="[cyan]ARP Discovery Finished.")

            # Phase 2: Stealth SYN Sweep for hidden hosts
            ip_list = [str(ip) for ip in IPNetwork(target)]
            task2 = progress.add_task(
                "[yellow]Stealth Scanning (SYN Sweep)...", total=len(ip_list))

            with ThreadPoolExecutor(max_workers=intensity) as executor:
                futures = {executor.submit(
                    self.stealth_probe, ip): ip for ip in ip_list}
                for f in as_completed(futures):
                    ip = futures[f]
                    progress.update(task2, advance=1)
                    if f.result() and not any(h["ip"] == ip for h in active_hosts):
                        res, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") /
                                     ARP(pdst=ip), timeout=1, verbose=False)
                        mac = res[0][1].hwsrc if res else "Unknown"
                        active_hosts.append({"ip": ip, "mac": mac})

            # Phase 3: Intelligence & Service Fingerprinting
            table = Table(
                title=f"Elite Intel: {target}", border_style="bold red", expand=True)
            table.add_column("Host (IP)", style="cyan", no_wrap=True)
            table.add_column("OS Fingerprint", style="bold magenta")
            table.add_column("Services & Vulnerabilities", style="bold yellow")
            table.add_column("MAC / Vendor", style="dim")

            task3 = progress.add_task(
                f"[magenta]Analyzing {len(active_hosts)} live hosts...", total=len(active_hosts))

            for host in active_hosts:
                ip = host["ip"]
                mac = host["mac"]
                vendor = self.get_vendor(mac)

                # Advanced OS Detection
                os_type = self.os_fingerprint(ip)

                svc_info = []
                if do_deep:
                    with ThreadPoolExecutor(max_workers=15) as executor:
                        futures = [executor.submit(
                            self.service_audit, ip, p) for p in scan_ports]
                        for f in as_completed(futures):
                            res = f.result()
                            if res:
                                svc_info.append(res)

                table.add_row(
                    ip,
                    os_type,
                    "\n".join(
                        svc_info) if svc_info else "[dim]None Detected[/dim]",
                    f"{mac}\n[white]{vendor}[/white]"
                )
                progress.update(task3, advance=1)

        console.print("\n", table)
        console.print(
            f"[bold green][+] Total Active Hosts Found: {len(active_hosts)}[/bold green]")
        input("\nPress Enter to return to main menu...")


def network_discovery():
    engine = ScannerEngine()
    engine.network_discovery()


if __name__ == "__main__":
    network_discovery()
