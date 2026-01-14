import socket
import threading
import warnings
import requests
from scapy.all import ARP, Ether, srp, IP, ICMP, TCP, sr, sr1, conf, get_if_addr
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from concurrent.futures import ThreadPoolExecutor, as_completed
from netaddr import IPNetwork
from core.ui import draw_header

# Suppress Scapy IPv6 and Layer 2 warnings
warnings.filterwarnings("ignore", category=UserWarning, module='scapy')
console = Console()

# Professional VulnDB Mapping
VULN_DB = {
    "vsFTPd 2.3.4": "CVE-2011-2523 (Backdoor)",
    "Apache/2.4.49": "CVE-2021-41773 (Path Traversal)",
    "OpenSSH_7.2p2": "CVE-2016-6210 (User Enum)",
    "SMBv1": "WannaCry/EternalBlue Risk",
    "IIS/6.0": "CVE-2017-7269 (RCE)"
}

# Top 50 Productive Ports for quick auditing
TOP_PORTS = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139,
             143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080]


class ScannerEngine:
    def __init__(self):
        self.results = []
        self.lock = threading.Lock()

    def get_vendor(self, mac):
        """Identifies manufacturer via MAC OUI."""
        try:
            url = f"https://api.macvendors.com/{mac}"
            res = requests.get(url, timeout=1.5)
            return res.text if res.status_code == 200 else "Unknown"
        except:
            return "Unknown"

    def service_audit(self, ip, port):
        """mimics nmap -sV banner grabbing."""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(1.2)
                if s.connect_ex((ip, port)) == 0:
                    if port in [80, 443, 8080]:
                        s.send(b"GET / HTTP/1.1\r\nHost: davoid\r\n\r\n")
                    else:
                        s.send(b"\r\n")

                    banner = s.recv(1024).decode(
                        'utf-8', errors='ignore').strip()
                    if banner:
                        for version, cve in VULN_DB.items():
                            if version.lower() in banner.lower():
                                return f"[bold red]VULN: {cve}[/bold red]"
                        return banner.replace('\n', ' ')[:30]
                    return "Open"
        except:
            pass
        return None

    def stealth_probe(self, ip):
        """TCP SYN Discovery to find hidden mobile devices."""
        syn_pkt = IP(dst=ip)/TCP(dport=[80, 443, 22], flags="S")
        ans, _ = sr(syn_pkt, timeout=0.6, verbose=0)
        if ans:
            return True
        return sr1(IP(dst=ip)/ICMP(), timeout=0.6, verbose=0) is not None

    def network_discovery(self):
        draw_header("Root Discovery & Deep Intelligence")

        try:
            local_ip = get_if_addr(conf.iface)
            subnet_hint = str(IPNetwork(f"{local_ip}/24").cidr)
            console.print(
                f"[dim]Interface: {conf.iface} | Target: {subnet_hint}[/dim]")
        except:
            subnet_hint = "192.168.1.0/24"

        target = console.input(
            f"[bold yellow]Scan Range (Default {subnet_hint}): [/bold yellow]").strip() or subnet_hint
        do_deep = console.input(
            "[bold cyan]Deep Service Fingerprinting (-sV)? (y/N): [/bold cyan]").lower() == 'y'

        table = Table(
            title=f"Elite Intel: {target}", border_style="bold red", expand=True)
        table.add_column("Host (IP)", style="cyan")
        table.add_column("OS/Vendor", style="white")
        table.add_column("Services/Vulns", style="bold yellow")
        table.add_column("MAC Address", style="magenta")

        active_hosts = []
        with Progress(SpinnerColumn(), TextColumn("{task.description}"), BarColumn(), console=console) as progress:
            # 1. ARP Discovery
            task1 = progress.add_task("[cyan]L2 ARP Mapping...", total=None)
            ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") /
                         ARP(pdst=target), timeout=2, verbose=False)
            for _, rcv in ans:
                active_hosts.append((rcv.psrc, rcv.hwsrc))

            # 2. SYN Sweep for silent hosts
            task2 = progress.add_task(
                "[yellow]Stealth discovery (SYN Sweep)...", total=None)
            ip_list = [str(ip) for ip in IPNetwork(target)]
            with ThreadPoolExecutor(max_workers=50) as executor:
                futures = {executor.submit(
                    self.stealth_probe, ip): ip for ip in ip_list}
                for f in as_completed(futures):
                    ip = futures[f]
                    if f.result() and not any(h[0] == ip for h in active_hosts):
                        res, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") /
                                     ARP(pdst=ip), timeout=1, verbose=False)
                        active_hosts.append(
                            (ip, res[0][1].hwsrc if res else "Unknown"))

            # 3. Final Analysis
            task3 = progress.add_task(
                f"[magenta]Analyzing {len(active_hosts)} live hosts...", total=len(active_hosts))
            for ip, mac in active_hosts:
                vendor = self.get_vendor(mac)

                # OS Detection via TTL
                os_type = "Unknown"
                pkt = sr1(IP(dst=ip)/ICMP(), timeout=0.5, verbose=0)
                if pkt:
                    ttl = pkt.getlayer(IP).ttl
                    os_type = "Linux/IoT" if ttl <= 64 else "Windows" if ttl <= 128 else "Network"

                svc_info = []
                if do_deep:
                    with ThreadPoolExecutor(max_workers=10) as executor:
                        results = list(executor.map(
                            lambda p: self.service_audit(ip, p), TOP_PORTS))
                        svc_info = [r for r in results if r]

                table.add_row(ip, f"{os_type}\n({vendor})", "\n".join(
                    svc_info) if svc_info else "Filtered", mac)
                progress.update(task3, advance=1)

        console.print("\n", table)
        input("\nPress Enter...")


def network_discovery():
    engine = ScannerEngine()
    engine.network_discovery()
