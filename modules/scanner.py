import socket
import threading
import warnings
import requests
import time
import random
import questionary
from scapy.all import ARP, Ether, srp, IP, ICMP, TCP, sr, sr1, conf, get_if_addr, send, RandShort
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
from rich.panel import Panel
from concurrent.futures import ThreadPoolExecutor, as_completed
from netaddr import IPNetwork
from core.ui import draw_header, Q_STYLE
from core.database import db  # Database Integration

warnings.filterwarnings("ignore", category=UserWarning, module='scapy')
console = Console()

VULN_DB = {
    "vsFTPd 2.3.4": "CVE-2011-2523 (Backdoor)",
    "Apache/2.4.49": "CVE-2021-41773 (Path Traversal)",
    "OpenSSH_7.2p2": "CVE-2016-6210 (User Enum)",
    "SMBv1": "WannaCry/EternalBlue Risk",
    "IIS/6.0": "CVE-2017-7269 (RCE)",
    "Werkzeug": "Potential Debugger RCE",
    "HFS 2.3": "CVE-2014-6287 (RCE)"
}

TOP_PORTS = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139,
             143, 443, 445, 993, 995, 1723, 3306, 3389, 5432, 5900, 8000, 8080, 8443]

class ScannerEngine:
    def __init__(self):
        self.results = []
        self.vendor_cache = {}
        self.stealth_delay = 0

    def get_vendor(self, mac):
        if mac in self.vendor_cache: return self.vendor_cache[mac]
        if mac == "Unknown" or ":" not in mac: return "Unknown"
        try:
            url = f"https://api.macvendors.com/{mac}"
            res = requests.get(url, timeout=2)
            vendor = res.text if res.status_code == 200 else "Unknown"
            self.vendor_cache[mac] = vendor
            return vendor
        except: return "Unknown"

    def os_fingerprint(self, ip):
        try:
            if self.stealth_delay > 0: time.sleep(random.uniform(0.1, self.stealth_delay))
            pkt = sr1(IP(dst=ip)/TCP(sport=RandShort(), dport=[80, 443, 22, 445], flags="S"), timeout=1, verbose=0)
            if pkt and pkt.haslayer(TCP):
                ttl = pkt.getlayer(IP).ttl
                if ttl <= 64: return "Linux/Unix"
                elif ttl <= 128: return "Windows"
                elif ttl <= 255: return "Network Device"
            if sr1(IP(dst=ip)/ICMP(), timeout=0.8, verbose=0): return "Unknown (ICMP)"
        except: pass
        return "Unknown"

    def service_audit(self, ip, port):
        try:
            if self.stealth_delay > 0: time.sleep(random.uniform(0.5, self.stealth_delay * 2))
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(1.5)
                if s.connect_ex((ip, port)) == 0:
                    if port in [80, 8080, 8000]: s.send(b"GET / HTTP/1.1\r\nHost: davoid\r\n\r\n")
                    else: s.send(b"\r\n")
                    banner = s.recv(1024).decode('utf-8', errors='ignore').strip()
                    if banner:
                        for version, cve in VULN_DB.items():
                            if version.lower() in banner.lower():
                                return f"[bold red]{port}: {version} -> {cve}[/bold red]"
                        return f"[green]{port}:[/green] {banner[:35]}"
                    return f"[green]{port}:[/green] Open"
        except: pass
        return None

    def stealth_probe(self, ip):
        try:
            src_port = RandShort()
            syn_pkt = IP(dst=ip)/TCP(sport=src_port, dport=[80, 443, 22, 53], flags="S")
            ans, _ = sr(syn_pkt, timeout=1.0, verbose=0)
            for sent, received in ans:
                if received.haslayer(TCP) and received.getlayer(TCP).flags == 0x12:
                    send(IP(dst=ip)/TCP(sport=src_port, dport=received.sport, flags="R"), verbose=0)
                    return True
            return False
        except: return False

    def network_discovery(self):
        draw_header("Root Discovery & Deep Intelligence")
        try:
            local_ip = get_if_addr(conf.iface)
            subnet_hint = str(IPNetwork(f"{local_ip}/24").cidr)
        except: subnet_hint = "192.168.1.0/24"

        target = questionary.text("Target Subnet:", default=subnet_hint, style=Q_STYLE).ask()
        port_mode = questionary.select("Scan Profile:", choices=["Fast (Top 20)", "Full (1-1024)", "Custom"], style=Q_STYLE).ask()
        
        scan_ports = TOP_PORTS
        if "Full" in port_mode: scan_ports = list(range(1, 1025))
        elif "Custom" in port_mode:
            p = questionary.text("Ports (e.g. 80,443):", style=Q_STYLE).ask()
            scan_ports = [int(x) for x in p.split(",")]

        intensity = int(questionary.select("Intensity:", choices=["Stealth (10)", "Balanced (40)", "Aggressive (100)"], default="Balanced (40)", style=Q_STYLE).ask().split('(')[1].split(')')[0])
        do_deep = questionary.confirm("Enable Service Fingerprinting?", default=False, style=Q_STYLE).ask()

        active_hosts = []
        with Progress(SpinnerColumn(), TextColumn("{task.description}"), BarColumn(), TimeElapsedColumn(), console=console) as progress:
            
            # 1. ARP Phase
            task1 = progress.add_task("[cyan]L2 Mapping...", total=100)
            ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=target), timeout=2, verbose=False)
            for _, rcv in ans: active_hosts.append({"ip": rcv.psrc, "mac": rcv.hwsrc})
            progress.update(task1, completed=100)

            # 2. SYN Phase
            ip_list = [str(ip) for ip in IPNetwork(target)]
            task2 = progress.add_task("[yellow]SYN Sweep...", total=len(ip_list))
            with ThreadPoolExecutor(max_workers=intensity) as executor:
                futures = {executor.submit(self.stealth_probe, ip): ip for ip in ip_list}
                for f in as_completed(futures):
                    ip = futures[f]
                    progress.update(task2, advance=1)
                    if f.result() and not any(h["ip"] == ip for h in active_hosts):
                         active_hosts.append({"ip": ip, "mac": "Unknown"})

            # 3. Analysis Phase
            table = Table(title=f"Results: {target}", border_style="bold red", expand=True)
            table.add_column("Host", style="cyan")
            table.add_column("OS", style="magenta")
            table.add_column("Services", style="yellow")
            table.add_column("Vendor", style="dim")

            task3 = progress.add_task(f"[magenta]Analyzing...", total=len(active_hosts))
            for host in active_hosts:
                ip, mac = host["ip"], host["mac"]
                vendor = self.get_vendor(mac)
                os_type = self.os_fingerprint(ip)
                svc_info = []
                
                if do_deep:
                    with ThreadPoolExecutor(max_workers=20) as executor:
                        futures = [executor.submit(self.service_audit, ip, p) for p in scan_ports]
                        for f in as_completed(futures):
                            if f.result(): svc_info.append(f.result())
                
                svc_str = "\n".join(svc_info) if svc_info else "None"
                table.add_row(ip, os_type, svc_str, f"{mac}\n{vendor}")
                
                # SAVE TO DB
                db.log("Net-Mapper", ip, f"OS: {os_type} | Vendor: {vendor} | Services: {svc_str}", "INFO")
                
                progress.update(task3, advance=1)

        console.print(table)
        questionary.press_any_key_to_continue(style=Q_STYLE).ask()

def network_discovery():
    ScannerEngine().network_discovery()

if __name__ == "__main__":
    network_discovery()