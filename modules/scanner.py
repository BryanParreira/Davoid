import asyncio
import socket
import os
import questionary
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich.panel import Panel
from netaddr import IPNetwork
from core.ui import draw_header, Q_STYLE
from core.database import db

console = Console()

# Expanded common ports for professional enumeration
TOP_PORTS = [21, 22, 23, 25, 53, 80, 88, 110, 111, 135, 139, 143, 389, 443, 445,
             464, 593, 636, 993, 995, 1433, 1723, 3306, 3389, 5432, 5900, 8000, 8080, 8443]


class AsyncScannerEngine:
    def __init__(self):
        self.results = {}
        self.concurrency_limit = 500

    def os_fingerprint(self, ip, banners):
        """Deduces OS via Passive Banner Grabbing and Active Scapy TTL analysis."""
        # 1. Passive Banner Analysis (Works without root)
        banner_text = " ".join(banners).lower()
        if any(x in banner_text for x in ['ubuntu', 'debian', 'centos', 'linux', 'openssh']):
            return "Linux/Unix"
        if any(x in banner_text for x in ['windows', 'iis', 'microsoft', 'win32', 'smb']):
            return "Windows"

        # 2. Active TTL Analysis (Requires Root / Sudo)
        if os.getuid() == 0:
            try:
                import logging
                logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
                from scapy.all import sr1, IP, ICMP

                # Send a single ICMP ping and analyze the Time-To-Live (TTL) of the response
                pkt = sr1(IP(dst=ip)/ICMP(), timeout=0.5, verbose=0)
                if pkt:
                    ttl = pkt.ttl
                    if ttl <= 64:
                        return "Linux/Unix"
                    elif ttl <= 128:
                        return "Windows"
                    else:
                        return "Network Device (Router/Switch)"
            except Exception:
                pass

        return "Unknown"

    async def scan_port(self, ip, port, sem, progress, task_id):
        """Asynchronously attempts a TCP connection and grabs banners."""
        async with sem:
            try:
                # Fast Async TCP Connection
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(ip, port), timeout=1.0
                )

                banner = ""
                # Active Banner Grabbing for HTTP-based services
                if port in [80, 8080, 443, 8443]:
                    writer.write(b"HEAD / HTTP/1.1\r\nHost: target\r\n\r\n")
                    await writer.drain()

                try:
                    # Wait briefly for a response banner
                    data = await asyncio.wait_for(reader.read(1024), timeout=1.0)
                    if data:
                        banner = data.decode(
                            'utf-8', errors='ignore').split('\n')[0].strip()
                except Exception:
                    pass

                writer.close()
                await writer.wait_closed()

                # Record successful connection
                if ip not in self.results:
                    self.results[ip] = {"ports": [], "raw_banners": []}

                svc_str = f"[bold green]{port}/tcp open[/bold green]"
                if banner:
                    svc_str += f" [dim]({banner[:50]})[/dim]"
                    self.results[ip]["raw_banners"].append(banner)

                self.results[ip]["ports"].append(svc_str)

            except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
                # Port is closed or filtered
                pass
            finally:
                progress.advance(task_id)

    async def run_scan(self, target_cidr, ports):
        """Orchestrates the massive async task pool."""
        try:
            # Using iter_hosts() removes the Network (.0) and Broadcast (.255) addresses. Fixes "Weird IPs".
            ips = [str(ip) for ip in IPNetwork(target_cidr).iter_hosts()]
            # Fallback for single IP targets (e.g. /32)
            if not ips:
                ips = [str(ip) for ip in IPNetwork(target_cidr)]
        except Exception:
            ips = [target_cidr]

        sem = asyncio.Semaphore(self.concurrency_limit)
        total_tasks = len(ips) * len(ports)
        tasks = []

        with Progress(SpinnerColumn(), TextColumn("{task.description}"), BarColumn(), console=console) as progress:
            scan_task = progress.add_task(
                f"[cyan]Asynchronous Scanning {len(ips)} hosts...", total=total_tasks)

            for ip in ips:
                for port in ports:
                    tasks.append(asyncio.create_task(
                        self.scan_port(ip, port, sem, progress, scan_task)))

            # Execute all tasks concurrently up to the semaphore limit
            await asyncio.gather(*tasks)

    def network_discovery(self):
        draw_header("Asynchronous Mass-Scanner & Fingerprinter")

        target = questionary.text(
            "Target (IP or Subnet, e.g., 192.168.1.0/24):", default="192.168.1.0/24", style=Q_STYLE).ask()
        if not target:
            return

        port_mode = questionary.select(
            "Scan Profile:",
            choices=["Fast (Top 30)", "Full (1-1024)", "Custom"],
            style=Q_STYLE
        ).ask()

        scan_ports = TOP_PORTS
        if "Full" in port_mode:
            scan_ports = list(range(1, 1025))
        elif "Custom" in port_mode:
            p = questionary.text(
                "Ports (comma separated, e.g., 80,443,3389):", style=Q_STYLE).ask()
            scan_ports = [int(x.strip()) for x in p.split(",")]

        intensity = questionary.select(
            "Concurrency Limit (Simultaneous Connections):",
            choices=["Stealth (50)", "Balanced (500)",
                     "Aggressive (2000 - High Bandwidth)"],
            default="Balanced (500)",
            style=Q_STYLE
        ).ask()

        if "Stealth" in intensity:
            self.concurrency_limit = 50
        elif "Aggressive" in intensity:
            self.concurrency_limit = 2000
        else:
            self.concurrency_limit = 500

        console.print(f"[*] Initiating Async Connect Scan against {target}...")

        try:
            # Drop into the async event loop
            asyncio.run(self.run_scan(target, scan_ports))
        except KeyboardInterrupt:
            console.print(
                "[yellow][!] Scan interrupted by user. Processing gathered data...[/yellow]")

        # Anomaly Filtering (Fixes fake "always on" IPs caused by firewalls/ISPs)
        filtered_results = {}
        for ip, data in self.results.items():
            # If an IP has 80% of all scanned ports open, it is definitely a firewall tricking us.
            if len(data["ports"]) > len(scan_ports) * 0.8 and len(scan_ports) > 10:
                console.print(
                    f"[yellow][!] Ignoring {ip}: Appears to be a firewall/tarpit (all ports reporting open).[/yellow]")
            else:
                filtered_results[ip] = data

        if not filtered_results:
            console.print(
                "[red][!] No valid open ports or active hosts discovered.[/red]")
            questionary.press_any_key_to_continue(style=Q_STYLE).ask()
            return

        table = Table(
            title=f"Async Discovery Results: {target}", border_style="bold red", expand=True)
        table.add_column("Host IP", style="cyan", justify="center")
        table.add_column("OS Detected", style="magenta", justify="center")
        table.add_column("Discovered Services & Banners", style="white")

        with console.status("[bold cyan]Analyzing Operating Systems...[/bold cyan]"):
            for ip, data in filtered_results.items():
                svc_output = "\n".join(data["ports"])

                # Determine the OS
                os_type = self.os_fingerprint(ip, data["raw_banners"])

                table.add_row(ip, os_type, svc_output)

                # Log findings to the centralized Davoid database
                clean_log = svc_output.replace("[bold green]", "").replace(
                    "[/bold green]", "").replace("[dim]", "").replace("[/dim]", "")
                db.log("Async-Scanner", ip,
                       f"OS: {os_type}\nServices:\n{clean_log}", "INFO")

        console.print(table)
        console.print(
            f"[bold green][+] Total active hosts discovered: {len(filtered_results)}[/bold green]")

        # OS Fingerprinting Accuracy Warning
        if os.getuid() != 0:
            console.print(
                "[dim]Note: Run Davoid with 'sudo' to enable highly accurate TTL-based OS Fingerprinting.[/dim]")

        questionary.press_any_key_to_continue(style=Q_STYLE).ask()


def network_discovery():
    AsyncScannerEngine().network_discovery()


if __name__ == "__main__":
    network_discovery()
