import asyncio
import socket
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

    async def scan_port(self, ip, port, sem, progress, task_id):
        """Asynchronously attempts a TCP connection and grabs banners."""
        async with sem:
            try:
                # Fast Async TCP Connection
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(ip, port), timeout=1.5
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
                    self.results[ip] = []

                svc_str = f"[bold green]{port}/tcp open[/bold green]"
                if banner:
                    svc_str += f" [dim]({banner[:50]})[/dim]"
                self.results[ip].append(svc_str)

            except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
                # Port is closed or filtered
                pass
            finally:
                progress.advance(task_id)

    async def run_scan(self, target_cidr, ports):
        """Orchestrates the massive async task pool."""
        ips = [str(ip) for ip in IPNetwork(target_cidr)]
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
        draw_header("Asynchronous Mass-Scanner (Next-Gen)")

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

        console.print(
            f"[*] Initiating Async TCP Connect Scan against {target}...")

        try:
            # Drop into the async event loop
            asyncio.run(self.run_scan(target, scan_ports))
        except KeyboardInterrupt:
            console.print(
                "[yellow][!] Scan interrupted by user. Processing gathered data...[/yellow]")

        if not self.results:
            console.print(
                "[red][!] No open ports or active hosts discovered.[/red]")
            questionary.press_any_key_to_continue(style=Q_STYLE).ask()
            return

        table = Table(
            title=f"Async Discovery Results: {target}", border_style="bold red", expand=True)
        table.add_column("Host IP", style="cyan")
        table.add_column("Discovered Services & Banners", style="white")

        for ip, services in self.results.items():
            svc_output = "\n".join(services)
            table.add_row(ip, svc_output)

            # Log findings to the centralized Davoid database
            clean_log = svc_output.replace("[bold green]", "").replace(
                "[/bold green]", "").replace("[dim]", "").replace("[/dim]", "")
            db.log("Async-Scanner", ip, f"Services:\n{clean_log}", "INFO")

        console.print(table)
        console.print(
            f"[bold green][+] Total active hosts discovered: {len(self.results)}[/bold green]")
        questionary.press_any_key_to_continue(style=Q_STYLE).ask()


def network_discovery():
    AsyncScannerEngine().network_discovery()


if __name__ == "__main__":
    network_discovery()
