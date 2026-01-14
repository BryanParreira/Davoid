import os
import shutil
import subprocess
import socket
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from scapy.all import conf, Dot11, RadioTap, sendp
from core.ui import draw_header

console = Console()


class DavoidAuditor:
    def __init__(self):
        self.results = []
        self.interfaces = []
        self.is_root = os.geteuid() == 0

    def check_cmd(self, cmd):
        return shutil.which(cmd) is not None

    def get_driver_info(self, iface):
        """Extracts the kernel driver for a specific interface."""
        try:
            path = f"/sys/class/net/{iface}/device/driver"
            return os.path.basename(os.readlink(path))
        except:
            return "Unknown"

    def test_injection(self, iface):
        """Performs a live packet injection test using Scapy."""
        if not self.is_root:
            return "[bold red]Permission Denied[/bold red]"

        try:
            # Craft a dummy probe request
            packet = RadioTap() / Dot11(type=0, subtype=4, addr1="ff:ff:ff:ff:ff:ff",
                                        addr2="00:11:22:33:44:55", addr3="ff:ff:ff:ff:ff:ff")
            sendp(packet, iface=iface, count=5, verbose=False)
            return "[bold green]Success[/bold green]"
        except Exception:
            return "[bold yellow]Failed/Unsupported[/bold yellow]"

    def get_wifi_state(self, iface):
        """Advanced verification of hardware state via iw."""
        if not self.check_cmd("iw"):
            return "Unknown", "Install 'iw'"

        try:
            output = subprocess.check_output(
                ["iw", "dev", iface, "info"], stderr=subprocess.DEVNULL).decode()
            driver = self.get_driver_info(iface)

            if "type monitor" in output.lower():
                inj = self.test_injection(iface)
                return f"[bold green]Monitor[/bold green] ({driver})", f"Inj: {inj}"
            else:
                return f"[bold cyan]Managed[/bold cyan] ({driver})", "Switch to Monitor mode"
        except:
            return "[bold red]Error[/bold red]", "Check Hardware"

    def run(self):
        draw_header("Davoid Advanced System Auditor")

        table = Table(title="Production Environment Audit",
                      border_style="bold cyan", expand=True)
        table.add_column("Category", style="cyan", no_wrap=True)
        table.add_column("Component/Interface", style="white")
        table.add_column("Status", style="bold")
        table.add_column("Diagnostics / Action", style="dim")

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            transient=True,
        ) as progress:

            # --- TASK 1: Permissions & Kernel ---
            progress.add_task(
                description="Checking System Privileges...", total=None)
            perm_status = "[bold green]ROOT[/bold green]" if self.is_root else "[bold red]USER[/bold red]"
            perm_rec = "Full Access" if self.is_root else "Sudo required for injection"
            table.add_row("System", "Execution Privilege",
                          perm_status, perm_rec)

            # --- TASK 2: Tooling Dependencies ---
            progress.add_task(
                description="Auditing Dependencies...", total=None)
            deps = {
                "tcpdump": "Packet capture",
                "nmap": "Network discovery",
                "iw": "Interface management",
                "aireplay-ng": "Frame injection",
                "airmon-ng": "Mode switching"
            }
            for dep, reason in deps.items():
                exists = self.check_cmd(dep)
                status = "[bold green]OK[/bold green]" if exists else "[bold red]MISSING[/bold red]"
                action = f"Available" if exists else f"sudo apt install {dep}"
                table.add_row("Dependency", dep, status, action)

            # --- TASK 3: Network & WLAN Analysis ---
            progress.add_task(
                description="Probing Wireless Hardware...", total=None)
            wlan_ifaces = [i.name for i in conf.ifaces.data.values()
                           if any(x in i.name.lower() for x in ["wlan", "wlp", "en"])]

            if not wlan_ifaces:
                table.add_row(
                    "Wireless", "Adapters", "[bold red]NOT FOUND[/bold red]", "Insert USB Wi-Fi card")
            else:
                for iface in wlan_ifaces:
                    status, diag = self.get_wifi_state(iface)
                    table.add_row("Interface", iface, status, diag)

        # Rendering
        console.print(table)

        # Final Critical Logic
        if not self.is_root:
            console.print(Panel(
                "[bold red][!] WARNING:[/bold red] Davoid is running in restricted mode. Monitor Mode and Packet Injection will fail.", border_style="red"))

        if not wlan_ifaces:
            console.print(Panel(
                "[bold yellow][!] NOTE:[/bold yellow] No wireless interfaces detected. Reverting to Ethernet/Socket mode.", border_style="yellow"))

        console.print(
            "\n[bold reverse white] Press Enter to return to Command Center [/bold reverse white]", end="")
        input()


def run_auditor():
    auditor = DavoidAuditor()
    auditor.run()
