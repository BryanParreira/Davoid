import re
import os
import threading
import logging
import questionary
from datetime import datetime
from scapy.all import sniff, IP, TCP, UDP, DNS, DNSQR, conf, Raw, wrpcap
from rich.console import Console
from rich.table import Table
from rich.live import Live
from rich.panel import Panel
from core.ui import draw_header, Q_STYLE
from core.database import db # Database Integration

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
console = Console()
session_pcap = []
captured_intel = []
intel_lock = threading.Lock()

class SnifferEngine:
    def __init__(self):
        self.max_entries = 15
        self.pcap_filename = f"logs/capture_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pcap"

    def parse_plaintext_creds(self, load, port):
        decoded = load.decode('utf-8', errors='ignore')
        intel = []
        http_patterns = [r"(?i)(user|username|login|email|pass|password|pwd|auth|token)=([^&^ ^\r^\n]*)"]
        proto_patterns = [r"(?i)USER\s+(.*)\r\n", r"(?i)PASS\s+(.*)\r\n"]

        if port in [80, 8080]:
            for p in http_patterns:
                matches = re.findall(p, decoded)
                for match in matches: intel.append(f"HTTP-DATA: {match[0]}={match[1]}")

        for p in proto_patterns:
            matches = re.findall(p, decoded)
            if matches: intel.append(f"AUTH-PROTO: {matches[0].strip()}")

        return intel

    def callback(self, packet):
        if not packet.haslayer(IP): return
        if len(session_pcap) < 5000: session_pcap.append(packet)

        src, dst = packet[IP].src, packet[IP].dst
        info = []

        if packet.haslayer(DNSQR) and packet.haslayer(DNS) and packet[DNS].qr == 0:
            query = packet[DNSQR].qname.decode().strip('.')
            info.append(f"DNS: {query}")

        elif packet.haslayer(TCP):
            port, sport = packet[TCP].dport, packet[TCP].sport
            if packet.haslayer(Raw):
                load = packet[Raw].load
                creds = self.parse_plaintext_creds(load, port)
                if not creds: creds = self.parse_plaintext_creds(load, sport)
                
                if creds:
                    for c in creds:
                        info.append(f"[bold red]{c}[/bold red]")
                        # SAVE TO DB
                        db.log("Live Interceptor", src, f"Credential Found: {c}", "CRITICAL")
                
                keywords = [b"password", b"passwd", b"secret", b"apikey", b"access_token"]
                if any(kw in load.lower() for kw in keywords):
                    info.append("[bold orange1]Sensitive Keyword[/bold orange1]")
                    db.log("Live Interceptor", src, "Sensitive Keyword detected in stream", "HIGH")

        if info:
            with intel_lock:
                captured_intel.append({
                    "time": datetime.now().strftime("%H:%M:%S"),
                    "src": src, "dst": dst, "intel": " | ".join(info)
                })
                if len(captured_intel) > 100: captured_intel.pop(0)

    def generate_table(self):
        table = Table(title="WLAN Intelligence Stream", expand=True, border_style="cyan")
        table.add_column("Time", style="dim", width=12)
        table.add_column("Source", style="green", width=16)
        table.add_column("Dest", style="blue", width=16)
        table.add_column("Intel", style="white")
        with intel_lock:
            for entry in captured_intel[-self.max_entries:]:
                table.add_row(entry["time"], entry["src"], entry["dst"], entry["intel"])
        return table

    def start(self):
        draw_header("WLAN LIVE INTERCEPTOR")
        iface_list = [i.name for i in conf.ifaces.data.values()]
        target_iface = questionary.select("Select Interface:", choices=iface_list, style=Q_STYLE).ask()
        if not target_iface: target_iface = conf.iface

        if not os.path.exists("logs"): os.makedirs("logs")
        console.print(f"[*] Sniffer Active on [bold green]{target_iface}[/bold green]. Saving critical intel to DB...")

        try:
            with Live(self.generate_table(), refresh_per_second=2, screen=False) as live:
                def wrapped_cb(pkt):
                    self.callback(pkt)
                    live.update(self.generate_table())
                sniff(iface=target_iface, prn=wrapped_cb, store=0, filter="ip")
        except KeyboardInterrupt:
            console.print("\n[yellow][!] Stopped.[/yellow]")
            if session_pcap:
                wrpcap(self.pcap_filename, session_pcap)
                console.print(f"[green]PCAP Saved: {self.pcap_filename}[/green]")

def run_sniffer():
    SnifferEngine().start()

if __name__ == "__main__":
    run_sniffer()