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

# Suppress Scapy warnings for cleaner output
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

console = Console()
session_pcap = []
captured_intel = []
intel_lock = threading.Lock()  # Ensure thread safety for the shared intel list


class SnifferEngine:
    def __init__(self):
        self.max_entries = 15
        self.pcap_filename = f"logs/capture_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pcap"

    def parse_plaintext_creds(self, load, port):
        """
        Multipurpose plaintext credential extractor.
        Covers HTTP, FTP, POP3, and IMAP.
        """
        decoded = load.decode('utf-8', errors='ignore')
        intel = []

        # Pattern 1: HTTP GET/POST parameters
        http_patterns = [
            r"(?i)(user|username|login|email|pass|password|pwd|auth|token)=([^&^ ^\r^\n]*)"
        ]

        # Pattern 2: FTP/POP3/IMAP specific
        proto_patterns = [
            r"(?i)USER\s+(.*)\r\n",
            r"(?i)PASS\s+(.*)\r\n"
        ]

        # Scan for HTTP Creds
        if port in [80, 8080]:
            for p in http_patterns:
                matches = re.findall(p, decoded)
                for match in matches:
                    intel.append(
                        f"[bold red]HTTP-DATA: {match[0]}={match[1]}[/bold red]")

        # Scan for Generic Plaintext Protocols
        for p in proto_patterns:
            matches = re.findall(p, decoded)
            if matches:
                intel.append(
                    f"[bold yellow]AUTH-PROTO: {matches[0].strip()}[/bold yellow]")

        return intel

    def callback(self, packet):
        """Main packet processing logic."""
        if not packet.haslayer(IP):
            return

        # Store packet in buffer for PCAP saving (limited to prevent RAM exhaustion)
        if len(session_pcap) < 5000:
            session_pcap.append(packet)

        src, dst = packet[IP].src, packet[IP].dst
        info = []

        # 1. Capture DNS Queries (Domain Intel)
        if packet.haslayer(DNSQR) and packet.haslayer(DNS) and packet[DNS].qr == 0:
            query = packet[DNSQR].qname.decode().strip('.')
            info.append(f"[bold cyan]DNS Q: {query}[/bold cyan]")

        # 2. Capture TCP Traffic (Layer 4 Intelligence)
        elif packet.haslayer(TCP):
            port = packet[TCP].dport
            sport = packet[TCP].sport

            if packet.haslayer(Raw):
                load = packet[Raw].load

                # Check for plaintext credentials
                creds = self.parse_plaintext_creds(load, port)
                if not creds:  # Try source port for responses
                    creds = self.parse_plaintext_creds(load, sport)

                if creds:
                    info.extend(creds)

                # Generic Sensitive Data Detection (Keyword Matching)
                keywords = [b"password", b"passwd",
                            b"secret", b"apikey", b"access_token"]
                if any(kw in load.lower() for kw in keywords):
                    info.append(
                        "[bold orange1]Sensitive Keyword Detected[/bold orange1]")

            # Protocol Labeling for Common Encrypted Traffic
            if not info:
                if port == 443 or sport == 443:
                    info.append("[dim]TLS/HTTPS Encrypted[/dim]")
                elif port == 22 or sport == 22:
                    info.append("[dim]SSH Encrypted[/dim]")

        if info:
            with intel_lock:
                captured_intel.append({
                    "time": datetime.now().strftime("%H:%M:%S"),
                    "src": src,
                    "dst": dst,
                    "intel": " | ".join(info)
                })
                # Keep the list manageable
                if len(captured_intel) > 100:
                    captured_intel.pop(0)

    def generate_table(self):
        """Generates a Rich table for the Live display."""
        table = Table(
            title="WLAN Intelligence Stream",
            expand=True,
            border_style="cyan",
            show_header=True,
            header_style="bold magenta"
        )
        table.add_column("Time", style="dim", width=12, justify="center")
        table.add_column("Source Host", style="green", width=16)
        table.add_column("Destination", style="blue", width=16)
        table.add_column("Intercepted Metadata", style="white")

        with intel_lock:
            # Display only the most recent N entries
            for entry in captured_intel[-self.max_entries:]:
                table.add_row(entry["time"], entry["src"],
                              entry["dst"], entry["intel"])

        return table

    def start(self):
        """Initializes the sniffer and UI loop."""
        draw_header("WLAN LIVE INTERCEPTOR ELITE")

        # Network config check
        iface_list = [i.name for i in conf.ifaces.data.values()]
        console.print(Panel(
            f"Available Interfaces: [bold cyan]{', '.join(iface_list)}[/bold cyan]", border_style="dim"))

        target_iface = questionary.select(
            "Select Interface:",
            choices=iface_list,
            style=Q_STYLE
        ).ask()

        if not target_iface:
            target_iface = conf.iface

        if not os.path.exists("logs"):
            os.makedirs("logs")

        console.print(
            f"[*] Sniffer Engine Active on [bold green]{target_iface}[/bold green]. Listening for IPv4...")
        console.print(
            "[dim]Press Ctrl+C to terminate and export session PCAP.[/dim]\n")

        try:
            # Live display management
            with Live(self.generate_table(), refresh_per_second=2, screen=False) as live:
                def wrapped_cb(pkt):
                    self.callback(pkt)
                    live.update(self.generate_table())

                # sniff with 'store=0' because we manage 'session_pcap' manually to control RAM
                sniff(iface=target_iface, prn=wrapped_cb, store=0, filter="ip")

        except KeyboardInterrupt:
            console.print(
                "\n[yellow][!] Interception stopped by user.[/yellow]")
            if session_pcap:
                console.print(
                    f"[*] Saving {len(session_pcap)} packets to evidence file...")
                wrpcap(self.pcap_filename, session_pcap)
                console.print(
                    f"[bold green][+] Evidence saved: {self.pcap_filename}[/bold green]")
        except Exception as e:
            console.print(f"[bold red][!] Sniffer Error: {e}[/bold red]")


def run_sniffer():
    engine = SnifferEngine()
    engine.start()


if __name__ == "__main__":
    run_sniffer()
