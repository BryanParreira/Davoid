"""
modules/sniff.py — WLAN Live Interceptor
Scapy-based live packet capture with real-time credential extraction,
DNS monitoring, HTTP keyword detection, and PCAP export.
FIXED: intel_lock is instance-level (not module-level) — safe across runs.
"""

import os
import threading
from datetime import datetime

import questionary
from rich.console import Console
from rich.live import Live
from rich.table import Table

from scapy.all import sniff, conf, IP, TCP, UDP, DNS, DNSQR, Raw
from scapy.utils import wrpcap

from core.ui import draw_header, Q_STYLE
from core.database import db

console = Console()

# ─────────────────────────────────────────────────────────────────────────────
#  PLAINTEXT CREDENTIAL PATTERNS (port → keywords)
# ─────────────────────────────────────────────────────────────────────────────

PLAINTEXT_PATTERNS = {
    21:  [b"USER ", b"PASS "],
    23:  [b"login: ", b"Password: "],
    25:  [b"AUTH ", b"MAIL FROM"],
    110: [b"USER ", b"PASS "],
    143: [b"LOGIN "],
    80:  [b"username=", b"password=", b"user=", b"pass=", b"email=", b"pwd=",
          b"passwd=", b"credentials="],
    8080: [b"username=", b"password=", b"user=", b"pass="],
}

SENSITIVE_KEYWORDS = [
    b"password", b"passwd", b"secret", b"apikey", b"api_key",
    b"access_token", b"bearer ", b"authorization:", b"x-api-key",
]


# ─────────────────────────────────────────────────────────────────────────────
#  ENGINE
# ─────────────────────────────────────────────────────────────────────────────

class SnifferEngine:
    def __init__(self):
        self.intel_lock = threading.Lock()   # instance-level — safe across runs
        self.captured_intel: list = []
        self.session_pcap:  list = []
        self.max_entries = 50
        self.pcap_filename = f"logs/capture_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pcap"

    def parse_plaintext_creds(self, payload: bytes, port: int) -> list:
        found = []
        patterns = PLAINTEXT_PATTERNS.get(port, [])
        for pat in patterns:
            if pat in payload:
                idx = payload.index(pat) + len(pat)
                value = payload[idx:idx + 64].split(b"\r")[0].split(b"\n")[0]
                found.append(
                    f"{pat.decode(errors='ignore').strip()} {value.decode(errors='ignore').strip()}")
        return found

    def callback(self, packet):
        if not packet.haslayer(IP):
            return

        self.session_pcap.append(packet)

        src = packet[IP].src
        dst = packet[IP].dst
        info: list = []

        # DNS queries
        if packet.haslayer(DNS) and packet.haslayer(DNSQR):
            try:
                query = packet[DNSQR].qname.decode(errors="ignore").rstrip(".")
                info.append(f"DNS: {query}")
            except Exception:
                pass

        # TCP payload
        elif packet.haslayer(TCP):
            dport = packet[TCP].dport
            sport = packet[TCP].sport

            if packet.haslayer(Raw):
                load = packet[Raw].load

                # Credential hunt
                creds = self.parse_plaintext_creds(load, dport)
                if not creds:
                    creds = self.parse_plaintext_creds(load, sport)

                for c in creds:
                    info.append(f"[bold red]{c}[/bold red]")
                    db.log("Live-Interceptor", src,
                           f"Credential: {c}", "CRITICAL")

                # Sensitive keyword scan
                lower_load = load.lower()
                if any(kw in lower_load for kw in SENSITIVE_KEYWORDS):
                    info.append(
                        "[bold orange1]Sensitive Keyword[/bold orange1]")
                    db.log("Live-Interceptor", src,
                           "Sensitive keyword in stream", "HIGH")

        if info:
            with self.intel_lock:
                self.captured_intel.append({
                    "time":  datetime.now().strftime("%H:%M:%S"),
                    "src":   src,
                    "dst":   dst,
                    "intel": " | ".join(info),
                })
                if len(self.captured_intel) > 100:
                    self.captured_intel.pop(0)

    def generate_table(self) -> Table:
        table = Table(title="WLAN Intelligence Stream",
                      expand=True, border_style="cyan")
        table.add_column("Time",   style="dim",   width=10)
        table.add_column("Source", style="green", width=16)
        table.add_column("Dest",   style="blue",  width=16)
        table.add_column("Intel",  style="white")
        with self.intel_lock:
            for entry in self.captured_intel[-self.max_entries:]:
                table.add_row(entry["time"], entry["src"],
                              entry["dst"], entry["intel"])
        return table

    def start(self):
        draw_header("WLAN LIVE INTERCEPTOR")

        iface_list = [i.name for i in conf.ifaces.data.values()]
        target_iface = questionary.select(
            "Select Network Interface:", choices=iface_list, style=Q_STYLE
        ).ask()
        if not target_iface:
            target_iface = str(conf.iface)

        os.makedirs("logs", exist_ok=True)

        console.print(
            f"[*] Sniffer active on [bold green]{target_iface}[/bold green].  "
            f"Press [bold yellow]Ctrl+C[/bold yellow] to stop and save PCAP.\n"
        )

        db.log("Live-Interceptor", target_iface,
               "Sniffer session started.", "INFO")

        try:
            with Live(self.generate_table(), refresh_per_second=2, screen=False) as live:
                def wrapped_cb(pkt):
                    self.callback(pkt)
                    live.update(self.generate_table())

                sniff(iface=target_iface, prn=wrapped_cb, store=0, filter="ip")

        except KeyboardInterrupt:
            console.print("\n[yellow][!] Capture stopped.[/yellow]")
            if self.session_pcap:
                wrpcap(self.pcap_filename, self.session_pcap)
                console.print(
                    f"[green][+] PCAP saved: {self.pcap_filename}[/green]")

        db.log("Live-Interceptor", target_iface,
               f"Session ended. {len(self.captured_intel)} events captured.", "INFO")


def run_sniffer():
    SnifferEngine().start()


if __name__ == "__main__":
    run_sniffer()
