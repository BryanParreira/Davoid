from scapy.all import sniff, IP, TCP, UDP
from rich.console import Console
from core.ui import draw_header

console = Console()


def packet_callback(packet):
    if packet.haslayer(IP):
        src = packet[IP].src
        dst = packet[IP].dst
        # Determine protocol
        proto = "TCP" if packet.haslayer(
            TCP) else "UDP" if packet.haslayer(UDP) else "IP"
        console.print(
            f"[dim][{proto}][/dim] [cyan]{src}[/cyan] -> [magenta]{dst}[/magenta]")


def start_sniffing():
    draw_header("Ghost Sniffer")
    console.print(
        "[bold green]Capture active. Press CTRL+C to stop sniffing.[/bold green]\n")
    try:
        # sniffing for 50 packets or until Ctrl+C
        sniff(prn=packet_callback, store=False)
    except KeyboardInterrupt:
        console.print(
            "\n[bold yellow][!] Sniffing stopped by user.[/bold yellow]")
    except Exception as e:
        console.print(f"[red]Error:[/red] {e}")

    input("\nPress Enter to return...")
