from scapy.all import sniff, IP, TCP, UDP
from rich.console import Console
from core.ui import draw_header

console = Console()


def packet_callback(packet):
    if packet.haslayer(IP):
        src = packet[IP].src
        dst = packet[IP].dst
        proto = "TCP" if packet.haslayer(
            TCP) else "UDP" if packet.haslayer(UDP) else "Other"
        console.print(f"[dim][{proto}][/dim] {src} -> {dst}")


def start_sniffing():
    draw_header("Ghost Sniffer")
    console.print("[bold green]Capture active. CTRL+C to stop.[/bold green]\n")
    try:
        sniff(prn=packet_callback, count=50)
    except Exception as e:
        console.print(f"[red]Error:[/red] {e}")
    input("\nPress Enter...")
