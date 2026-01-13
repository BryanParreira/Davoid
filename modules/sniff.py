from scapy.all import sniff, IP, TCP, UDP, conf
from rich.console import Console
from rich.table import Table
from core.ui import draw_header

console = Console()

def packet_callback(packet):
    """Sniffs and flags high-value traffic in the intercepted stream."""
    if packet.haslayer(IP):
        src = packet[IP].src
        dst = packet[IP].dst
        
        if packet.haslayer(TCP):
            port = packet[TCP].dport
            # Protocol Tagging: Identify 'hot' targets automatically
            tag = "[cyan][TCP][/cyan]"
            
            if port == 80: 
                tag = "[bold green][HTTP][/bold green]"
            elif port == 21: 
                tag = "[bold red][FTP-INTEL][/bold red]" # Potential Credentials
            elif port == 445: 
                tag = "[bold yellow][SMB-FILE][/bold yellow]" # File Sharing
            elif port == 22:
                tag = "[bold blue][SSH][/bold blue]"

            console.print(f"{tag} [cyan]{src}[/cyan] -> [magenta]{dst}:{port}[/magenta]")
            
        elif packet.haslayer(UDP):
            port = packet[UDP].dport
            tag = "[dim][UDP][/dim]"
            if port == 53:
                tag = "[bold magenta][DNS][/bold magenta]"
            
            console.print(f"{tag} [cyan]{src}[/cyan] -> [magenta]{dst}:{port}[/magenta]")

def start_sniffing():
    draw_header("WLAN Live Interceptor")
    
    # 1. WLAN Interface Discovery
    ifaces = [i.name for i in conf.ifaces.data.values()]
    console.print("[bold cyan]Available Interfaces:[/bold cyan] " + ", ".join(ifaces))
    
    chosen_iface = console.input("[bold yellow]Interface to use (e.g., wlan0): [/bold yellow]").strip()

    if not chosen_iface:
        return

    # 
    console.print(f"\n[bold green][*] Interceptor active on {chosen_iface}. Press CTRL+C to stop.[/bold green]\n")
    
    try:
        # Binding sniff to specific interface for Wi-Fi support
        sniff(iface=chosen_iface, prn=packet_callback, store=False)
    except KeyboardInterrupt:
        console.print("\n[bold yellow][!] Sniffing stopped by user.[/bold yellow]")
    except Exception as e:
        console.print(f"[bold red][!] Error:[/bold red] {e}")

    input("\nPress Enter to return...")