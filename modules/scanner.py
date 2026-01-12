from scapy.all import ARP, Ether, srp
from rich.console import Console
from rich.table import Table
from core.ui import draw_header

console = Console()


def network_discovery():
    draw_header("Root Discovery Mode")
    console.print("[dim]Example: 192.168.1.0/24[/dim]")
    ip_range = console.input("[bold yellow]Enter Subnet: [/bold yellow]")

    if not ip_range:
        return

    try:
        console.print(f"[bold cyan][*][/bold cyan] Scanning {ip_range}...")
        # Creating a broadcast Ethernet frame with an ARP request
        ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") /
                     ARP(pdst=ip_range), timeout=2, verbose=False)

        table = Table(
            title=f"Live Nodes on {ip_range}", border_style="bold red")
        table.add_column("IP Address", style="cyan")
        table.add_column("MAC Address", style="magenta")
        table.add_column("Status", style="green")

        for _, rcv in ans:
            table.add_row(rcv.psrc, rcv.hwsrc, "ONLINE")

        console.print(table)
    except Exception as e:
        console.print(f"[bold red]Critical Error:[/bold red] {e}")

    input("\nPress Enter to return...")
