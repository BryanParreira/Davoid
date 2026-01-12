from scapy.all import ARP, Ether, srp
from rich.console import Console
from rich.table import Table
from core.ui import draw_header

console = Console()


def network_discovery():
    draw_header("Root Discovery Mode")
    ip_range = console.input(
        "[bold yellow]Enter Subnet (e.g., 192.168.1.0/24): [/bold yellow]")

    try:
        # Creating a broadcast Ethernet frame with an ARP request
        # This is the "Gold Standard" for local network mapping
        ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") /
                     ARP(pdst=ip_range), timeout=2, verbose=False)

        table = Table(title="Live Nodes Found", border_style="bold red")
        table.add_column("IP Address", style="cyan")
        table.add_column("MAC Address", style="magenta")
        table.add_column("Vendor", style="green")

        for _, rcv in ans:
            # Note: Vendor lookup usually requires an OUI database,
            # for now, we show the hardware address.
            table.add_row(rcv.psrc, rcv.hwsrc, "Detected")

        console.print(table)
    except Exception as e:
        console.print(f"[bold red]Critical Error:[/bold red] {e}")

    input("\nPress Enter to return...")
