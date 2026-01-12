import socket
from rich.console import Console
from rich.table import Table
from core.ui import draw_header

console = Console()


def dns_recon():
    draw_header("DNS Reconnaissance")
    domain = console.input(
        "[bold yellow]Enter Target Domain (e.g., google.com): [/bold yellow]")

    if not domain:
        return

    table = Table(title=f"Recon Report: {domain}", border_style="bold magenta")
    table.add_column("Query Type", style="cyan")
    table.add_column("Result", style="white")

    console.print(f"[*] Querying [bold cyan]{domain}[/bold cyan]...")

    try:
        # Resolve Basic IP
        ip_addr = socket.gethostbyname(domain)
        table.add_row("Primary IPv4", ip_addr)

        # Resolve Canonical Name / Aliases
        name, alias, _ = socket.gethostbyname_ex(domain)
        table.add_row("Canonical Name", name)
        if alias:
            table.add_row("Aliases", ", ".join(alias))

        console.print(table)
    except Exception as e:
        console.print(f"[bold red][!] Error:[/bold red] {e}")

    input("\nPress Enter to return...")
