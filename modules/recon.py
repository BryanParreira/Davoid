import socket
from rich.console import Console
from rich.table import Table

console = Console()


def dns_recon():
    domain = console.input("[bold yellow]Enter Domain: [/bold yellow]")
    table = Table(title=f"Recon: {domain}", header_style="bold magenta")
    table.add_column("Type")
    table.add_column("Data")

    try:
        table.add_row("IP Address", socket.gethostbyname(domain))
        name, alias, _ = socket.gethostbyname_ex(domain)
        table.add_row("Canonical Name", name)
        table.add_row("Aliases", str(alias))
        console.print(table)
    except Exception as e:
        console.print(f"[red]Failed:[/red] {e}")
    input("\nPress Enter...")
