import socket
from rich.console import Console
from rich.table import Table
from core.ui import draw_header

console = Console()

def dns_recon():
    draw_header("DNS Infrastructure Recon")
    domain = console.input("[bold yellow]Enter Target Domain (e.g., example.com): [/bold yellow]").strip()

    if not domain:
        return

    table = Table(title=f"Infrastructure Report: {domain}", border_style="bold magenta")
    table.add_column("Query Type", style="cyan")
    table.add_column("Result / Value", style="white")

    console.print(f"[*] Analyzing [bold cyan]{domain}[/bold cyan]...")

    try:
        # 1. Resolve Primary IPv4
        ip_addr = socket.gethostbyname(domain)
        table.add_row("Primary IPv4", ip_addr)

        # 2. Reverse DNS Lookup (PTR) to identify hosting infrastructure
        try:
            host_info = socket.gethostbyaddr(ip_addr)
            table.add_row("PTR (Reverse DNS)", host_info[0])
        except:
            table.add_row("PTR (Reverse DNS)", "No Record Found")

        # 3. Resolve Canonical Name / Aliases
        name, alias, _ = socket.gethostbyname_ex(domain)
        if name != domain:
            table.add_row("Canonical Name", name)
        
        if alias:
            table.add_row("Aliases", ", ".join(alias))

        # 
        console.print(table)
        
    except Exception as e:
        console.print(f"[bold red][!] Recon Failed:[/bold red] {e}")

    input("\nPress Enter to return...")