import sys
import psutil
import platform
import socket
from rich.console import Console
from rich.panel import Panel
from rich.align import Align
from rich import box
from rich.table import Table
from rich.layout import Layout
from rich.text import Text

console = Console()


def get_system_metrics():
    """Captures real-time system telemetry."""
    cpu_usage = psutil.cpu_percent(interval=None)
    ram_usage = psutil.virtual_memory().percent

    # Color coding for metrics
    cpu_color = "green" if cpu_usage < 50 else "yellow" if cpu_usage < 80 else "red"
    ram_color = "green" if ram_usage < 50 else "yellow" if ram_usage < 80 else "red"

    return f"CPU: [{cpu_color}]{cpu_usage}%[/{cpu_color}] | RAM: [{ram_color}]{ram_usage}%[/{ram_color}]"


def draw_header(title: str, context=None):
    """
    Renders a Next-Gen Tactical HUD.
    Includes Logo, Module Title, and Real-time Telemetry Grid.
    """
    logo_text = """
      ██████╗  █████╗ ██╗   ██╗ ██████╗ ██╗██████╗ 
      ██╔══██╗██╔══██╗██║   ██║██╔═══██╗██║██╔══██╗
      ██║  ██║███████║██║   ██║██║   ██║██║██║  ██║
      ██║  ██║██╔══██║╚██╗ ██╔╝██║   ██║██║██║  ██║
      ██████╔╝██║  ██║ ╚████╔╝ ╚██████╔╝██║██████╔╝
      ╚═════╝ ╚═╝  ╚═╝  ╚═══╝   ╚═════╝ ╚═╝╚═════╝ 
    """

    # 1. Construct the Top Bar (Logo + System Stats)
    sys_info = f"[bold white]{platform.node()}[/bold white] | [dim]{platform.system()} {platform.release()}[/dim]"
    metrics = get_system_metrics()

    header_table = Table.grid(expand=True)
    header_table.add_column(justify="left", ratio=1)
    header_table.add_column(justify="right", ratio=1)
    header_table.add_row(
        Text.from_markup(f"[bold red]GHOST SEC OPERATOR[/bold red]"),
        Text.from_markup(metrics)
    )

    # 2. Context Bar (Interface, IP, Target)
    ctx_text = "[dim]No Active Context[/dim]"
    if context:
        ctx_text = f"[bold cyan]IFACE:[/bold cyan] {context.get('INTERFACE')} | [bold cyan]IP:[/bold cyan] {context.get('LHOST')} | [bold cyan]GW:[/bold cyan] {context.vars.get('GATEWAY', 'Unknown')}"

    # 3. Render the Dashboard
    console.print(Align.center(f"[bold red]{logo_text}[/bold red]"))

    # Create a layout grid for the HUD
    grid = Table.grid(expand=True, padding=(0, 1))
    grid.add_column(ratio=1)

    # Main Title Bar
    grid.add_row(
        Panel(
            Align.center(f"[bold white]{title.upper()}[/bold white]"),
            border_style="red",
            box=box.HEAVY_HEAD,
            title="[bold red]ACTIVE MODULE[/bold red]",
            title_align="center"
        )
    )

    # Telemetry Bar
    grid.add_row(
        Panel(
            Align.center(ctx_text),
            border_style="dim blue",
            box=box.ROUNDED,
            title=f"[bold blue]SYSTEM TELEMETRY :: {sys_info}[/bold blue]",
            title_align="left"
        )
    )

    console.print(grid)
    console.print("\n")


def show_briefing(title, purpose, rules):
    """Provides a tactical overview before module execution."""
    draw_header(title)
    table = Table(box=box.SIMPLE, show_header=False, border_style="dim")
    table.add_column("Key", style="cyan")
    table.add_column("Value", style="white")

    table.add_row("PURPOSE", purpose)
    rules_text = "\n".join([f" [red]![/red] {r}" for r in rules])
    table.add_row("RULES", rules_text)

    console.print(Align.center(table))
    console.print("[dim]" + "─" * 60 + "[/dim]\n")
