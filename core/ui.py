from rich.console import Console
from rich.panel import Panel
from rich.align import Align
from rich import box
from rich.table import Table

console = Console()


def draw_header(title: str):
    logo = """
      ██████╗  █████╗ ██╗   ██╗ ██████╗ ██╗██████╗ 
      ██╔══██╗██╔══██╗██║   ██║██╔═══██╗██║██╔══██╗
      ██║  ██║███████║██║   ██║██║   ██║██║██║  ██║
      ██║  ██║██╔══██║╚██╗ ██╔╝██║   ██║██║██║  ██║
      ██████╔╝██║  ██║ ╚████╔╝ ╚██████╔╝██║██████╔╝
      ╚═════╝ ╚═╝  ╚═╝  ╚═══╝   ╚═════╝ ╚═╝╚═════╝ 
             [ G H O S T   I N   T H E   N E T ]
    """
    console.print(Align.center(f"[bold red]{logo}[/bold red]"))
    console.print(Align.center(
        Panel(
            f"[bold white]{title.upper()}[/bold white]",
            border_style="red",
            box=box.ROUNDED,
            padding=(0, 2)
        )
    ))


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
