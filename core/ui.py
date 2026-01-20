from rich.console import Console
from rich.panel import Panel
from rich.align import Align
from rich import box
from rich.table import Table
from rich.text import Text

console = Console()


def draw_header(title: str, status_info: str = None):
    """Draws the Davoid logo with a tactical module title and live status bar."""

    # 1. THE LOGO: Using a high-impact 'Glitch' style ASCII with depth
    # We use rich tags inside the string to create a red-to-dark-red depth effect
    logo = """
 [bold red]  _____ [/bold red] [bold white]         [/bold white] [bold red]        [/bold red] [bold white]  _ [/bold white] [bold red]      _ [/bold red]
 [bold red] |  __ \ [/bold red][bold white]   /\    [/bold white] [bold red] \    / [/bold red] [bold white] (_) [/bold white][bold red]     | |[/bold red]
 [bold red] | |  | |[/bold red][bold white]  /  \   [/bold white] [bold red]  \  /  [/bold red] [bold white]  _ [/bold white] [bold red]  _  | |[/bold red]
 [bold red] | |  | |[/bold red][bold white] / /\ \  [/bold white] [bold red]   \/   [/bold red] [bold white] | |[/bold white][bold red] | | | |[/bold red]
 [bold red] | |__| |[/bold red][bold white]/ ____ \ [/bold white] [bold red]        [/bold red] [bold white] | |[/bold white][bold red] |_| | |[/bold red]
 [bold red] |_____/[/bold red][bold white]/_/    \_\ [/bold white][bold red]        [/bold red] [bold white] |_|[/bold white][bold red] \__,_|_|[/bold red]
    [dim white]▆▆▆▆▆▆▆▆▆▆▆▆▆▆▆▆▆▆▆▆▆▆▆▆▆▆▆▆▆▆▆▆▆▆▆▆▆▆▆▆▆▆▆▆[/dim white]
           [bold white on red] G H O S T   I N   T H E   N E T [/bold white on red]
    """

    # Print Logo with centering
    console.print(Align.center(logo))

    # 2. Module Title Panel - Changed to a 'Double' border for more "tech" weight
    console.print(Align.center(
        Panel(
            f" [blink red]⚡[/blink red] [bold white]{title.upper()}[/bold white] [blink red]⚡[/blink red] ",
            border_style="red",
            box=box.DOUBLE_EDGE,
            padding=(0, 3)
        )
    ))

    # 3. Elite Feature: Live Network Status Bar
    if status_info:
        console.print(Align.center(
            Panel(
                f"[bold cyan]▼ SYSTEM_STATE:[/bold cyan] [green]STABLE[/green] [bold cyan]▼ TARGET:[/bold cyan] {status_info}",
                border_style="dim red",
                box=box.HORIZONTALS,
                padding=(0, 1)
            )
        ))
    console.print("\n")


def show_briefing(title, purpose, rules):
    """Provides a tactical overview before module execution."""
    draw_header(title)
    table = Table(box=box.SIMPLE, show_header=False, border_style="dim red")
    table.add_column("Key", style="bold red")
    table.add_column("Value", style="white")

    table.add_row("ENTRY_POINT", f"[italic]{purpose}[/italic]")
    rules_text = "\n".join([f" [red]▶[/red] {r}" for r in rules])
    table.add_row("PROTOCOL", rules_text)

    console.print(Align.center(table))
    console.print(Align.center("[dim red]" + "━" * 65 + "[/dim red]\n"))


# Example Trigger
if __name__ == "__main__":
    show_briefing("Neural Bypass", "Bypassing external firewalls via Davoid Logic.", [
                  "Silence is mandatory", "No trace", "Exit on 0"])
