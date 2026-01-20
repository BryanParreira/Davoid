from rich.console import Console
from rich.panel import Panel
from rich.align import Align
from rich import box
from rich.table import Table
from rich.text import Text

console = Console()


def draw_header(title: str, status_info: str = None):
    """Draws the Davoid logo with a tactical module title and live status bar."""
    # Using a multi-color gradient for the logo to give it depth
    logo_raw = """
      ██████╗  █████╗ ██╗   ██╗ ██████╗ ██╗██████╗ 
      ██╔══██╗██╔══██╗██║   ██║██╔═══██╗██║██╔══██╗
      ██║  ██║███████║██║   ██║██║   ██║██║██║  ██║
      ██║  ██║██╔══██║╚██╗ ██╔╝██║   ██║██║██║  ██║
      ██████╔╝██║  ██║ ╚████╔╝ ╚██████╔╝██║██████╔╝
      ╚═════╝ ╚═╝  ╚═╝  ╚═══╝   ╚═════╝ ╚═╝╚═════╝ 
    """

    # Subtitle with spacing for a "cleaner" tactical look
    subtitle = "── [ G H O S T   I N   T H E   N E T ] ──"

    # Render logo with a red-to-dark-red gradient
    logo_text = Text(logo_raw, style="bold red")
    console.print(Align.center(logo_text))

    # Subtitle with a pulsing dim effect
    console.print(Align.center(
        f"[bold black on red] {subtitle} [/bold black on red]"))
    console.print()

    # 2. Module Title Panel - Added a "Double" box for a more industrial feel
    console.print(Align.center(
        Panel(
            f" [bold white]OP_TYPE:[/bold white] [blink red]▶[/blink red] [bold white]{title.upper()}[/bold white] ",
            border_style="red",
            box=box.DOUBLE_EDGE,
            padding=(0, 3)
        )
    ))

    # 3. Live Network Status Bar - Changed to a "heavy" box style
    if status_info:
        console.print(Align.center(
            Panel(
                f"📡 [bold cyan]SYSTEM_STATE:[/bold cyan] [green]ONLINE[/green] | [bold cyan]TARGET:[/bold cyan] {status_info}",
                border_style="bright_black",
                box=box.HEAVY_EDGE,
                padding=(0, 2)
            )
        ))
    console.print("\n")


def show_briefing(title, purpose, rules):
    """Provides a tactical overview before module execution."""
    draw_header(title)

    # Table layout with a more "Command Center" feel
    table = Table(box=box.HORIZONTALS, show_header=False,
                  border_style="red", padding=(0, 2))
    table.add_column("Key", style="bold red", justify="right")
    table.add_column("Value", style="white")

    table.add_row("MISSION_OBJECTIVE", f"[italic]{purpose}[/italic]")

    # Rules with "Danger" icons
    rules_text = "\n".join([f"[bold red]✘[/bold red] {r}" for r in rules])
    table.add_row("ENGAGEMENT_LIMITS", rules_text)

    console.print(Align.center(table))
    # Bottom separator line
    console.print(Align.center("[dim red]" + "━" * 70 + "[/dim red]\n"))


# --- Example Execution ---
if __name__ == "__main__":
    show_briefing(
        "Infiltration",
        "Decrypting mainframe nodes via ghost protocols.",
        ["No trace left behind", "Disable logs before exit",
            "Maintain 128-bit encryption"]
    )
