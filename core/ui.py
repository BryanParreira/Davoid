from rich.console import Console
from rich.panel import Panel
from rich.align import Align
from rich import box  # Make sure this is imported!

console = Console()


def draw_header(title: str):
    # This creates the stylized logo + title panel
    logo = """
      ██████╗  █████╗ ██╗   ██╗ ██████╗ ██╗██████╗ 
      ██╔══██╗██╔══██╗██║   ██║██╔═══██╗██║██╔══██╗
      ██║  ██║███████║██║   ██║██║   ██║██║██║  ██║
      ██║  ██║██╔══██║╚██╗ ██╔╝██║   ██║██║██║  ██║
      ██████╔╝██║  ██║ ╚████╔╝ ╚██████╔╝██║██████╔╝
      ╚═════╝ ╚═╝  ╚═╝  ╚═══╝   ╚═════╝ ╚═╝╚═════╝ 
             [ G H O S T   I N   T H E   N E T ]
    """

    # Print Logo
    console.print(Align.center(f"[bold red]{logo}[/bold red]"))

    # Print the Title Panel - FIX: explicitly set box=box.ROUNDED
    console.print(Align.center(
        Panel(
            f"[bold white]{title.upper()}[/bold white]",
            border_style="red",
            box=box.ROUNDED,  # This is the line that usually causes the crash if 'box' isn't imported or used correctly
            padding=(0, 2)
        )
    ))
