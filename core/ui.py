from rich.console import Console
from rich.panel import Panel
from rich.align import Align
from rich.text import Text

console = Console()

DAVOID_LOGO = r"""
      ██████╗  █████╗ ██╗   ██╗ ██████╗ ██╗██████╗ 
      ██╔══██╗██╔══██╗██║   ██║██╔═══██╗██║██╔══██╗
      ██║  ██║███████║██║   ██║██║   ██║██║██║  ██║
      ██║  ██║██╔══██║╚██╗ ██╔╝██║   ██║██║██║  ██║
      ██████╔╝██║  ██║ ╚████╔╝ ╚██████╔╝██║██████╔╝
      ╚═════╝ ╚═╝  ╚═╝  ╚═══╝   ╚═════╝ ╚═╝╚═════╝ 
             [ G H O S T  I N  T H E  N E T ]
"""


def draw_header(title=""):
    console.clear()

    # logo with deep red styling
    banner_text = Text(DAVOID_LOGO, style="bold red")

    # Stylized dripping divider
    drip = Text("       " + "v  " * 15, style="dim red")

    console.print(Align.center(banner_text))
    console.print(Align.center(drip))

    if title:
        console.print(Align.center(
            Panel(f"[bold white]{title.upper()}[/bold white]",
                  border_style="red",
                  box=None,
                  padding=(0, 2))
        ))
    console.print("[dim white]" + "━"*75 + "[/dim white]")
