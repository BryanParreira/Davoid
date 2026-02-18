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
from questionary import Style

console = Console()

# --- GLOBAL THEME DEFINITION ---
Q_STYLE = Style([
    ('qmark', 'fg:#ff0000 bold'),       # Red Token
    ('question', 'fg:#ffffff bold'),    # White Question
    ('answer', 'fg:#ff0000 bold'),      # Red Answer
    ('pointer', 'fg:#ff0000 bold'),     # Red Pointer
    ('highlighted', 'fg:#ff0000 bold'), # Red Highlight
    ('selected', 'fg:#cc5454'),         # Dim Red Selected
    ('separator', 'fg:#444444'),        # Dark Grey Separator
    ('instruction', 'fg:#666666 italic') # User instructions
])

def get_system_metrics():
    """Captures real-time system telemetry."""
    try:
        cpu_usage = psutil.cpu_percent(interval=None)
        ram_usage = psutil.virtual_memory().percent
        
        # Aggressive Color Coding
        cpu_c = "white" if cpu_usage < 50 else "yellow" if cpu_usage < 80 else "red"
        ram_c = "white" if ram_usage < 50 else "yellow" if ram_usage < 80 else "red"
        
        return f"[dim]CPU:[/dim] [{cpu_c}]{cpu_usage}%[/{cpu_c}]   [dim]RAM:[/dim] [{ram_c}]{ram_usage}%[/{ram_c}]"
    except:
        return "Telemetry Offline"

def draw_header(title: str, context=None):
    """
    Renders the Redesigned Tactical HUD.
    """
    logo_text = """
      ██████╗  █████╗ ██╗   ██╗ ██████╗ ██╗██████╗ 
      ██╔══██╗██╔══██╗██║   ██║██╔═══██╗██║██╔══██╗
      ██║  ██║███████║██║   ██║██║   ██║██║██║  ██║
      ██║  ██║██╔══██║╚██╗ ██╔╝██║   ██║██║██║  ██║
      ██████╔╝██║  ██║ ╚████╔╝ ╚██████╔╝██║██████╔╝
      ╚═════╝ ╚═╝  ╚═╝  ╚═══╝   ╚═════╝ ╚═╝╚═════╝ 
    """
    
    # 1. Main Logo
    console.print(Align.center(f"[bold red]{logo_text}[/bold red]"))

    # 2. Context Data Construction
    sys_info = f"{platform.node()} ({platform.system()})"
    metrics = get_system_metrics()
    
    if context:
        iface = context.get('INTERFACE') or "Eth0"
        ip = context.get('LHOST') or "127.0.0.1"
        gw = context.vars.get('GATEWAY', 'Unknown')
        
        # New Layout: Three-Column Tactical Bar
        grid = Table.grid(expand=True, padding=(0, 2))
        grid.add_column(justify="left", ratio=1)
        grid.add_column(justify="center", ratio=1)
        grid.add_column(justify="right", ratio=1)
        
        # Left: Identity
        grid.add_row(
            f"[bold red]OPERATOR ::[/bold red] [bold white]{sys_info}[/bold white]",
            f"[bold red]INTERFACE ::[/bold red] [bold white]{iface}[/bold white]",
            f"[bold red]TARGET GW ::[/bold red] [bold white]{gw}[/bold white]"
        )
        
        # Second Row: Stats
        grid.add_row(
            f"[dim]{metrics}[/dim]",
            f"[bold red]LOCAL IP ::[/bold red] [bold white]{ip}[/bold white]",
            "[dim]SECURE SHELL: ACTIVE[/dim]"
        )

        # 3. Render the Module Title Bar
        console.print(Panel(
            Align.center(f"[bold white]{title.upper()}[/bold white]"),
            border_style="red",
            box=box.HEAVY_HEAD,
            padding=(0, 2)
        ))
        
        # 4. Render the Data Grid below it
        console.print(Panel(
            grid,
            border_style="dim red",
            box=box.SIMPLE,
            padding=(0, 1)
        ))
    
    console.print("\n")

def show_briefing(title, purpose, rules):
    """Provides a tactical overview before module execution."""
    draw_header(title)
    table = Table(box=box.SIMPLE, show_header=False, border_style="dim")
    table.add_column("Key", style="red")
    table.add_column("Value", style="white")

    table.add_row("MISSION", purpose)
    rules_text = "\n".join([f" > {r}" for r in rules])
    table.add_row("ROE", rules_text)

    console.print(Align.center(table))
    console.print("[dim]" + "─" * 60 + "[/dim]\n")