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
        
        return f"CPU: [{cpu_c}]{cpu_usage}%[/{cpu_c}]  RAM: [{ram_c}]{ram_usage}%[/{ram_c}]"
    except:
        return "Telemetry Offline"

def draw_header(title: str, context=None):
    """
    Renders the Redesigned Tactical HUD.
    Features a clean, centered layout that auto-scales.
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
    metrics = get_system_metrics()
    
    if context:
        iface = context.get('INTERFACE') or "Eth0"
        ip = context.get('LHOST') or "127.0.0.1"
        gw = context.vars.get('GATEWAY', 'Unknown')
        
        # New Layout: Centered Master Table
        # This keeps everything perfectly aligned regardless of screen size
        info_table = Table(box=None, show_header=False, expand=False)
        info_table.add_column(justify="center")
        
        # Row 1: Network Context (High Visibility)
        info_table.add_row(
            f"[bold red]IFACE:[/bold red] [bold white]{iface}[/bold white]   "
            f"[bold red]IP:[/bold red] [bold white]{ip}[/bold white]   "
            f"[bold red]GW:[/bold red] [bold white]{gw}[/bold white]"
        )
        
        # Row 2: Hardware Stats (Dimmed)
        info_table.add_row(f"[dim]{metrics} | {platform.system()} {platform.release()}[/dim]")

        # 3. Render the Module Title Bar
        console.print(Align.center(
            Panel(
                f"[bold white]{title.upper()}[/bold white]",
                border_style="red",
                box=box.HEAVY_HEAD,
                padding=(0, 4),
                subtitle="[bold red]ACTIVE MODULE[/bold red]",
                subtitle_align="center"
            )
        ))
        
        # 4. Render the Data Table below it
        console.print(Align.center(info_table))
    
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