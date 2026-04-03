import os
import sys
import socket
import subprocess
import questionary
from rich.console import Console
from rich.panel import Panel
from core.ui import draw_header, Q_STYLE

console = Console()


def is_port_in_use(port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        return s.connect_ex(('127.0.0.1', port)) == 0


def run_burp_proxy():
    draw_header("Web Interception Proxy (Burp Alternative)")

    console.print(
        "[dim]Professional TUI for intercepting, modifying, and replaying HTTP/HTTPS traffic.[/dim]")
    console.print(
        "[dim]Fully integrated with the Mission Database for automated credential harvesting.[/dim]\n")

    port_str = questionary.text(
        "Listen Port (Default 8080):", default="8080", style=Q_STYLE).ask()
    if not port_str:
        return

    try:
        port = int(port_str)
    except ValueError:
        return console.print("[red][!] Invalid port number.[/red]")

    if is_port_in_use(port):
        console.print(
            f"[bold red][!] Error: Port {port} is already in use. Please select a different port or kill the blocking process.[/bold red]")
        questionary.press_any_key_to_continue(style=Q_STYLE).ask()
        return

    addon_path = os.path.join(os.path.dirname(__file__), "burp_addon.py")
    if not os.path.exists(addon_path):
        console.print(
            f"[bold red][!] Error: Proxy addon engine missing at {addon_path}[/bold red]")
        questionary.press_any_key_to_continue(style=Q_STYLE).ask()
        return

    console.print(Panel(
        f"[bold green]Proxy Engine Primed for 127.0.0.1:{port}[/bold green]\n\n"
        "[white]Operator Instructions:[/white]\n"
        "1. Route your target browser/device through [bold cyan]127.0.0.1:{port}[/bold cyan].\n"
        "2. Navigate to [bold cyan]http://mitm.it[/bold cyan] on the target to install the Davoid SSL Certificate.\n"
        "3. Inside the TUI, press [bold yellow]'i'[/bold yellow] to set intercept filters, or [bold yellow]'?'[/bold yellow] for help.",
        border_style="green"
    ))

    questionary.press_any_key_to_continue(
        "Press Enter to launch proxy interface...", style=Q_STYLE).ask()

    try:
        # Production Fix: Run via sys.executable to ensure virtual environment persistence
        subprocess.run([
            sys.executable, "-m", "mitmproxy",
            "-p", str(port),
            "-s", addon_path,
            "--set", "console_palette=dark",
            "--set", "block_global=false"  # Prevents mitmproxy from blocking external requests
        ])
    except Exception as e:
        console.print(f"\n[bold red][!] Proxy Engine Failure: {e}[/bold red]")

    console.print(
        "\n[yellow][*] Proxy shutdown complete. Returning to Mainframe...[/yellow]")


if __name__ == "__main__":
    run_burp_proxy()
