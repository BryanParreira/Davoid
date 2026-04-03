import os
import subprocess
import questionary
from rich.console import Console
from rich.panel import Panel
from core.ui import draw_header, Q_STYLE

console = Console()


def run_burp_proxy():
    draw_header("Web Interception Proxy (Burp Alternative)")

    console.print(
        "[dim]This module launches an interactive TUI for intercepting, inspecting, and modifying HTTP/HTTPS traffic.[/dim]")
    console.print(
        "[dim]Traffic containing sensitive data (passwords, tokens) will be logged to Davoid's Mission Database.[/dim]\n")

    port = questionary.text("Listen Port (Default 8080):",
                            default="8080", style=Q_STYLE).ask()
    if not port:
        return

    # Ensure the addon script exists
    addon_path = os.path.join(os.path.dirname(__file__), "burp_addon.py")
    if not os.path.exists(addon_path):
        console.print(
            f"[bold red][!] Error: Proxy addon missing at {addon_path}[/bold red]")
        questionary.press_any_key_to_continue(style=Q_STYLE).ask()
        return

    console.print(Panel(
        f"[bold green]Proxy Starting on 127.0.0.1:{port}[/bold green]\n\n"
        "[white]Setup Instructions:[/white]\n"
        "1. Set your browser/device proxy to 127.0.0.1 on the specified port.\n"
        "2. Visit [bold cyan]http://mitm.it[/bold cyan] in your browser to install the SSL certificate.\n"
        "3. Inside the proxy, press [bold yellow]'?'[/bold yellow] for keyboard shortcuts.",
        border_style="green"
    ))

    questionary.press_any_key_to_continue(
        "Press Enter to enter the Proxy Interface...", style=Q_STYLE).ask()

    try:
        subprocess.run([
            "mitmproxy",
            "-p", str(port),
            "-s", addon_path,
            "--set", "console_palette=dark"
        ])
    except FileNotFoundError:
        console.print("\n[bold red][!] mitmproxy is not installed.[/bold red]")
        console.print(
            "[white]Run: /opt/davoid/venv/bin/pip install mitmproxy[/white]")
    except KeyboardInterrupt:
        pass

    console.print(
        "\n[yellow][*] Proxy shutdown complete. Returning to Davoid Hub...[/yellow]")


if __name__ == "__main__":
    run_burp_proxy()
