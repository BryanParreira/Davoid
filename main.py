from modules.sniff import start_sniffing
from modules.scanner import network_discovery
from core.updater import check_version, perform_update
from core.ui import draw_header
import sys
import os
from rich.console import Console
from rich.prompt import Prompt

# --- Environment Setup ---
# Ensures Davoid can find its internal modules when running globally
BASE_DIR = "/opt/davoid"
sys.path.append(BASE_DIR)


console = Console()


def main():
    # 1. Handle Command Line Arguments (e.g., davoid --update)
    if len(sys.argv) > 1:
        arg = sys.argv[1].lower()
        if arg == "--update":
            perform_update()
            sys.exit(0)
        elif arg in ["--help", "-h"]:
            console.print("[bold cyan]Usage:[/bold cyan] davoid [options]")
            console.print("  --update    Pull latest tools from GitHub")
            console.print("  --help      Show this menu")
            sys.exit(0)

    # 2. Main TUI Loop
    try:
        while True:
            # Clear terminal for a clean, professional interface
            os.system('cls' if os.name == 'nt' else 'clear')

            draw_header("Main Control")

            # Passive update check (notifies user if update is available)
            check_version()

            console.print("\n[bold cyan]COMMAND CENTER[/bold cyan]")
            console.print(
                "[bold red]>[/bold red] [1] Net-Mapper       [dim](ARP Discovery)[/dim]")
            console.print(
                "[bold red]>[/bold red] [2] Live Interceptor [dim](Packet Sniffing)[/dim]")
            console.print(
                "[bold red]>[/bold red] [Q] Vanish           [dim](Exit)[/dim]")

            # Prompt user for input
            choice = Prompt.ask(
                "\n[bold red]davoid[/bold red]@[root]",
                choices=["1", "2", "q", "Q"],
                show_choices=False
            )

            # 3. Route Logic
            if choice == "1":
                network_discovery()
            elif choice == "2":
                start_sniffing()
            elif choice.lower() == "q":
                console.print(
                    "\n[bold yellow]Vanish mode activated. Clearing traces...[/bold yellow]")
                sys.exit(0)

    except KeyboardInterrupt:
        # Prevents messy tracebacks if the user hits Ctrl+C
        console.print(
            "\n\n[bold red][!] Shutdown signal received. Exiting...[/bold red]")
        sys.exit(0)


if __name__ == "__main__":
    main()
