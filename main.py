import sys
import os
from rich.console import Console
from rich.prompt import Prompt

# Importing the missing modules
from core.ui import draw_header
from core.updater import check_version, perform_update
from modules.scanner import network_discovery
from modules.sniff import start_sniffing
from modules.spoof import start_mitm        # New: MITM Engine
from modules.payloads import generate_shell  # New: Shell Forge

console = Console()


def main():
    if len(sys.argv) > 1:
        if sys.argv[1].lower() == "--update":
            perform_update()
            sys.exit(0)

    try:
        while True:
            os.system('cls' if os.name == 'nt' else 'clear')
            draw_header("Main Control")
            check_version()

            console.print("\n[bold cyan]COMMAND CENTER[/bold cyan]")
            console.print(
                "[bold red]>[/bold red] [1] Net-Mapper       [dim](ARP Discovery)[/dim]")
            console.print(
                "[bold red]>[/bold red] [2] Live Interceptor [dim](Packet Sniffing)[/dim]")
            console.print(
                "[bold red]>[/bold red] [3] MITM Engine      [dim](ARP Poisoning)[/dim]")
            console.print(
                "[bold red]>[/bold red] [4] Shell Forge      [dim](Payload Gen)[/dim]")
            console.print(
                "[bold red]>[/bold red] [Q] Vanish           [dim](Exit)[/dim]")

            choice = Prompt.ask(
                "\n[bold red]davoid[/bold red]@[root]",
                choices=["1", "2", "3", "4", "q", "Q"],
                show_choices=False
            )

            if choice == "1":
                network_discovery()
            elif choice == "2":
                start_sniffing()
            elif choice == "3":
                start_mitm()
            elif choice == "4":
                generate_shell()
            elif choice.lower() == "q":
                sys.exit(0)

    except KeyboardInterrupt:
        sys.exit(0)


if __name__ == "__main__":
    main()
