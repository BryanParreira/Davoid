from modules.bruteforce import hash_cracker
from modules.recon import dns_recon
from modules.payloads import generate_shell
from modules.spoof import start_mitm
from modules.sniff import start_sniffing
from modules.scanner import network_discovery
from core.updater import check_version, perform_update
from core.ui import draw_header
import sys
import os
from rich.console import Console
from rich.prompt import Prompt

# --- Environment Setup ---
# Ensures Davoid can find its internal modules when running globally from /opt/
BASE_DIR = "/opt/davoid"
sys.path.append(BASE_DIR)

# Import Core Logic

# Import Security Modules

console = Console()


def main():
    # 1. Handle Command Line Arguments BEFORE UI starts
    # This ensures that if the UI crashes, the user can still run --update
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

    # 2. Main Terminal User Interface (TUI) Loop
    try:
        while True:
            # Clear terminal for a clean, professional aesthetic
            os.system('cls' if os.name == 'nt' else 'clear')

            draw_header("Main Control")

            # Passive update check (notifies user via a yellow panel)
            check_version()

            console.print("\n[bold cyan]COMMAND CENTER[/bold cyan]")
            console.print(
                "[bold red]>[/bold red] [1] Net-Mapper       [dim](ARP Discovery)[/dim]")
            console.print(
                "[bold red]>[/bold red] [2] Live Interceptor [dim](Packet Sniffing)[/dim]")
            console.print(
                "[bold red]>[/bold red] [3] MITM Engine      [dim](ARP Poisoning)[/dim]")
            console.print(
                "[bold red]>[/bold red] [4] Shell Forge      [dim](Payload Generation)[/dim]")
            console.print(
                "[bold red]>[/bold red] [5] DNS Recon        [dim](Domain Intel)[/dim]")
            console.print(
                "[bold red]>[/bold red] [6] Hash Cracker     [dim](MD5 Wordlist)[/dim]")
            console.print(
                "[bold red]>[/bold red] [Q] Vanish           [dim](Exit Console)[/dim]")

            # Handle user interaction
            choice = Prompt.ask(
                "\n[bold red]davoid[/bold red]@[root]",
                choices=["1", "2", "3", "4", "5", "6", "q", "Q"],
                show_choices=False
            )

            # 3. Routing Logic
            if choice == "1":
                network_discovery()
            elif choice == "2":
                start_sniffing()
            elif choice == "3":
                start_mitm()
            elif choice == "4":
                generate_shell()
            elif choice == "5":
                dns_recon()
            elif choice == "6":
                hash_cracker()
            elif choice.lower() == "q":
                console.print(
                    "\n[bold yellow]Vanish mode activated. Clearing traces...[/bold yellow]")
                sys.exit(0)

    except KeyboardInterrupt:
        # Prevents messy Python tracebacks on Ctrl+C
        console.print(
            "\n\n[bold red][!] Shutdown signal received. Exiting...[/bold red]")
        sys.exit(0)


if __name__ == "__main__":
    main()
