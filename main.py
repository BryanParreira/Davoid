from rich.prompt import Prompt
from rich.console import Console
import sys
import os
import warnings

# --- 1. SYSTEM SUPPRESSION LAYER ---
warnings.filterwarnings("ignore", message=".*OpenSSL 1.1.1+.*")
warnings.filterwarnings("ignore", category=UserWarning, module='urllib3')


# --- 2. ENVIRONMENT SETUP ---
BASE_DIR = "/opt/davoid"
if os.path.exists(BASE_DIR):
    sys.path.append(BASE_DIR)

# --- 3. CORE & UI LOGIC ---
try:
    from core.ui import draw_header
    from core.updater import check_version, perform_update
except ImportError as e:
    print(f"Core components missing: {e}")
    sys.exit(1)

# --- 4. SECURITY MODULE IMPORTS ---
try:
    # Recon & Scanning
    from modules.scanner import network_discovery
    from modules.sniff import start_sniffing
    from modules.recon import dns_recon
    from modules.web_recon import web_ghost

    # Offensive Engine
    from modules.spoof import start_mitm
    from modules.dns_spoofer import start_dns_spoof
    from modules.cloner import clone_site
    # UPGRADED: C2 Hub replaces basic listener
    from modules.ghost_hub import run_ghost_hub

    # Payloads & Persistence
    from modules.payloads import generate_shell
    from modules.crypt_keeper import encrypt_payload
    from modules.bruteforce import hash_cracker

    # System, Persistence & Intelligence
    from modules.auditor import run_auditor
    from modules.persistence import run_persistence_engine

except ImportError as e:
    # Modules are imported dynamically to keep the core stable
    pass

console = Console()


def main():
    if len(sys.argv) > 1:
        arg = sys.argv[1].lower()
        if arg == "--update":
            perform_update()
            sys.exit(0)

    try:
        while True:
            os.system('cls' if os.name == 'nt' else 'clear')
            draw_header("Main Control")
            check_version()

            # --- COMMAND CENTER UI ---
            console.print("\n[bold cyan]RECON & SCANNING[/bold cyan]")
            console.print(
                "[bold red]>[/bold red] [1] Net-Mapper       [2] Live Interceptor  [3] DNS Recon")
            console.print("[bold red]>[/bold red] [4] Web Ghost")

            console.print("\n[bold cyan]OFFENSIVE ENGINE[/bold cyan]")
            console.print(
                "[bold red]>[/bold red] [5] MITM Engine      [6] DNS Spoofer       [7] Phantom Cloner")
            # UPGRADED ENTRY
            console.print(
                "[bold red]>[/bold red] [L] GHOST-HUB C2    [dim](Multi-Session)[/dim]")

            console.print("\n[bold cyan]PAYLOADS & PERSISTENCE[/bold cyan]")
            console.print(
                "[bold red]>[/bold red] [8] Shell Forge      [9] Crypt-Keeper      [0] Persistence Engine")
            console.print("[bold red]>[/bold red] [H] Hash Cracker")

            console.print("\n[bold cyan]SYSTEM TOOLS[/bold cyan]")
            console.print(
                "[bold red]>[/bold red] [A] Setup Auditor    [dim](Pre-flight Check)[/dim]")

            console.print(
                "\n[bold red]>[/bold red] [Q] Vanish           [dim](Exit Console)[/dim]")

            # Handle user interaction
            choice = Prompt.ask(
                "\n[bold red]davoid[/bold red]@[root]",
                choices=["1", "2", "3", "4", "5", "6", "7", "l", "L",
                         "8", "9", "0", "h", "H", "a", "A", "q", "Q"],
                show_choices=False
            )

            # --- ROUTING LOGIC ---
            if choice == "1":
                network_discovery()
            elif choice == "2":
                start_sniffing()
            elif choice == "3":
                dns_recon()
            elif choice == "4":
                web_ghost()
            elif choice == "5":
                start_mitm()
            elif choice == "6":
                start_dns_spoof()
            elif choice == "7":
                clone_site()
            elif choice.lower() == "l":
                run_ghost_hub()  # ROUTED TO NEW C2 HUB
            elif choice == "8":
                generate_shell()
            elif choice == "9":
                encrypt_payload()
            elif choice == "0":
                run_persistence_engine()
            elif choice.lower() == "h":
                hash_cracker()
            elif choice.lower() == "a":
                run_auditor()
            elif choice.lower() == "q":
                console.print(
                    "\n[bold yellow]Vanish mode activated. Clearing traces...[/bold yellow]")
                sys.exit(0)

    except KeyboardInterrupt:
        console.print(
            "\n\n[bold red][!] Shutdown signal received. Exiting...[/bold red]")
        sys.exit(0)
    except Exception as e:
        console.print(f"\n[bold red][!] Runtime Error:[/bold red] {e}")
        input("\nPress Enter to continue...")


if __name__ == "__main__":
    main()
