from rich.prompt import Prompt
from rich.console import Console
from rich.table import Table
import sys
import os
import warnings

# --- 1. SYSTEM SUPPRESSION LAYER ---
# Specifically target and kill the urllib3/LibreSSL warning before imports
warnings.filterwarnings("ignore", message=".*OpenSSL 1.1.1+.*")
warnings.filterwarnings("ignore", category=UserWarning, module='urllib3')
# Suppress Scapy IPv6 warnings for a cleaner interface
warnings.filterwarnings("ignore", category=UserWarning, module='scapy')


# --- 2. ENVIRONMENT SETUP ---
# Ensures Davoid can find its internal modules when running globally
BASE_DIR = "/opt/davoid"
if os.path.exists(BASE_DIR):
    sys.path.append(BASE_DIR)

# --- 3. CORE & UI LOGIC ---
try:
    from core.ui import draw_header
    from core.updater import check_version, perform_update
    from core.context import ctx  # Added: Global Context Engine
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
    from modules.spoof import MITMEngine
    from modules.dns_spoofer import start_dns_spoof
    from modules.cloner import clone_site
    from modules.ghost_hub import run_ghost_hub
    from modules.wifi_ops import run_wifi_suite

    # Payloads & Persistence
    from modules.payloads import generate_shell
    from modules.crypt_keeper import encrypt_payload
    from modules.bruteforce import crack_hash
    from modules.persistence import PersistenceEngine

    # System, Persistence & Intelligence
    from modules.auditor import run_auditor

except ImportError as e:
    # Modules are imported dynamically; missing modules will notify the user upon selection
    pass

console = Console()


def configure_context():
    """UI for managing global variables within the Context Engine."""
    while True:
        os.system('cls' if os.name == 'nt' else 'clear')
        draw_header("Global Configuration")

        table = Table(title="Current Global Context",
                      border_style="bold magenta")
        table.add_column("Variable", style="cyan")
        table.add_column("Value", style="white")

        for key, value in ctx.vars.items():
            table.add_row(key, str(value))

        console.print(table)
        console.print(
            "\n[bold red]>[/bold red] [S] Set Variable  [B] Back to Main")

        choice = Prompt.ask("\n[bold red]config[/bold red]@[root]",
                            choices=["s", "b"], show_choices=False).lower()

        if choice == 's':
            key = Prompt.ask(
                "[bold yellow]Variable to set (e.g., LHOST): [/bold yellow]").upper()
            val = Prompt.ask(
                f"[bold yellow]New value for {key}: [/bold yellow]")
            if not ctx.set(key, val):
                console.print(
                    f"[bold red][!] Error:[/bold red] '{key}' is not a valid global variable.")
                input("Press Enter...")
        else:
            break


def main():
    # FIRST: Check for update argument via CLI
    if len(sys.argv) > 1:
        arg = sys.argv[1].lower()
        if arg == "--update":
            perform_update()
            sys.exit(0)

    # SECOND: Start the TUI loop
    try:
        while True:
            # Clear screen based on OS
            os.system('cls' if os.name == 'nt' else 'clear')

            # Draw ASCII Header with current Module Title
            draw_header("Main Control")

            # Passive update check (Displays notification if version mismatch)
            check_version()

            # --- COMMAND CENTER UI ---
            console.print("\n[bold cyan]RECON & SCANNING[/bold cyan]")
            console.print(
                "[bold red]>[/bold red] [1] Net-Mapper       [2] Live Interceptor  [3] DNS Recon")
            console.print("[bold red]>[/bold red] [4] Web Ghost")

            console.print("\n[bold cyan]OFFENSIVE ENGINE[/bold cyan]")
            console.print(
                "[bold red]>[/bold red] [5] MITM Engine      [6] DNS Spoofer       [7] Phantom Cloner")
            console.print(
                "[bold red]>[/bold red] [W] WiFi-Suite       [L] GHOST-HUB C2")

            console.print("\n[bold cyan]PAYLOADS & PERSISTENCE[/bold cyan]")
            console.print(
                "[bold red]>[/bold red] [8] Shell Forge      [9] Crypt-Keeper      [0] Persistence Engine")
            console.print("[bold red]>[/bold red] [H] Hash Cracker")

            console.print("\n[bold cyan]SYSTEM TOOLS[/bold cyan]")
            console.print(
                "[bold red]>[/bold red] [C] Config Context   [A] Setup Auditor    [Q] Vanish")

            # Handle user interaction with root prompt style
            choice = Prompt.ask(
                "\n[bold red]davoid[/bold red]@[root]",
                choices=["1", "2", "3", "4", "5", "6", "7", "w", "W", "l", "L",
                         "8", "9", "0", "h", "H", "c", "C", "a", "A", "q", "Q"],
                show_choices=False
            ).lower()

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
                engine = MITMEngine()
                engine.run()
            elif choice == "6":
                start_dns_spoof()
            elif choice == "7":
                clone_site()
            elif choice == "w":
                run_wifi_suite()
            elif choice == "l":
                run_ghost_hub()
            elif choice == "8":
                generate_shell()
            elif choice == "9":
                path = console.input(
                    "[bold yellow]Path to payload: [/bold yellow]")
                if os.path.exists(path):
                    encrypt_payload(path)
                else:
                    console.print("[red]File not found.[/red]")
                    input("Press Enter...")
            elif choice == "0":
                path = console.input(
                    "[bold yellow]Absolute Payload Path: [/bold yellow]")
                engine = PersistenceEngine(path)
                engine.run()
            elif choice == "h":
                target = console.input(
                    "[bold yellow]Target Hash: [/bold yellow]")
                algo = console.input(
                    "[bold yellow]Algo (sha256): [/bold yellow]") or "sha256"
                crack_hash(target, algo)
            elif choice == "c":
                configure_context()
            elif choice == "a":
                run_auditor()
            elif choice == "q":
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
