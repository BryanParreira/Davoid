import sys
import os
import warnings
from rich.console import Console
from rich.prompt import Prompt

# 1. Suppress the urllib3/LibreSSL warning for a cleaner TUI experience
warnings.filterwarnings("ignore", category=UserWarning, module='urllib3')

# 2. Environment Setup
# Ensures Davoid can find its internal modules when running globally from /opt/
BASE_DIR = "/opt/davoid"
if os.path.exists(BASE_DIR):
    sys.path.append(BASE_DIR)

# 3. Import Core & UI Logic
try:
    from core.ui import draw_header
    from core.updater import check_version, perform_update
except ImportError as e:
    print(f"Core components missing: {e}")
    sys.exit(1)

# 4. Import Security Modules
try:
    # Recon & Scanning
    from modules.scanner import network_discovery
    from modules.sniff import start_sniffing
    from modules.recon import dns_recon
    
    # Offensive Engine
    from modules.spoof import start_mitm
    from modules.dns_spoofer import start_dns_spoof
    from modules.cloner import clone_site
    
    # Payloads & Evasion
    from modules.payloads import generate_shell
    from modules.crypt_keeper import encrypt_payload
    from modules.bruteforce import hash_cracker
    from modules.web_recon import web_ghost
    
except ImportError as e:
    # If a module is missing, Davoid will still run, but notify the user
    pass

console = Console()

def main():
    # FIRST: Check for update argument
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
            
            # Draw ASCII Header
            draw_header("Main Control")

            # Passive update check (Displays notification if version mismatch)
            check_version()

            # --- COMMAND CENTER UI ---
            console.print("\n[bold cyan]RECON & SCANNING[/bold cyan]")
            console.print("[bold red]>[/bold red] [1] Net-Mapper       [2] Live Interceptor  [3] DNS Recon")
            
            console.print("\n[bold cyan]OFFENSIVE ENGINE[/bold cyan]")
            console.print("[bold red]>[/bold red] [4] MITM Engine      [5] DNS Spoofer       [6] Phantom Cloner")
            
            console.print("\n[bold cyan]PAYLOADS & EVASION[/bold cyan]")
            console.print("[bold red]>[/bold red] [7] Shell Forge      [8] Crypt-Keeper      [9] Hash Cracker")
            console.print("[bold red]>[/bold red] [0] Web Ghost")
            
            console.print("\n[bold red]>[/bold red] [Q] Vanish           [dim](Exit Console)[/dim]")

            # Handle user interaction
            choice = Prompt.ask(
                "\n[bold red]davoid[/bold red]@[root]",
                choices=["1", "2", "3", "4", "5", "6", "7", "8", "9", "0", "q", "Q"],
                show_choices=False
            )

            # Routing Logic
            if choice == "1":
                network_discovery()
            elif choice == "2":
                start_sniffing()
            elif choice == "3":
                dns_recon()
            elif choice == "4":
                start_mitm()
            elif choice == "5":
                start_dns_spoof()
            elif choice == "6":
                clone_site()
            elif choice == "7":
                generate_shell()
            elif choice == "8":
                encrypt_payload()
            elif choice == "9":
                hash_cracker()
            elif choice == "0":
                web_ghost()
            elif choice.lower() == "q":
                console.print("\n[bold yellow]Vanish mode activated. Clearing traces...[/bold yellow]")
                sys.exit(0)

    except KeyboardInterrupt:
        # Prevents messy Python tracebacks on Ctrl+C
        console.print("\n\n[bold red][!] Shutdown signal received. Exiting...[/bold red]")
        sys.exit(0)
    except Exception as e:
        console.print(f"\n[bold red][!] Runtime Error:[/bold red] {e}")
        input("\nPress Enter to continue...")

if __name__ == "__main__":
    main()