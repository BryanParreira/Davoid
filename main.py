import sys
import os
from rich.console import Console
from rich.prompt import Prompt
import warnings

# Suppress the urllib3/LibreSSL warning for a cleaner TUI
warnings.filterwarnings("ignore", category=UserWarning, module='urllib3')

# Add base directory to path
BASE_DIR = "/opt/davoid"
sys.path.append(BASE_DIR)

# Core & UI
from core.ui import draw_header
from core.updater import check_version

# Security Modules
from modules.scanner import network_discovery
from modules.sniff import start_sniffing
from modules.spoof import start_mitm
from modules.payloads import generate_shell
from modules.recon import dns_recon
from modules.bruteforce import hash_cracker
from modules.web_recon import web_ghost
from modules.crypt_keeper import encrypt_payload

console = Console()

def main():
    if len(sys.argv) > 1 and sys.argv[1] == "--update":
        from core.updater import perform_update
        perform_update()
        sys.exit(0)

    try:
        while True:
            os.system('cls' if os.name == 'nt' else 'clear')
            draw_header("Main Control")
            check_version()

            console.print("\n[bold cyan]COMMAND CENTER[/bold cyan]")
            console.print("[bold red]>[/bold red] [1] Net-Mapper       [dim](ARP Discovery)[/dim]")
            console.print("[bold red]>[/bold red] [2] Live Interceptor [dim](Sniffing)[/dim]")
            console.print("[bold red]>[/bold red] [3] MITM Engine      [dim](Poisoning)[/dim]")
            console.print("[bold red]>[/bold red] [4] Shell Forge      [dim](B64 Payloads)[/dim]")
            console.print("[bold red]>[/bold red] [5] DNS Recon        [dim](Domain Intel)[/dim]")
            console.print("[bold red]>[/bold red] [6] Hash Cracker     [dim](Wordlist Pro)[/dim]")
            console.print("[bold red]>[/bold red] [7] Web Ghost        [dim](Sensitive Files)[/dim]")
            console.print("[bold red]>[/bold red] [8] Crypt-Keeper     [dim](Evasion)[/dim]")
            console.print("[bold red]>[/bold red] [Q] Vanish           [dim](Exit)[/dim]")

            choice = Prompt.ask("\n[bold red]davoid[/bold red]@[root]", choices=["1","2","3","4","5","6","7","8","q","Q"], show_choices=False)

            if choice == "1": network_discovery()
            elif choice == "2": start_sniffing()
            elif choice == "3": start_mitm()
            elif choice == "4": generate_shell()
            elif choice == "5": dns_recon()
            elif choice == "6": hash_cracker()
            elif choice == "7": web_ghost()
            elif choice == "8": encrypt_payload()
            elif choice.lower() == "q": sys.exit(0)

    except KeyboardInterrupt:
        sys.exit(0)

if __name__ == "__main__":
    main()