from rich.prompt import Prompt
from rich.console import Console
from rich.table import Table
import sys
import os
import warnings

# --- 1. SYSTEM SUPPRESSION LAYER ---
warnings.filterwarnings("ignore", message=".*OpenSSL 1.1.1+.*")
warnings.filterwarnings("ignore", category=UserWarning, module='urllib3')
warnings.filterwarnings("ignore", category=UserWarning, module='scapy')

# --- 2. ENVIRONMENT SETUP ---
BASE_DIR = "/opt/davoid"
if os.path.exists(BASE_DIR):
    sys.path.append(BASE_DIR)

# --- 3. CORE & UI LOGIC ---
try:
    from core.ui import draw_header
    from core.updater import check_version, perform_update
    from core.context import ctx
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

    # System & Intelligence
    from modules.auditor import run_auditor
except ImportError:
    pass

console = Console()


def auto_discovery():
    """Elite Feature: Automatic Interface and Network Detection."""
    try:
        from scapy.all import conf, get_if_addr
        # Detect active interface (e.g. en0 on Mac)
        active_iface = str(conf.iface)
        local_ip = get_if_addr(active_iface)
        # Resolve default gateway
        gw_ip = conf.route.route("0.0.0.0")[2]

        # Populate context automatically
        ctx.set("INTERFACE", active_iface)
        ctx.set("LHOST", local_ip)
        # Adding 'GATEWAY' to the vars manually if it's not in the original context class
        ctx.vars["GATEWAY"] = gw_ip
        return True
    except:
        return False


def configure_context():
    """Manual Overrides for the Context Engine."""
    while True:
        os.system('cls' if os.name == 'nt' else 'clear')
        draw_header("Global Configuration")
        table = Table(title="Framework Context", border_style="bold magenta")
        table.add_column("Variable", style="cyan")
        table.add_column("Current Value", style="white")
        for key, value in ctx.vars.items():
            table.add_row(key, str(value))
        console.print(table)
        console.print(
            "\n[bold red]>[/bold red] [S] Set Variable  [B] Back to Main")
        choice = Prompt.ask("\n[bold red]config[/bold red]@[root]",
                            choices=["s", "b"], show_choices=False).lower()
        if choice == 's':
            key = Prompt.ask("[bold yellow]Variable: [/bold yellow]").upper()
            val = Prompt.ask(f"New value for {key}: ")
            if not ctx.set(key, val):
                # Manual entry for custom vars like GATEWAY
                ctx.vars[key] = val
        else:
            break


def main():
    # CLI Check for updates
    if len(sys.argv) > 1 and sys.argv[1].lower() == "--update":
        perform_update()
        sys.exit(0)

    # 1. INITIAL AUTO-DISCOVERY
    auto_discovery()

    try:
        while True:
            os.system('cls' if os.name == 'nt' else 'clear')

            # 2. DYNAMIC STATUS BAR
            status = f"[green]IFACE:[/green] {ctx.get('INTERFACE')} | [green]IP:[/green] {ctx.get('LHOST')} | [green]GW:[/green] {ctx.vars.get('GATEWAY', 'Unknown')}"
            draw_header("Main Control", status_info=status)

            # Passive update check
            check_version()

            # --- COMMAND CENTER ---
            console.print(
                "\n[bold cyan]PHASE I: RECON & INTELLIGENCE[/bold cyan]")
            console.print(
                "[bold red]>[/bold red] [1] Net-Mapper       [2] Live Interceptor  [3] DNS Recon")
            console.print("[bold red]>[/bold red] [4] Web Ghost")

            console.print(
                "\n[bold cyan]PHASE II: OFFENSIVE ENGINE[/bold cyan]")
            console.print(
                "[bold red]>[/bold red] [5] MITM Engine      [6] DNS Spoofer       [7] Phantom Cloner")
            console.print(
                "[bold red]>[/bold red] [W] WiFi-Suite       [L] GHOST-HUB C2")

            console.print(
                "\n[bold cyan]PHASE III: PAYLOADS & PERSISTENCE[/bold cyan]")
            console.print(
                "[bold red]>[/bold red] [8] Shell Forge      [9] Crypt-Keeper      [0] Persistence Engine")
            console.print("[bold red]>[/bold red] [H] Hash Cracker")

            console.print("\n[bold cyan]SYSTEM & CONFIGURATION[/bold cyan]")
            console.print(
                "[bold red]>[/bold red] [C] Global Config    [A] Setup Auditor    [Q] Vanish")

            choice = Prompt.ask("\n[bold red]davoid[/bold red]@[root]", choices=["1", "2", "3", "4", "5", "6", "7",
                                "w", "W", "l", "L", "8", "9", "0", "h", "H", "c", "C", "a", "A", "q", "Q"], show_choices=False).lower()

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
                    "[bold yellow]Payload Path: [/bold yellow]")
                if os.path.exists(path):
                    encrypt_payload(path)
                else:
                    input("[red][!] File not found.[/red] Enter to continue...")
            elif choice == "0":
                path = console.input(
                    "[bold yellow]Persistence Target Path: [/bold yellow]")
                if os.path.exists(path):
                    engine = PersistenceEngine(path)
                    engine.run()
                else:
                    input("[red][!] File not found.[/red] Enter to continue...")
            elif choice == "h":
                target = console.input(
                    "[bold yellow]Hash to Crack: [/bold yellow]")
                crack_hash(target)
            elif choice == "c":
                configure_context()
            elif choice == "a":
                run_auditor()
            elif choice == "q":
                sys.exit(0)

    except KeyboardInterrupt:
        sys.exit(0)
    except Exception as e:
        console.print(f"\n[bold red][!] Runtime Error:[/bold red] {e}")
        input("\nPress Enter to return...")


if __name__ == "__main__":
    main()
