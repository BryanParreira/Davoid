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
    from modules.sniff import SnifferEngine
    from modules.recon import dns_recon
    from modules.web_recon import web_ghost

    # OSINT & Profiling (Holmes Engine)
    from modules.osint_pro import username_tracker, phone_intel, geolocate, dork_generator

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
except ImportError as e:
    print(f"[!] Warning: Module initialization failed: {e}")

console = Console()

# --- 5. SUPPORT FUNCTIONS ---


def auto_discovery():
    """Elite Feature: Automatic Interface and Network Detection."""
    try:
        from scapy.all import conf, get_if_addr
        active_iface = str(conf.iface)
        local_ip = get_if_addr(active_iface)
        gw_ip = conf.route.route("0.0.0.0")[2]

        ctx.set("INTERFACE", active_iface)
        ctx.set("LHOST", local_ip)
        ctx.vars["GATEWAY"] = gw_ip
        return True
    except:
        return False


def get_status():
    """Generates the dynamic status string for the header."""
    return f"[green]IFACE:[/green] {ctx.get('INTERFACE')} | [green]IP:[/green] {ctx.get('LHOST')} | [green]GW:[/green] {ctx.vars.get('GATEWAY', 'Unknown')}"


def configure_context():
    """Manual Overrides for the Context Engine."""
    while True:
        os.system('cls' if os.name == 'nt' else 'clear')
        draw_header("Global Configuration", status_info=get_status())
        table = Table(title="Framework Context", border_style="bold magenta")
        table.add_column("Variable", style="cyan")
        table.add_column("Current Value", style="white")
        for key, value in ctx.vars.items():
            table.add_row(key, str(value))
        console.print(table)
        console.print(
            "\n[bold red]>[/bold red] [S] Set Variable  [B] Back to Hub")
        choice = Prompt.ask("\n[bold red]config[/bold red]@[root]",
                            choices=["s", "b"], show_choices=False).lower()
        if choice == 's':
            key = Prompt.ask("[bold yellow]Variable: [/bold yellow]").upper()
            val = Prompt.ask(f"New value for {key}: ")
            if not ctx.set(key, val):
                ctx.vars[key] = val
        else:
            break

# --- 6. CATEGORY SUB-MENUS ---


def hub_intelligence():
    """Category: Recon, Infrastructure, and OSINT."""
    while True:
        os.system('cls' if os.name == 'nt' else 'clear')
        draw_header("Intelligence Hub", status_info=get_status())
        console.print("\n[bold cyan]NETWORK & INFRASTRUCTURE[/bold cyan]")
        console.print(
            "[bold red]>[/bold red] [1] Net-Mapper       [2] Live Interceptor  [3] DNS Recon")
        console.print("[bold red]>[/bold red] [4] Web Ghost")

        console.print("\n[bold cyan]OSINT & PROFILING (Holmes)[/bold cyan]")
        console.print(
            "[bold red]>[/bold red] [U] Username Tracker [P] Phone Intelligence [G] Geo-Locator")
        console.print("[bold red]>[/bold red] [D] Dork Automator")

        console.print("\n[bold red]>[/bold red] [B] Back to Master Hub")

        choice = Prompt.ask("\n[bold red]intel[/bold red]@[root]", choices=[
                            "1", "2", "3", "4", "u", "p", "g", "d", "b"], show_choices=False).lower()
        if choice == "1":
            network_discovery()
        elif choice == "2":
            engine = SnifferEngine()
            engine.start()
        elif choice == "3":
            dns_recon()
        elif choice == "4":
            web_ghost()
        elif choice == "u":
            username_tracker()
        elif choice == "p":
            phone_intel()
        elif choice == "g":
            geolocate()
        elif choice == "d":
            dork_generator()
        elif choice == "b":
            break


def hub_offensive():
    """Category: Active Traffic and Network Manipulation."""
    while True:
        os.system('cls' if os.name == 'nt' else 'clear')
        draw_header("Offensive Hub", status_info=get_status())
        console.print("\n[bold cyan]TRAFFIC MANIPULATION[/bold cyan]")
        console.print(
            "[bold red]>[/bold red] [1] MITM Engine      [2] DNS Spoofer       [3] Phantom Cloner")

        console.print("\n[bold cyan]WIRELESS & CONTROL[/bold cyan]")
        console.print(
            "[bold red]>[/bold red] [W] WiFi-Suite       [L] GHOST-HUB C2")

        console.print("\n[bold red]>[/bold red] [B] Back to Master Hub")

        choice = Prompt.ask("\n[bold red]attack[/bold red]@[root]",
                            choices=["1", "2", "3", "w", "l", "b"], show_choices=False).lower()
        if choice == "1":
            engine = MITMEngine()
            engine.run()
        elif choice == "2":
            start_dns_spoof()
        elif choice == "3":
            clone_site()
        elif choice == "w":
            run_wifi_suite()
        elif choice == "l":
            run_ghost_hub()
        elif choice == "b":
            break


def hub_payloads():
    """Category: Generation, Evasion, and Persistence."""
    while True:
        os.system('cls' if os.name == 'nt' else 'clear')
        draw_header("Payload Hub", status_info=get_status())
        console.print("\n[bold cyan]PAYLOADS & EVASION[/bold cyan]")
        console.print(
            "[bold red]>[/bold red] [1] Shell Forge      [2] Crypt-Keeper")

        console.print("\n[bold cyan]POST-EXPLOITATION[/bold cyan]")
        console.print(
            "[bold red]>[/bold red] [3] Persistence Engine [4] Hash Cracker")

        console.print("\n[bold red]>[/bold red] [B] Back to Master Hub")

        choice = Prompt.ask("\n[bold red]payload[/bold red]@[root]",
                            choices=["1", "2", "3", "4", "b"], show_choices=False).lower()
        if choice == "1":
            generate_shell()
        elif choice == "2":
            path = console.input("[bold yellow]Payload Path: [/bold yellow]")
            if os.path.exists(path):
                encrypt_payload(path)
            else:
                input("[red][!] File not found.[/red] Enter to continue...")
        elif choice == "3":
            path = console.input(
                "[bold yellow]Persistence Target Path: [/bold yellow]")
            if os.path.exists(path):
                engine = PersistenceEngine(path)
                engine.run()
            else:
                input("[red][!] File not found.[/red] Enter to continue...")
        elif choice == "4":
            target = console.input(
                "[bold yellow]Hash to Crack: [/bold yellow]")
            crack_hash(target)
        elif choice == "b":
            break

# --- 7. MASTER CONTROL ---


def main():
    if len(sys.argv) > 1 and sys.argv[1].lower() == "--update":
        perform_update()
        sys.exit(0)

    # 1. INITIAL AUTO-DISCOVERY
    auto_discovery()

    try:
        while True:
            os.system('cls' if os.name == 'nt' else 'clear')
            draw_header("Master Command Hub", status_info=get_status())
            check_version()

            # --- MASTER HUB MENU ---
            console.print(
                "\n[bold cyan]SELECT OPERATIONAL OBJECTIVE[/bold cyan]")
            console.print(
                "[bold red]>[/bold red] [1] Intelligence & OSINT   [dim](Recon, Fuzzing, Holmes Engine)[/dim]")
            console.print(
                "[bold red]>[/bold red] [2] Offensive Operations   [dim](MITM, Spofing, WiFi, C2 Hub)[/dim]")
            console.print(
                "[bold red]>[/bold red] [3] Payloads & Persistence [dim](Forge, Crypt, Backdoors, Cracker)[/dim]")

            console.print("\n[bold cyan]SYSTEM & STEALTH[/bold cyan]")
            console.print(
                "[bold red]>[/bold red] [C] Global Config         [A] Setup Auditor")
            console.print(
                "[bold red]>[/bold red] [U] Update Mainframe      [Q] Vanish (Exit)")

            choice = Prompt.ask(
                "\n[bold red]davoid[/bold red]@[root]",
                choices=["1", "2", "3", "c", "a", "u", "q"],
                show_choices=False
            ).lower()

            if choice == "1":
                hub_intelligence()
            elif choice == "2":
                hub_offensive()
            elif choice == "3":
                hub_payloads()
            elif choice == "c":
                configure_context()
            elif choice == "a":
                run_auditor()
            elif choice == "u":
                perform_update()
            elif choice == "q":
                console.print(
                    "\n[bold yellow]Vanish mode activated. Clearing traces...[/bold yellow]")
                sys.exit(0)

    except KeyboardInterrupt:
        sys.exit(0)
    except Exception as e:
        console.print(f"\n[bold red][!] Hub Error:[/bold red] {e}")
        input("\nPress Enter to return...")


if __name__ == "__main__":
    main()
