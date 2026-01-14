from rich.prompt import Prompt
from rich.console import Console
from rich.table import Table
import sys
import os
import warnings

# --- 1. SYSTEM SUPPRESSION LAYER ---
warnings.filterwarnings("ignore", category=UserWarning)

# --- 2. CORE IMPORTS ---
try:
    from core.ui import draw_header
    from core.context import ctx
    from core.updater import check_version
except ImportError as e:
    print(f"[!] Critical Core Error: {e}")
    sys.exit(1)

console = Console()


def run_module(module_name, function_name, is_class=False):
    """Dynamically loads and runs a module to prevent global import crashes."""
    try:
        # Dynamic Import
        mod = __import__(f"modules.{module_name}", fromlist=[function_name])
        if is_class:
            # Handle classes like MITMEngine
            attr = getattr(mod, function_name)
            instance = attr()
            instance.run()
        else:
            # Handle direct functions
            func = getattr(mod, function_name)
            func()
    except Exception as e:
        console.print(
            f"\n[bold red][!] Module Failure ({module_name}): {e}[/bold red]")
        input("\nPress Enter to return...")


def manage_context():
    """UI for setting global session variables."""
    while True:
        os.system('cls' if os.name == 'nt' else 'clear')
        draw_header("Global Configuration")
        table = Table(title="Active Session Variables",
                      border_style="cyan", expand=True)
        table.add_column("Variable", style="bold yellow")
        table.add_column("Current Value", style="white")

        for k, v in ctx.vars.items():
            table.add_row(k, str(v))
        console.print(table)

        console.print(
            "\n[dim]Usage: set <variable> <value> (e.g., 'set lhost 10.0.0.5') or 'back'[/dim]")
        cmd = console.input(
            "[bold red]davoid[/bold red]@[config]> ").strip().split()

        if not cmd or cmd[0].lower() == "back":
            break
        if cmd[0].lower() == "set" and len(cmd) > 2:
            if ctx.set(cmd[1], cmd[2]):
                console.print(f"[green][+] {cmd[1].upper()} updated.[/green]")
                time.sleep(0.5)
            else:
                console.print("[red][!] Invalid variable name.[/red]")
                time.sleep(1)


def main():
    try:
        while True:
            os.system('cls' if os.name == 'nt' else 'clear')
            draw_header("Main Control")
            check_version()

            console.print("\n[bold cyan]RECON & SCANNING[/bold cyan]")
            console.print(
                "[bold red]>[/bold red] [1] Net-Mapper       [2] Live Interceptor  [3] DNS Recon")
            console.print("[bold red]>[/bold red] [4] Web Ghost")

            console.print("\n[bold cyan]OFFENSIVE ENGINE[/bold cyan]")
            console.print(
                "[bold red]>[/bold red] [5] MITM Engine      [6] DNS Spoofer       [7] Phantom Cloner")
            console.print(
                "[bold red]>[/bold red] [L] GHOST-HUB C2    [W] Wireless Ops [dim](Wifi Deauth/Capture)[/dim]")

            console.print("\n[bold cyan]PAYLOADS & SYSTEM[/bold cyan]")
            console.print(
                "[bold red]>[/bold red] [8] Shell Forge      [S] Set Variables     [A] Setup Auditor")
            console.print("[bold red]>[/bold red] [Q] Vanish")

            choice = Prompt.ask(
                "\n[bold red]davoid[/bold red]@[root]", show_choices=False).lower()

            # Routing Logic using Dynamic Loader
            if choice == "1":
                run_module("scanner", "network_discovery")
            elif choice == "2":
                run_module("sniff", "start_sniffing")
            elif choice == "3":
                run_module("recon", "dns_recon")
            elif choice == "4":
                run_module("web_recon", "web_ghost")
            elif choice == "5":
                run_module("spoof", "MITMEngine", is_class=True)
            elif choice == "6":
                run_module("dns_spoofer", "start_dns_spoof")
            elif choice == "7":
                run_module("cloner", "clone_site")
            elif choice == "l":
                run_module("ghost_hub", "run_ghost_hub")
            elif choice == "w":
                run_module("wifi_ops", "run_wifi_suite")  # New Module
            elif choice == "8":
                run_module("payloads", "generate_shell")
            elif choice == "s":
                manage_context()
            elif choice == "a":
                run_module("auditor", "run_auditor")
            elif choice == "q":
                sys.exit(0)

    except KeyboardInterrupt:
        sys.exit(0)


if __name__ == "__main__":
    main()
