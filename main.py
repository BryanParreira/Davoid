import sys
import os
import warnings
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.prompt import Prompt

# --- 1. SYSTEM SUPPRESSION LAYER ---
warnings.filterwarnings("ignore")

# --- 2. ENVIRONMENT SETUP ---
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
if SCRIPT_DIR not in sys.path:
    sys.path.append(SCRIPT_DIR)

# --- 3. CORE & MODULE IMPORTS ---
try:
    from core.ui import draw_header
    from core.context import ctx
    # Import Hub Launchers
    from modules.scanner import network_discovery
    from modules.sniff import run_sniffer
    from modules.recon import dns_recon
    from modules.web_recon import web_ghost
    from modules.spoof import start_mitm
    from modules.dns_spoofer import start_dns_spoof
    from modules.cloner import clone_site
    from modules.ghost_hub import GhostHubManager
    from modules.wifi_ops import run_wifi_suite
    from modules.payloads import generate_shell
    from modules.bruteforce import start_crack
    from modules.auditor import run_auditor
except ImportError as e:
    print(f"[!] Error: Critical module missing: {e}")
    sys.exit(1)

console = Console()


class DavoidConsole:
    def __init__(self):
        self.modules = {
            "scanner": network_discovery,
            "sniffer": run_sniffer,
            "dns_recon": dns_recon,
            "web_recon": web_ghost,
            "mitm": start_mitm,
            "dns_spoof": start_dns_spoof,
            "cloner": clone_site,
            "ghost_hub": GhostHubManager,
            "wifi": run_wifi_suite,
            "payload_forge": generate_shell,
            "cracker": start_crack,
            "auditor": run_auditor
        }

    def get_status_line(self):
        return f"[green]IFACE:[/green] {ctx.get('INTERFACE')} | [green]LHOST:[/green] {ctx.get('LHOST')} | [red]MODULE:[/red] {ctx.selected_module or 'None'}"

    def help(self):
        table = Table(title="Davoid Console Commands",
                      border_style="cyan", box=None)
        table.add_column("Command", style="bold yellow")
        table.add_column("Description", style="white")
        table.add_row("help", "Show this help menu")
        table.add_row("use <module>", "Select a module to work with")
        table.add_row("set <key> <val>", "Set a global or module variable")
        table.add_row("show options", "Display current configuration")
        table.add_row("show modules", "List all available modules")
        table.add_row("run", "Execute the selected module")
        table.add_row("back", "Deselect current module")
        table.add_row("exit / quit", "Terminate Davoid")
        console.print(table)

    def run_console(self):
        os.system('cls' if os.name == 'nt' else 'clear')
        draw_header("Interactive Command Hub",
                    status_info=self.get_status_line())

        while True:
            try:
                prompt_label = f"davoid({ctx.selected_module or 'root'})"
                cmd_input = console.input(
                    f"[bold red]{prompt_label}[/bold red] > ").strip().split()

                if not cmd_input:
                    continue

                cmd = cmd_input[0].lower()

                if cmd in ["exit", "quit", "q"]:
                    console.print(
                        "[yellow][*] Shutting down mainframe...[/yellow]")
                    break

                elif cmd == "help":
                    self.help()

                elif cmd == "show":
                    if len(cmd_input) > 1 and cmd_input[1] == "modules":
                        console.print(
                            f"[bold cyan]Available Modules:[/bold cyan] {', '.join(self.modules.keys())}")
                    elif len(cmd_input) > 1 and cmd_input[1] == "options":
                        table = Table(
                            title="Framework Configuration", border_style="magenta")
                        table.add_column("Variable", style="cyan")
                        table.add_column("Value", style="white")
                        for k, v in ctx.vars.items():
                            table.add_row(k, str(v))
                        console.print(table)

                elif cmd == "use":
                    if len(cmd_input) > 1:
                        mod_name = cmd_input[1].lower()
                        if mod_name in self.modules:
                            ctx.selected_module = mod_name
                        else:
                            console.print(
                                f"[red][!] Module '{mod_name}' not found.[/red]")
                    else:
                        console.print(
                            "[red][!] Usage: use <module_name>[/red]")

                elif cmd == "set":
                    if len(cmd_input) > 2:
                        ctx.set(cmd_input[1], cmd_input[2])
                        console.print(
                            f"[green][+] {cmd_input[1].upper()} => {cmd_input[2]}[/green]")
                    else:
                        console.print(
                            "[red][!] Usage: set <VARIABLE> <VALUE>[/red]")

                elif cmd == "run" or cmd == "exploit":
                    if ctx.selected_module:
                        # Clear screen for module execution
                        os.system('cls' if os.name == 'nt' else 'clear')
                        self.modules[ctx.selected_module]()
                        # After module finishes, redraw header
                        input(
                            "\nExecution Finished. Press Enter to return to console...")
                        os.system('cls' if os.name == 'nt' else 'clear')
                        draw_header("Interactive Command Hub",
                                    status_info=self.get_status_line())
                    else:
                        console.print(
                            "[red][!] No module selected. Use 'use <module>' first.[/red]")

                elif cmd == "back":
                    ctx.selected_module = None

                else:
                    console.print(
                        f"[red][!] Unknown command: {cmd}. Type 'help' for options.[/red]")

            except KeyboardInterrupt:
                console.print(
                    "\n[yellow][*] Use 'exit' to quit safely.[/yellow]")
            except Exception as e:
                console.print(f"[bold red][!] Console Error: {e}[/bold red]")


if __name__ == "__main__":
    app = DavoidConsole()
    app.run_console()
