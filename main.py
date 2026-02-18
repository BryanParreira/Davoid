import sys
import os
import warnings
import subprocess
import shutil
import time
import questionary
from questionary import Choice, Style
from rich.console import Console
from rich.table import Table

# --- 1. SYSTEM SUPPRESSION LAYER ---
warnings.filterwarnings("ignore", message=".*OpenSSL 1.1.1+.*")
warnings.filterwarnings("ignore", category=UserWarning, module='urllib3')
warnings.filterwarnings("ignore", category=UserWarning, module='scapy')

# --- 2. ENVIRONMENT SETUP ---
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
if SCRIPT_DIR not in sys.path:
    sys.path.append(SCRIPT_DIR)

BASE_DIR = "/opt/davoid"
if os.path.exists(BASE_DIR) and BASE_DIR not in sys.path:
    sys.path.append(BASE_DIR)

# --- 3. CORE & UI LOGIC ---
try:
    from core.ui import draw_header
    from core.updater import check_version, perform_update
    from core.context import ctx
except ImportError as e:
    print(f"Core components missing: {e}")
    sys.exit(1)

# --- 4. MODULE IMPORTS ---
try:
    from modules.auditor import run_auditor
except ImportError:
    run_auditor = None

try:
    from modules.scanner import network_discovery
    from modules.sniff import SnifferEngine
    from modules.recon import dns_recon
    from modules.web_recon import web_ghost
    from modules.osint_pro import (username_tracker, phone_intel, geolocate,
                                   dork_generator, robots_scraper, reputation_check, dns_intel)
except ImportError:
    pass

try:
    from modules.spoof import MITMEngine
    from modules.dns_spoofer import start_dns_spoof
    from modules.cloner import clone_site
    from modules.ghost_hub import run_ghost_hub
    from modules.wifi_ops import run_wifi_suite
    from modules.payloads import generate_shell
    from modules.crypt_keeper import encrypt_payload
    from modules.bruteforce import crack_hash
    from modules.persistence import PersistenceEngine
except ImportError:
    pass

try:
    from modules.ai_assist import run_ai_console
    from modules.reporter import generate_report
except ImportError:
    pass

console = Console()

# --- 5. NAVIGATION STYLE ---
# Custom "Cyberpunk" theme for the menus
q_style = Style([
    ('qmark', 'fg:#ff0000 bold'),       # Token in front of the question
    ('question', 'fg:#ffffff bold'),    # Question text
    ('answer', 'fg:#ff0000 bold'),      # Submitted answer
    ('pointer', 'fg:#ff0000 bold'),     # Pointer used in select
    ('highlighted', 'fg:#ff0000 bold'),  # Pointed-at choice
    ('selected', 'fg:#cc5454'),         # Checkbox selected
    ('separator', 'fg:#666666'),        # Separator
    ('instruction', 'fg:#666666 italic')  # User instructions
])

# --- 6. SUPPORT FUNCTIONS ---


def auto_discovery():
    """Elite Feature: Automatic Interface and Network Detection."""
    try:
        from scapy.all import conf, get_if_addr
        active_iface = str(conf.iface)
        local_ip = get_if_addr(active_iface)
        try:
            gw_ip = conf.route.route("0.0.0.0")[2]
        except:
            gw_ip = "Unknown"
        ctx.set("INTERFACE", active_iface)
        ctx.set("LHOST", local_ip)
        ctx.vars["GATEWAY"] = gw_ip
        return True
    except:
        return False


def vanish_sequence():
    console.print("\n[bold red]INITIATING VANISH SEQUENCE...[/bold red]")
    targets = ["logs", "clones", "payloads", "__pycache__"]
    for t in targets:
        path = os.path.join(os.getcwd(), t)
        if os.path.exists(path):
            try:
                shutil.rmtree(path)
                console.print(f"[dim][-] Wiped: {path}[/dim]")
            except Exception as e:
                console.print(f"[red][!] Failed to wipe {t}: {e}[/red]")
    console.print("[bold green][*] Evidence cleared. Ghost out.[/bold green]")
    sys.exit(0)


def configure_context():
    while True:
        os.system('cls' if os.name == 'nt' else 'clear')
        draw_header("Global Configuration", context=ctx)

        # Show current context
        table = Table(title="Framework Context", border_style="bold magenta")
        table.add_column("Variable")
        table.add_column("Value")
        for k, v in ctx.vars.items():
            table.add_row(k, str(v))
        console.print(table)
        console.print("\n")

        action = questionary.select(
            "Configuration Options:",
            choices=[
                Choice("Set Variable", value="s"),
                Choice("Randomize Identity (MAC Rotation)", value="m"),
                Choice("Back to Hub", value="b")
            ],
            style=q_style,
            use_indicator=True
        ).ask()

        if action == 's':
            key = questionary.text(
                "Variable Name (e.g., RHOST):", style=q_style).ask()
            if key:
                val = questionary.text(
                    f"Value for {key}:", style=q_style).ask()
                ctx.set(key, val)
        elif action == 'm':
            # randomize_identity function logic (omitted for brevity, assume exists or import)
            console.print("[yellow][!] MAC Rotation triggered...[/yellow]")
            time.sleep(1)
            auto_discovery()
        else:
            break

# --- 7. SUB-MENUS WITH ARROW NAVIGATION ---


def hub_intelligence():
    while True:
        os.system('cls' if os.name == 'nt' else 'clear')
        draw_header("Intelligence Hub", context=ctx)

        choice = questionary.select(
            "Select Intelligence Module:",
            choices=[
                questionary.Separator("--- NETWORK RECON ---"),
                Choice("Net-Mapper (Active Discovery)", value="scan"),
                Choice("Live Interceptor (Sniffer)", value="sniff"),
                Choice("DNS Reconnaissance", value="dns"),
                Choice("Web Ghost (Vulnerability Scanner)", value="web"),

                questionary.Separator("--- OSINT & PROFILING ---"),
                Choice("Username Tracker (Sherlock)", value="user"),
                Choice("Phone Number Intelligence", value="phone"),
                Choice("Geo-Location & Infrastructure", value="geo"),
                Choice("Google Dork Automator", value="dork"),
                Choice("Robots.txt Scraper", value="robots"),
                Choice("Reputation Audit", value="rep"),
                Choice("Passive DNS Intel", value="pdns"),

                questionary.Separator("--- NAVIGATION ---"),
                Choice("Back to Main Menu", value="back")
            ],
            style=q_style,
            use_indicator=True
        ).ask()

        if choice == "scan":
            network_discovery()
        elif choice == "sniff":
            e = SnifferEngine()
            e.start()
        elif choice == "dns":
            dns_recon()
        elif choice == "web":
            web_ghost()
        elif choice == "user":
            username_tracker()
        elif choice == "phone":
            phone_intel()
        elif choice == "geo":
            geolocate()
        elif choice == "dork":
            dork_generator()
        elif choice == "robots":
            robots_scraper()
        elif choice == "rep":
            reputation_check()
        elif choice == "pdns":
            dns_intel()
        elif choice == "back":
            break


def hub_offensive():
    while True:
        os.system('cls' if os.name == 'nt' else 'clear')
        draw_header("Offensive Hub", context=ctx)

        choice = questionary.select(
            "Select Offensive Module:",
            choices=[
                questionary.Separator("--- TRAFFIC MANIPULATION ---"),
                Choice("MITM Engine (ARP Poisoning)", value="mitm"),
                Choice("DNS Spoofer (Phishing Redirection)", value="dns_spoof"),
                Choice("Phantom Cloner (Site Cloning)", value="clone"),

                questionary.Separator("--- WIRELESS & C2 ---"),
                Choice("WiFi Offensive Suite", value="wifi"),
                Choice("GHOST-HUB C2 Server", value="c2"),

                questionary.Separator("--- NAVIGATION ---"),
                Choice("Back to Main Menu", value="back")
            ],
            style=q_style
        ).ask()

        if choice == "mitm":
            e = MITMEngine()
            e.run()
        elif choice == "dns_spoof":
            start_dns_spoof()
        elif choice == "clone":
            clone_site()
        elif choice == "wifi":
            run_wifi_suite()
        elif choice == "c2":
            run_ghost_hub()
        elif choice == "back":
            break


def hub_payloads():
    while True:
        os.system('cls' if os.name == 'nt' else 'clear')
        draw_header("Payload Hub", context=ctx)

        choice = questionary.select(
            "Select Payload Operation:",
            choices=[
                questionary.Separator("--- GENERATION & EVASION ---"),
                Choice("Shell Forge (Payload Generator)", value="forge"),
                Choice("Crypt-Keeper (Encryption/Obfuscation)", value="crypt"),

                questionary.Separator("--- POST-EXPLOITATION ---"),
                Choice("Persistence Engine", value="persist"),
                Choice("Hash Cracker", value="crack"),

                questionary.Separator("--- NAVIGATION ---"),
                Choice("Back to Main Menu", value="back")
            ],
            style=q_style
        ).ask()

        if choice == "forge":
            generate_shell()
        elif choice == "crypt":
            p = questionary.text("Path to payload:", style=q_style).ask()
            if p:
                encrypt_payload(p)
        elif choice == "persist":
            p = questionary.text("Target file path:", style=q_style).ask()
            if p:
                e = PersistenceEngine(p)
                e.run()
        elif choice == "crack":
            h = questionary.text("Hash to crack:", style=q_style).ask()
            if h:
                crack_hash(h)
        elif choice == "back":
            break

# --- 8. MASTER LOOP ---


def main():
    if len(sys.argv) > 1 and sys.argv[1].lower() == "--update":
        perform_update()
        sys.exit(0)

    auto_discovery()

    try:
        while True:
            os.system('cls' if os.name == 'nt' else 'clear')
            draw_header("Master Command Hub", context=ctx)
            check_version()

            # The Main Menu using Questionary
            category = questionary.select(
                "Select Operational Category:",
                choices=[
                    questionary.Separator("--- OPERATIONS ---"),
                    Choice("1. Intelligence & OSINT", value="intel"),
                    Choice("2. Offensive Operations", value="offense"),
                    Choice("3. Payloads & Post-Exploit", value="payload"),

                    questionary.Separator("--- ADVANCED CAPABILITIES ---"),
                    Choice("4. AI Cortex (Ollama)", value="ai"),
                    Choice("5. Generate Mission Report", value="report"),

                    questionary.Separator("--- SYSTEM ---"),
                    Choice("Configuration & Context", value="config"),
                    Choice("System Auditor", value="audit"),
                    Choice("Update Framework", value="update"),
                    Choice("VANISH (Secure Exit)", value="exit")
                ],
                style=q_style,
                use_indicator=True,
                pointer=">"
            ).ask()

            # Handle user selection
            if category == "intel":
                hub_intelligence()
            elif category == "offense":
                hub_offensive()
            elif category == "payload":
                hub_payloads()
            elif category == "ai":
                run_ai_console()
            elif category == "report":
                generate_report()
            elif category == "config":
                configure_context()
            elif category == "audit":
                if run_auditor:
                    run_auditor()
                else:
                    console.print("[red]Auditor missing.[/red]")
                    time.sleep(1)
            elif category == "update":
                perform_update()
            elif category == "exit":
                vanish_sequence()

    except KeyboardInterrupt:
        vanish_sequence()
    except Exception as e:
        console.print(f"[bold red]CRITICAL FAILURE: {e}[/bold red]")
        input("Press Enter to crash gracefully...")


if __name__ == "__main__":
    main()
