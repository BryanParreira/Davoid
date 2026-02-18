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
# Suppress noisy warnings from libraries to keep the terminal clean
warnings.filterwarnings("ignore", message=".*OpenSSL 1.1.1+.*")
warnings.filterwarnings("ignore", category=UserWarning, module='urllib3')
warnings.filterwarnings("ignore", category=UserWarning, module='scapy')

# --- 2. ENVIRONMENT SETUP ---
# Ensure the script can always find its modules, even if run from root
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
if SCRIPT_DIR not in sys.path:
    sys.path.append(SCRIPT_DIR)

# Fallback path for global installations
BASE_DIR = "/opt/davoid"
if os.path.exists(BASE_DIR) and BASE_DIR not in sys.path:
    sys.path.append(BASE_DIR)

# --- 3. CORE & UI LOGIC ---
try:
    from core.ui import draw_header
    from core.updater import check_version, perform_update
    from core.context import ctx
    # Attempt to load the new config engine
    try:
        from core.config import load_config
    except ImportError:
        def load_config(): return None
except ImportError as e:
    print(f"Core components missing: {e}")
    sys.exit(1)

# --- 4. MODULE IMPORTS ---
# A. System Tools
try:
    from modules.auditor import run_auditor
except ImportError:
    run_auditor = None

# B. Intelligence & Recon
try:
    from modules.scanner import network_discovery
    from modules.sniff import SnifferEngine
    from modules.recon import dns_recon
    from modules.web_recon import web_ghost
    from modules.osint_pro import (username_tracker, phone_intel, geolocate,
                                   dork_generator, robots_scraper, reputation_check, dns_intel)
except ImportError:
    pass

# C. Offensive Operations
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

# D. Advanced Capabilities (AI & Reporting)
try:
    from modules.ai_assist import run_ai_console
    from modules.reporter import generate_report
except ImportError:
    pass

console = Console()

# --- 5. NAVIGATION STYLE ---
# "Cyberpunk" theme for the interactive menus
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
        # Handle potential route errors gracefully
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
    """
    [SAFETY] Forensics Counter-Measure.
    Wipes all logs, captures, and temporary files created during the session.
    """
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
    """Interactive Configuration Menu."""
    while True:
        os.system('cls' if os.name == 'nt' else 'clear')
        draw_header("Global Configuration", context=ctx)

        # Display current context table
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
            # Trigger MAC Rotation Logic
            iface = ctx.get("INTERFACE") or "eth0"
            console.print(f"[dim][*] Rotating Identity on {iface}...[/dim]")
            try:
                # Preferred: Macchanger
                if shutil.which("macchanger"):
                    subprocess.run(["ifconfig", iface, "down"],
                                   check=False, stdout=subprocess.DEVNULL)
                    subprocess.run(["macchanger", "-r", iface],
                                   check=False, stdout=subprocess.DEVNULL)
                    subprocess.run(["ifconfig", iface, "up"],
                                   check=False, stdout=subprocess.DEVNULL)
                    console.print(
                        f"[bold green][+] Identity Randomized (Macchanger)[/bold green]")
                else:
                    # Fallback: Manual Link
                    import random
                    mac = "02:00:00:%02x:%02x:%02x" % (random.randint(
                        0, 255), random.randint(0, 255), random.randint(0, 255))
                    subprocess.run(
                        f"ip link set dev {iface} address {mac}", shell=True, stderr=subprocess.DEVNULL)
                    console.print(
                        f"[bold green][+] Identity Randomized (Manual Link)[/bold green]")

                # Re-discover IP after MAC change
                time.sleep(2)
                auto_discovery()
            except Exception as e:
                console.print(
                    f"[yellow][!] Identity Rotation Skipped: {e}[/yellow]")
                time.sleep(1)
        else:
            break

# --- 7. SUB-MENUS WITH ARROW NAVIGATION ---


def hub_intelligence():
    """Intelligence Hub Menu"""
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
    """Offensive Hub Menu"""
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
            try:
                e = MITMEngine()
                e.run()
            except Exception as e:
                console.print(f"[red][!] MITM Error: {e}[/red]")
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
    """Payload Hub Menu"""
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
            p = console.input("[bold yellow]Path to payload: [/bold yellow]")
            if p:
                encrypt_payload(p)
        elif choice == "persist":
            p = console.input("[bold yellow]Target file path: [/bold yellow]")
            if p:
                e = PersistenceEngine(p)
                e.run()
        elif choice == "crack":
            h = console.input("[bold yellow]Hash to crack: [/bold yellow]")
            if h:
                crack_hash(h)
        elif choice == "back":
            break

# --- 8. MASTER LOOP ---


def main():
    """Master Hub: Categorized Operational Command."""

    # CLI Argument: Auto-Update
    if len(sys.argv) > 1 and sys.argv[1].lower() == "--update":
        perform_update()
        sys.exit(0)

    # 1. Automatic Discovery
    auto_discovery()

    # 2. Load Configuration (if exists)
    config = load_config()
    if config:
        sys_conf = config.get('system', {})
        # Apply default interface override
        if sys_conf.get('default_interface', 'auto') != 'auto':
            ctx.set("INTERFACE", sys_conf['default_interface'])

    try:
        while True:
            os.system('cls' if os.name == 'nt' else 'clear')
            # Updated header logic from core.ui will be used here
            draw_header("Master Command Hub", context=ctx)
            check_version()

            # The Main Menu using Questionary for Arrow-Key Navigation
            category = questionary.select(
                "Select Operational Category:",
                choices=[
                    questionary.Separator("--- OPERATIONS ---"),
                    Choice("1. Intelligence & OSINT", value="intel"),
                    Choice("2. Offensive Operations", value="offense"),
                    Choice("3. Payloads & Post-Exploit", value="payload"),

                    questionary.Separator("--- ADVANCED CAPABILITIES ---"),
                    Choice("4. AI Cortex (Ollama)", value="ai"),
                    Choice("5. Generate Threat Map", value="report"),

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
                    console.input("\n[dim]Press Enter to return...[/dim]")
                else:
                    console.print("[red]Auditor module missing.[/red]")
                    time.sleep(1)
            elif category == "update":
                perform_update()
            elif category == "exit":
                # Optional confirmation
                if questionary.confirm("Are you sure you want to vanish?", default=True, style=q_style).ask():
                    vanish_sequence()

    except KeyboardInterrupt:
        # Catch Ctrl+C and offer cleanup
        vanish_sequence()
    except Exception as e:
        console.print(
            f"\n[bold red][!] CRITICAL MAIN LOOP ERROR:[/bold red] {e}")
        console.input("\nPress Enter to restart loop...")


if __name__ == "__main__":
    main()
