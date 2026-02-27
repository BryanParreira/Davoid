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

# ============================================================================
# 1. SYSTEM CONFIGURATION & PATHS
# ============================================================================
warnings.filterwarnings("ignore", message=".*OpenSSL 1.1.1+.*")
warnings.filterwarnings("ignore", category=UserWarning, module='urllib3')
warnings.filterwarnings("ignore", category=UserWarning, module='scapy')

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
if SCRIPT_DIR not in sys.path:
    sys.path.append(SCRIPT_DIR)
BASE_DIR = "/opt/davoid"
if os.path.exists(BASE_DIR) and BASE_DIR not in sys.path:
    sys.path.append(BASE_DIR)

# ============================================================================
# 2. CORE IMPORTS & SAFE MODULE LOADING
# ============================================================================
try:
    from core.ui import draw_header
    from core.updater import check_version, perform_update
    from core.context import ctx
    from core.database import db
    try:
        from core.config import load_config
    except ImportError:
        def load_config(): return None
except ImportError as e:
    print(f"[!] Critical core components missing: {e}")
    sys.exit(1)

# Safely wrap module imports so a single missing dependency doesn't crash the hub
try:
    from modules.auditor import run_auditor
except ImportError:
    run_auditor = None

try:
    from modules.looter import run_looter
except ImportError:
    run_looter = None

try:
    from modules.scanner import network_discovery
except ImportError:
    network_discovery = None

try:
    from modules.sniff import SnifferEngine
except ImportError:
    SnifferEngine = None

try:
    from modules.recon import dns_recon
except ImportError:
    dns_recon = None

try:
    from modules.web_recon import web_ghost
except ImportError:
    web_ghost = None

try:
    from modules.osint_pro import (
        username_tracker, phone_intel, geolocate, dork_generator, wayback_intel, shodan_intel, dns_intel)
except ImportError:
    username_tracker = phone_intel = geolocate = dork_generator = wayback_intel = shodan_intel = dns_intel = None

try:
    from modules.spoof import MITMEngine
except ImportError:
    MITMEngine = None

try:
    from modules.dns_spoofer import start_dns_spoof
except ImportError:
    start_dns_spoof = None

try:
    from modules.cloner import run_cloner
except ImportError:
    run_cloner = None

try:
    from modules.ghost_hub import run_ghost_hub
except ImportError:
    run_ghost_hub = None

try:
    from modules.wifi_ops import run_wifi_suite
except ImportError:
    run_wifi_suite = None

try:
    from modules.payloads import generate_shell
except ImportError:
    generate_shell = None

try:
    from modules.crypt_keeper import encrypt_payload
except ImportError:
    encrypt_payload = None

try:
    from modules.bruteforce import crack_hash
except ImportError:
    crack_hash = None

try:
    from modules.persistence import PersistenceEngine
except ImportError:
    PersistenceEngine = None

try:
    from modules.ai_assist import run_ai_console
except ImportError:
    run_ai_console = None

try:
    from modules.reporter import generate_report
except ImportError:
    generate_report = None

try:
    from modules.ad_ops import run_ad_ops
except ImportError:
    run_ad_ops = None

try:
    from modules.msf_engine import run_msf
except ImportError:
    run_msf = None

# ============================================================================
# 3. GLOBAL UI STYLING
# ============================================================================
console = Console()
q_style = Style([
    ('qmark', 'fg:#ff0000 bold'), ('question', 'fg:#ffffff bold'),
    ('answer', 'fg:#ff0000 bold'), ('pointer', 'fg:#ff0000 bold'),
    ('highlighted', 'fg:#ff0000 bold'), ('selected', 'fg:#cc5454'),
    ('separator', 'fg:#666666'), ('instruction', 'fg:#666666 italic')
])

# ============================================================================
# 4. SYSTEM OPERATION FUNCTIONS
# ============================================================================


def detect_network_environment():
    """Automatically fingerprints the host's networking context (IP, Gateway, IFace)."""
    try:
        from scapy.all import conf, get_if_addr
        ctx.set("INTERFACE", str(conf.iface))
        ctx.set("LHOST", get_if_addr(str(conf.iface)))

        gw = "Unknown"
        try:
            if sys.platform == "darwin":  # macOS
                out = subprocess.check_output(
                    ["route", "-n", "get", "default"]).decode()
                for line in out.splitlines():
                    if "gateway:" in line:
                        gw = line.split(":")[1].strip()
                        break
            else:  # Linux
                out = subprocess.check_output(["ip", "route"]).decode()
                for line in out.splitlines():
                    if line.startswith("default via"):
                        gw = line.split(" ")[2].strip()
                        break
        except Exception:
            pass

        if gw == "Unknown":
            gw = conf.route.route("0.0.0.0")[1]

        ctx.set("GATEWAY", str(gw))
        return True
    except:
        return False


def execute_vanish_protocol():
    """Wipes generated artifacts and exits the framework cleanly."""
    console.print("\n[bold red]INITIATING VANISH SEQUENCE...[/bold red]")
    for target_dir in ["logs", "clones", "payloads", "__pycache__"]:
        if os.path.exists(target_dir):
            shutil.rmtree(target_dir, ignore_errors=True)
    console.print("[bold green][*] Evidence cleared. Ghost out.[/bold green]")
    sys.exit(0)


def configure_global_context():
    """UI for viewing and overriding global variables."""
    while True:
        os.system('cls' if os.name == 'nt' else 'clear')
        draw_header("Global Configuration", context=ctx)

        table = Table(title="Mission Context", border_style="bold magenta")
        table.add_column("Variable")
        table.add_column("Value")
        for k, v in ctx.vars.items():
            table.add_row(k, str(v))
        console.print(table)
        console.print("\n")

        action = questionary.select(
            "Options:",
            choices=[
                Choice("Set Variable", value="set"),
                Choice("Rotate Identity (Refresh Network Context)", value="rotate"),
                Choice("Back", value="back")
            ],
            style=q_style
        ).ask()

        if not action or action == 'back':
            break
        elif action == 'set':
            key = questionary.text(
                "Variable Name (Leave blank to cancel):", style=q_style).ask()
            if key:
                val = questionary.text(
                    f"Value for {key}:", style=q_style).ask()
                ctx.set(key, val)
        elif action == 'rotate':
            console.print("[dim]Refreshing Network Identity...[/dim]")
            time.sleep(1)
            detect_network_environment()


def safe_execute(func, *args, **kwargs):
    """Gracefully handles execution of a module if it's missing dependencies."""
    if func is None:
        console.print(
            "\n[bold red][!] Module offline or missing dependencies.[/bold red]")
        time.sleep(1.5)
        return
    func(*args, **kwargs)

# ============================================================================
# 5. ACTION ROUTERS & MENU HANDLERS
# ============================================================================


def run_net_scan():
    sub = questionary.select("Tool:", choices=[
                             "Active Discovery", "Passive Sniffer", "Back"], style=q_style).ask()
    if not sub or sub == "Back":
        return
    if "Active" in sub:
        safe_execute(network_discovery)
    else:
        safe_execute(lambda: SnifferEngine().start()
                     if SnifferEngine else None)


def run_person_osint():
    sub = questionary.select("Mode:", choices=[
                             "Username Tracker", "Phone Intel", "Back"], style=q_style).ask()
    if not sub or sub == "Back":
        return
    if "Username" in sub:
        safe_execute(username_tracker)
    else:
        safe_execute(phone_intel)


def run_ai_ops():
    sub = questionary.select("AI Ops:", choices=[
                             "Launch Cortex", "Generate Report (DB)", "Back"], style=q_style).ask()
    if not sub or sub == "Back":
        return
    if "Cortex" in sub:
        safe_execute(run_ai_console)
    else:
        safe_execute(generate_report)


def run_mitm():
    safe_execute(lambda: MITMEngine().run() if MITMEngine else None)


def run_encrypt():
    if encrypt_payload is None:
        return safe_execute(None)
    path = questionary.text(
        "Path (Leave blank to cancel):", style=q_style).ask()
    if path:
        encrypt_payload(path)


def run_persist():
    if PersistenceEngine is None:
        return safe_execute(None)
    path = questionary.text(
        "Path (Leave blank to cancel):", style=q_style).ask()
    if path:
        PersistenceEngine(path).run()


def show_reconnaissance_menu():
    actions = {
        "net": run_net_scan,
        "web": lambda: safe_execute(web_ghost),
        "shodan": lambda: safe_execute(shodan_intel),
        "dns": lambda: safe_execute(dns_intel),
        "wayback": lambda: safe_execute(wayback_intel),
        "dork": lambda: safe_execute(dork_generator),
        "person": run_person_osint,
        "geo": lambda: safe_execute(geolocate)
    }

    while True:
        os.system('cls' if os.name == 'nt' else 'clear')
        draw_header("Target Acquisition & Intelligence", context=ctx)

        choice = questionary.select("Select Recon Module:", choices=[
            questionary.Separator("--- ACTIVE SCANNING ---"),
            Choice("Network Scanner (Nmap)", value="net"),
            Choice("Web Vulnerability Scanner", value="web"),
            questionary.Separator("--- PASSIVE OSINT ---"),
            Choice("Shodan API (Attack Surface)", value="shodan"),
            Choice("DNS & Subdomain Mapping", value="dns"),
            questionary.Separator("--- DEEP WEB ---"),
            Choice("Wayback Machine (Archive Mining)", value="wayback"),
            Choice("Google Dork Generator", value="dork"),
            questionary.Separator("--- IDENTITY / GEO ---"),
            Choice("Social OSINT (Identity)", value="person"),
            Choice("Geo-IP Tracker", value="geo"),
            questionary.Separator("--- NAVIGATION ---"),
            Choice("Return to Main Menu", value="back")
        ], style=q_style).ask()

        if not choice or choice == "back":
            break
        if choice in actions:
            actions[choice]()


def show_assault_menu():
    actions = {
        "msf": lambda: safe_execute(run_msf),
        "ad": lambda: safe_execute(run_ad_ops),
        "loot": lambda: safe_execute(run_looter),
        "mitm": run_mitm,
        "dns": lambda: safe_execute(start_dns_spoof),
        "wifi": lambda: safe_execute(run_wifi_suite),
        "clone": lambda: safe_execute(run_cloner),
        "crack": lambda: safe_execute(crack_hash)
    }

    while True:
        os.system('cls' if os.name == 'nt' else 'clear')
        draw_header("Direct Action", context=ctx)

        choice = questionary.select("Select Assault Vector:", choices=[
            questionary.Separator("--- EXPLOITATION ---"),
            Choice("Metasploit Framework", value="msf"),
            Choice("Active Directory Ops", value="ad"),
            Choice("PrivEsc Looter", value="loot"),
            questionary.Separator("--- NETWORK ATTACKS ---"),
            Choice("MITM Interceptor", value="mitm"),
            Choice("DNS Spoofer", value="dns"),
            Choice("WiFi Attack Suite", value="wifi"),
            questionary.Separator("--- SOCIAL & CRYPTO ---"),
            Choice("AitM Web Cloner", value="clone"),
            Choice("Hash Cracker", value="crack"),
            questionary.Separator("--- NAVIGATION ---"),
            Choice("Return to Main Menu", value="back")
        ], style=q_style).ask()

        if not choice or choice == "back":
            break
        if choice in actions:
            actions[choice]()


def show_infrastructure_menu():
    actions = {
        "forge": lambda: safe_execute(generate_shell),
        "crypt": run_encrypt,
        "persist": run_persist,
        "c2": lambda: safe_execute(run_ghost_hub)
    }

    while True:
        os.system('cls' if os.name == 'nt' else 'clear')
        draw_header("Infrastructure & C2", context=ctx)

        choice = questionary.select("Select C2 Operation:", choices=[
            questionary.Separator("--- WEAPONIZATION ---"),
            Choice("Payload Generator", value="forge"),
            Choice("Payload Encryptor", value="crypt"),
            questionary.Separator("--- PERSISTENCE & COMMAND ---"),
            Choice("Persistence Installer", value="persist"),
            Choice("GhostHub C2 Server", value="c2"),
            questionary.Separator("--- NAVIGATION ---"),
            Choice("Return to Main Menu", value="back")
        ], style=q_style).ask()

        if not choice or choice == "back":
            break
        if choice in actions:
            actions[choice]()

# ============================================================================
# 6. MAIN EXECUTION LOOP
# ============================================================================


def main():
    if len(sys.argv) > 1 and sys.argv[1] == "--update":
        perform_update()
        sys.exit(0)

    detect_network_environment()
    config = load_config()

    actions = {
        "recon": show_reconnaissance_menu,
        "assault": show_assault_menu,
        "infra": show_infrastructure_menu,
        "ai": run_ai_ops,
        "sys": configure_global_context,
        "update": perform_update
    }

    while True:
        try:
            os.system('cls' if os.name == 'nt' else 'clear')
            draw_header("Master Command Hub", context=ctx)
            check_version()

            phase = questionary.select("Select Mission Phase:", choices=[
                questionary.Separator("--- OFFENSIVE OPS ---"),
                Choice("1. Recon & OSINT", value="recon"),
                Choice("2. Assault & Exploitation", value="assault"),
                Choice("3. C2 & Payloads", value="infra"),
                questionary.Separator("--- INTELLIGENCE ---"),
                Choice("4. AI Cortex & Reporting", value="ai"),
                questionary.Separator("--- SYSTEM ---"),
                Choice("Configuration & Context", value="sys"),
                Choice("Framework Update", value="update"),
                Choice("Execute Vanish Protocol", value="exit")
            ], style=q_style, pointer=">").ask()

            if not phase:  # Handles Esc/Ctrl+C gracefully
                continue

            if phase == "exit":
                if questionary.confirm("Execute Vanish Protocol?", default=True, style=q_style).ask():
                    execute_vanish_protocol()
            elif phase in actions:
                actions[phase]()

        except KeyboardInterrupt:
            execute_vanish_protocol()
        except Exception as e:
            console.print(
                f"[bold red]Critical Error in Main Loop:[/bold red] {e}")
            input("Press Enter to continue...")


if __name__ == "__main__":
    main()
