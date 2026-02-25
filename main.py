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
try: from modules.auditor import run_auditor
except ImportError: run_auditor = None

try: from modules.looter import run_looter
except ImportError: pass

try: from modules.scanner import network_discovery
except ImportError: pass

try: from modules.sniff import SnifferEngine
except ImportError: pass

try: from modules.recon import dns_recon
except ImportError: pass

try: from modules.web_recon import web_ghost
except ImportError: pass

try: from modules.osint_pro import (username_tracker, phone_intel, geolocate, dork_generator, wayback_intel, shodan_intel, dns_intel)
except ImportError: pass

try: from modules.spoof import MITMEngine
except ImportError: pass

try: from modules.dns_spoofer import start_dns_spoof
except ImportError: pass

try: from modules.cloner import clone_site
except ImportError: pass

try: from modules.ghost_hub import run_ghost_hub
except ImportError: pass

try: from modules.wifi_ops import run_wifi_suite
except ImportError: pass

try: from modules.payloads import generate_shell
except ImportError: pass

try: from modules.crypt_keeper import encrypt_payload
except ImportError: pass

try: from modules.bruteforce import crack_hash
except ImportError: pass

try: from modules.persistence import PersistenceEngine
except ImportError: pass

try: from modules.ai_assist import run_ai_console
except ImportError: pass

try: from modules.reporter import generate_report
except ImportError: pass

try: from modules.ad_ops import run_ad_ops
except ImportError: pass

try: from modules.msf_engine import run_msf
except ImportError: pass

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
                out = subprocess.check_output(["route", "-n", "get", "default"]).decode()
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
            key = questionary.text("Variable Name (Leave blank to cancel):", style=q_style).ask()
            if key:
                val = questionary.text(f"Value for {key}:", style=q_style).ask()
                ctx.set(key, val)
        elif action == 'rotate':
            console.print("[dim]Refreshing Network Identity...[/dim]")
            time.sleep(1)
            detect_network_environment()

# ============================================================================
# 5. MENU ROUTERS
# ============================================================================

def show_reconnaissance_menu():
    while True:
        os.system('cls' if os.name == 'nt' else 'clear')
        draw_header("Target Acquisition & Intelligence", context=ctx)
        
        choice = questionary.select("Select Reconnaissance Module:", choices=[
            questionary.Separator("--- ACTIVE NETWORK SCANNING ---"),
            Choice("Network Mapper (Nmap & ExploitDB)", value="net"),
            Choice("Web Vulnerability Scanner & Fuzzer", value="web"),
            questionary.Separator("--- PASSIVE INFRASTRUCTURE OSINT ---"),
            Choice("Shodan API (Attack Surface Recon)", value="shodan"),
            Choice("DNS & Subdomain Mapping (CRT.sh)", value="dns"),
            questionary.Separator("--- DEEP WEB & ARCHIVE MINING ---"),
            Choice("Wayback Machine (Hidden Endpoint Mining)", value="wayback"),
            Choice("Google Dork Generator (Advanced Search)", value="dork"),
            questionary.Separator("--- IDENTITY & GEO-TRACKING ---"),
            Choice("Social OSINT (Identity Profiling)", value="person"),
            Choice("Geo-IP Tracker (Location Profiling)", value="geo"),
            questionary.Separator("--- NAVIGATION ---"),
            Choice("Return to Main Menu", value="back")
        ], style=q_style).ask()

        if not choice or choice == "back": break

        if choice == "net":
            sub = questionary.select("Tool:", choices=["Active Discovery", "Passive Sniffer", "Back"], style=q_style).ask()
            if not sub or sub == "Back": continue
            if "Active" in sub: network_discovery()
            else: SnifferEngine().start()
        elif choice == "web": web_ghost()
        elif choice == "shodan": shodan_intel()
        elif choice == "wayback": wayback_intel()
        elif choice == "dork": dork_generator()
        elif choice == "dns": dns_intel()
        elif choice == "person":
            sub = questionary.select("Mode:", choices=["Username Tracker", "Phone Intel", "Back"], style=q_style).ask()
            if not sub or sub == "Back": continue
            if "Username" in sub: username_tracker()
            else: phone_intel()
        elif choice == "geo": geolocate()

def show_assault_menu():
    while True:
        os.system('cls' if os.name == 'nt' else 'clear')
        draw_header("Direct Action", context=ctx)
        
        choice = questionary.select("Select Assault Vector:", choices=[
            questionary.Separator("--- EXPLOITATION & POST-EXPLOITATION ---"),
            Choice("Metasploit Framework (RPC Engine)", value="msf"),
            Choice("Active Directory Exploitation", value="ad"),
            Choice("Privilege Escalation & Looter", value="loot"),
            questionary.Separator("--- NETWORK ATTACKS ---"),
            Choice("Adversary-in-the-Middle (MITM) Intercept", value="mitm"),
            Choice("DNS Spoofing & Traffic Hijacking", value="dns"),
            Choice("Wireless (WiFi) Attack Suite", value="wifi"),
            questionary.Separator("--- SOCIAL ENGINEERING & CRYPTO ---"),
            Choice("Web Cloner & MFA Bypass Proxy", value="clone"),
            Choice("Cryptographic Hash Cracker", value="crack"),
            questionary.Separator("--- NAVIGATION ---"),
            Choice("Return to Main Menu", value="back")
        ], style=q_style).ask()

        if not choice or choice == "back": break

        if choice == "msf": run_msf()
        elif choice == "ad": run_ad_ops()
        elif choice == "loot": run_looter()
        elif choice == "mitm": MITMEngine().run()
        elif choice == "dns": start_dns_spoof()
        elif choice == "wifi": run_wifi_suite()
        elif choice == "clone": clone_site()
        elif choice == "crack":
            hash_val = questionary.text("Hash (Leave blank to cancel):", style=q_style).ask()
            if hash_val: crack_hash(hash_val)

def show_infrastructure_menu():
    while True:
        os.system('cls' if os.name == 'nt' else 'clear')
        draw_header("Infrastructure & C2", context=ctx)
        
        choice = questionary.select("Select Infrastructure Operation:", choices=[
            questionary.Separator("--- WEAPONIZATION ---"),
            Choice("Payload Generator (C2 Beacons & Shells)", value="forge"),
            Choice("Payload Obfuscator & Encryptor", value="crypt"),
            questionary.Separator("--- PERSISTENCE & COMMAND ---"),
            Choice("Persistence Installer (Target Auto-Run)", value="persist"),
            Choice("Launch GhostHub (Dual-Stack C2 Server)", value="c2"),
            questionary.Separator("--- NAVIGATION ---"),
            Choice("Return to Main Menu", value="back")
        ], style=q_style).ask()

        if not choice or choice == "back": break

        if choice == "forge": generate_shell()
        elif choice == "crypt":
            path = questionary.text("Path (Leave blank to cancel):", style=q_style).ask()
            if path: encrypt_payload(path)
        elif choice == "persist":
            path = questionary.text("Path (Leave blank to cancel):", style=q_style).ask()
            if path: PersistenceEngine(path).run()
        elif choice == "c2": run_ghost_hub()

# ============================================================================
# 6. MAIN EXECUTION LOOP
# ============================================================================

def main():
    if len(sys.argv) > 1 and sys.argv[1] == "--update":
        perform_update()
        sys.exit(0)
        
    detect_network_environment()
    config = load_config()

    while True:
        try:
            os.system('cls' if os.name == 'nt' else 'clear')
            draw_header("Master Command Hub", context=ctx)
            check_version()

            phase = questionary.select("Select Mission Phase:", choices=[
                questionary.Separator("--- OFFENSIVE OPERATIONS ---"),
                Choice("1. Reconnaissance & OSINT", value="recon"),
                Choice("2. Assault & Exploitation", value="assault"),
                Choice("3. C2 Infrastructure & Payloads", value="infra"),
                questionary.Separator("--- INTELLIGENCE ---"),
                Choice("4. AI Cortex & Mission Reporting", value="ai"),
                questionary.Separator("--- SYSTEM ---"),
                Choice("Configuration & Context", value="sys"),
                Choice("Framework Update", value="update"),
                Choice("Execute Vanish Protocol", value="exit")
            ], style=q_style, pointer=">").ask()

            if not phase:  # Handles Esc/Ctrl+C gracefully
                continue

            if phase == "recon": show_reconnaissance_menu()
            elif phase == "assault": show_assault_menu()
            elif phase == "infra": show_infrastructure_menu()
            elif phase == "ai":
                sub = questionary.select("AI Ops:", choices=["Launch Cortex", "Generate Report (DB)", "Back"], style=q_style).ask()
                if not sub or sub == "Back": continue
                if "Cortex" in sub: run_ai_console()
                else: generate_report()
            elif phase == "sys": configure_global_context()
            elif phase == "update": perform_update()
            elif phase == "exit":
                if questionary.confirm("Execute Vanish Protocol?", default=True, style=q_style).ask():
                    execute_vanish_protocol()
                    
        except KeyboardInterrupt:
            execute_vanish_protocol()
        except Exception as e:
            console.print(f"[bold red]Critical Error in Main Loop:[/bold red] {e}")
            input("Press Enter to continue...")

if __name__ == "__main__":
    main()