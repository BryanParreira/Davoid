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

# --- 1. SYSTEM CONFIG ---
warnings.filterwarnings("ignore", message=".*OpenSSL 1.1.1+.*")
warnings.filterwarnings("ignore", category=UserWarning, module='urllib3')
warnings.filterwarnings("ignore", category=UserWarning, module='scapy')

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
if SCRIPT_DIR not in sys.path:
    sys.path.append(SCRIPT_DIR)
BASE_DIR = "/opt/davoid"
if os.path.exists(BASE_DIR) and BASE_DIR not in sys.path:
    sys.path.append(BASE_DIR)

# --- 2. IMPORTS ---
try:
    from core.ui import draw_header
    from core.updater import check_version, perform_update
    from core.context import ctx
    from core.database import db  # Initializing DB
    try:
        from core.config import load_config
    except ImportError:
        def load_config(): return None
except ImportError as e:
    print(f"Core components missing: {e}")
    sys.exit(1)

# Modules (Safety Wrapped)
try:
    from modules.auditor import run_auditor
except:
    run_auditor = None
try: 
    from modules.looter import run_looter
except: pass
try:
    from modules.scanner import network_discovery
except:
    pass
try:
    from modules.sniff import SnifferEngine
except:
    pass
try:
    from modules.recon import dns_recon
except:
    pass
try:
    from modules.web_recon import web_ghost
except:
    pass
try:
    from modules.osint_pro import (username_tracker, phone_intel, geolocate,
                                   dork_generator, wayback_intel, shodan_intel, dns_intel)
except ImportError:
    pass
try:
    from modules.spoof import MITMEngine
except:
    pass
try:
    from modules.dns_spoofer import start_dns_spoof
except:
    pass
try:
    from modules.cloner import clone_site
except:
    pass
try:
    from modules.ghost_hub import run_ghost_hub
except:
    pass
try:
    from modules.wifi_ops import run_wifi_suite
except:
    pass
try:
    from modules.payloads import generate_shell
except:
    pass
try:
    from modules.crypt_keeper import encrypt_payload
except:
    pass
try:
    from modules.bruteforce import crack_hash
except:
    pass
try:
    from modules.persistence import PersistenceEngine
except:
    pass
try:
    from modules.ai_assist import run_ai_console
except:
    pass
try:
    from modules.reporter import generate_report
except:
    pass
try:
    from modules.ad_ops import run_ad_ops
except ImportError:
    pass
try:
    from modules.msf_engine import run_msf
except:
    pass

console = Console()
q_style = Style([
    ('qmark', 'fg:#ff0000 bold'), ('question', 'fg:#ffffff bold'),
    ('answer', 'fg:#ff0000 bold'), ('pointer', 'fg:#ff0000 bold'),
    ('highlighted', 'fg:#ff0000 bold'), ('selected', 'fg:#cc5454'),
    ('separator', 'fg:#666666'), ('instruction', 'fg:#666666 italic')
])

# --- 3. CORE FUNCTIONS ---


def auto_discovery():
    try:
        from scapy.all import conf, get_if_addr
        ctx.set("INTERFACE", str(conf.iface))
        ctx.set("LHOST", get_if_addr(str(conf.iface)))

        gw = "Unknown"
        try:
            # Ask the OS directly for the most accurate gateway
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

        # Fallback to Scapy if the OS commands fail
        if gw == "Unknown":
            gw = conf.route.route("0.0.0.0")[1]

        ctx.set("GATEWAY", str(gw))
        return True
    except:
        return False


def vanish_sequence():
    console.print("\n[bold red]INITIATING VANISH SEQUENCE...[/bold red]")
    for t in ["logs", "clones", "payloads", "__pycache__"]:
        if os.path.exists(t):
            shutil.rmtree(t, ignore_errors=True)
    console.print("[bold green][*] Evidence cleared. Ghost out.[/bold green]")
    sys.exit(0)


def configure_context():
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

        action = questionary.select("Options:", choices=[Choice("Set Variable", value="s"), Choice(
            "Rotate Identity", value="m"), Choice("Back", value="b")], style=q_style).ask()

        if not action or action == 'b':
            break
        elif action == 's':
            key = questionary.text(
                "Name (Leave blank to cancel):", style=q_style).ask()
            if key:
                ctx.set(key, questionary.text("Value:", style=q_style).ask())
        elif action == 'm':
            console.print("[dim]Rotating Identity...[/dim]")
            time.sleep(1)
            auto_discovery()

# --- 4. MENUS ---


def menu_recon():
    while True:
        os.system('cls' if os.name == 'nt' else 'clear')
        draw_header("Target Acquisition & Intelligence", context=ctx)
        choice = questionary.select("Select Objective:", choices=[
            questionary.Separator("--- INFRASTRUCTURE ---"),
            Choice("Network Mapper (Active Port Scan)", value="net"),
            Choice("Web Scanner & Fuzzer", value="web"),
            Choice("Passive Infrastructure Map (DNS & Certs)", value="dns"),
            Choice("Shodan Attack Surface Mapping", value="shodan"),
            questionary.Separator("--- DEEP WEB ---"),
            Choice("Archive Mining (Wayback Machine)", value="wayback"),
            Choice("Google Dork Generator", value="dork"),
            questionary.Separator("--- IDENTITY / GEO ---"),
            Choice("Profile Person (Social OSINT)", value="person"),
            Choice("Profile Location (Geo-IP)", value="geo"),
            questionary.Separator("--- NAV ---"),
            Choice("Back", value="back")
        ], style=q_style).ask()

        if not choice or choice == "back":
            break

        if choice == "net":
            sub = questionary.select(
                "Tool:", choices=["Active Discovery", "Passive Sniffer", "Back"], style=q_style).ask()
            if not sub or sub == "Back":
                continue
            if "Active" in sub:
                network_discovery()
            else:
                SnifferEngine().start()

        elif choice == "web":
            web_ghost()

        elif choice == "shodan":
            shodan_intel()

        elif choice == "wayback":
            wayback_intel()

        elif choice == "dork":
            dork_generator()

        elif choice == "dns":
            dns_intel()

        elif choice == "person":
            sub = questionary.select(
                "Mode:", choices=["Username Tracker", "Phone Intel", "Back"], style=q_style).ask()
            if not sub or sub == "Back":
                continue
            if "Username" in sub:
                username_tracker()
            else:
                phone_intel()

        elif choice == "geo":
            geolocate()


def menu_assault():
    while True:
        os.system('cls' if os.name == 'nt' else 'clear')
        draw_header("Direct Action", context=ctx)
        choice = questionary.select("Select Vector:", choices=[
            Choice("Active Directory Ops", value="ad"),
            Choice("Post-Exploitation Looter (PrivEsc)", value="loot"),
            Choice("MITM Attack", value="mitm"),
            Choice("DNS Hijack", value="dns"),
            Choice("WiFi Suite", value="wifi"),
            Choice("Web Cloner & AitM Proxy", value="clone"),
            Choice("Hash Cracker", value="crack"),
            Choice("Metasploit Framework", value="msf"),
            Choice("Back", value="back")
        ], style=q_style).ask()

        if not choice or choice == "back":
            break

        if choice == "ad":
            run_ad_ops()
        elif choice == "loot": 
            run_looter()
        elif choice == "mitm":
            MITMEngine().run()
        elif choice == "dns":
            start_dns_spoof()
        elif choice == "wifi":
            run_wifi_suite()
        elif choice == "clone":
            clone_site()
        elif choice == "crack":
            hash_val = questionary.text(
                "Hash (Leave blank to cancel):", style=q_style).ask()
            if hash_val:
                crack_hash(hash_val)
        elif choice == "msf":       # <-- ADD THIS BLOCK
            run_msf()


def menu_infra():
    while True:
        os.system('cls' if os.name == 'nt' else 'clear')
        draw_header("Infrastructure & C2", context=ctx)
        choice = questionary.select("Operation:", choices=[
            Choice("Generate Payload (Beacons/Shells)", value="forge"),
            Choice("Encrypt Payload", value="crypt"),
            Choice("Install Persistence", value="persist"),
            Choice("Launch Dual-Stack C2 Server", value="c2"),
            Choice("Back", value="back")
        ], style=q_style).ask()

        if not choice or choice == "back":
            break

        if choice == "forge":
            generate_shell()
        elif choice == "crypt":
            path = questionary.text(
                "Path (Leave blank to cancel):", style=q_style).ask()
            if path:
                encrypt_payload(path)
        elif choice == "persist":
            path = questionary.text(
                "Path (Leave blank to cancel):", style=q_style).ask()
            if path:
                PersistenceEngine(path).run()
        elif choice == "c2":
            run_ghost_hub()

# --- 5. MAIN ---


def main():
    if len(sys.argv) > 1 and sys.argv[1] == "--update":
        perform_update()
        sys.exit(0)
    auto_discovery()
    config = load_config()

    while True:
        try:
            os.system('cls' if os.name == 'nt' else 'clear')
            draw_header("Master Command Hub", context=ctx)
            check_version()

            cat = questionary.select("Mission Phase:", choices=[
                questionary.Separator("--- OPS ---"),
                Choice("1. Reconnaissance", value="recon"),
                Choice("2. Assault", value="assault"),
                Choice("3. Infrastructure", value="infra"),
                questionary.Separator("--- INTEL ---"),
                Choice("4. AI Cortex & Report", value="ai"),
                questionary.Separator("--- SYS ---"),
                Choice("Settings", value="sys"),
                Choice("Update", value="update"),
                Choice("VANISH", value="exit")
            ], style=q_style, pointer=">").ask()

            if not cat:  # Handles Esc key gracefully
                continue

            if cat == "recon":
                menu_recon()
            elif cat == "assault":
                menu_assault()
            elif cat == "infra":
                menu_infra()
            elif cat == "ai":
                sub = questionary.select("AI Ops:", choices=[
                                         "Launch Cortex", "Generate Report (DB)", "Back"], style=q_style).ask()
                if not sub or sub == "Back":
                    continue
                if "Cortex" in sub:
                    run_ai_console()
                else:
                    generate_report()
            elif cat == "sys":
                configure_context()
            elif cat == "update":
                perform_update()
            elif cat == "exit":
                if questionary.confirm("Vanish?", default=True, style=q_style).ask():
                    vanish_sequence()
        except KeyboardInterrupt:
            vanish_sequence()
        except Exception as e:
            console.print(f"[red]Error: {e}[/red]")
            input("Press Enter...")


if __name__ == "__main__":
    main()
