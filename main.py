"""
main.py — Davoid Red Team Framework
Master entry point. All module imports are individually guarded so a single
missing pip dependency never crashes the entire hub.
"""

import sys
import os
import warnings
import subprocess
import shutil
import time
import questionary
from questionary import Choice, Separator
from rich.console import Console
from rich.table import Table

# ─────────────────────────────────────────────────────────────────────────────
#  PATH & WARNING SUPPRESSION
# ─────────────────────────────────────────────────────────────────────────────
warnings.filterwarnings("ignore", message=".*OpenSSL 1.1.1+.*")
warnings.filterwarnings("ignore", category=UserWarning, module='urllib3')
warnings.filterwarnings("ignore", category=UserWarning, module='scapy')

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
if SCRIPT_DIR not in sys.path:
    sys.path.append(SCRIPT_DIR)
BASE_DIR = "/opt/davoid"
if os.path.exists(BASE_DIR) and BASE_DIR not in sys.path:
    sys.path.append(BASE_DIR)

# ─────────────────────────────────────────────────────────────────────────────
#  CORE IMPORTS  (must always succeed)
# ─────────────────────────────────────────────────────────────────────────────
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
    print(f"[!] Critical core component missing: {e}")
    sys.exit(1)

# ─────────────────────────────────────────────────────────────────────────────
#  SAFE MODULE LOADER
#  Returns None (never raises) so a missing dep silently disables that module.
# ─────────────────────────────────────────────────────────────────────────────


def _try_import(module_path, attr):
    try:
        mod = __import__(module_path, fromlist=[attr])
        return getattr(mod, attr)
    except Exception:
        return None


network_discovery = _try_import("modules.scanner",      "network_discovery")
SnifferEngine = _try_import("modules.sniff",        "SnifferEngine")
dns_recon = _try_import("modules.recon",        "dns_recon")
web_ghost = _try_import("modules.web_recon",    "web_ghost")
MITMEngine = _try_import("modules.spoof",        "MITMEngine")
start_dns_spoof = _try_import("modules.dns_spoofer",  "start_dns_spoof")
run_cloner = _try_import("modules.cloner",       "run_cloner")
run_ghost_hub = _try_import("modules.ghost_hub",    "run_ghost_hub")
run_wifi_suite = _try_import("modules.wifi_ops",     "run_wifi_suite")
generate_shell = _try_import("modules.payloads",     "generate_shell")
encrypt_payload = _try_import("modules.crypt_keeper", "encrypt_payload")
crack_hash = _try_import("modules.bruteforce",   "crack_hash")
PersistenceEngine = _try_import("modules.persistence",  "PersistenceEngine")
run_ai_console = _try_import("modules.ai_assist",    "run_ai_console")
generate_report = _try_import("modules.reporter",     "generate_report")
run_ad_ops = _try_import("modules.ad_ops",       "run_ad_ops")
run_msf = _try_import("modules.msf_engine",   "run_msf")
run_looter = _try_import("modules.looter",       "run_looter")
run_auditor = _try_import("modules.auditor",      "run_auditor")

# OSINT module (bundle of functions)
username_tracker = phone_intel = geolocate = None
dork_generator = wayback_intel = shodan_intel = dns_intel = None
try:
    from modules.osint_pro import (
        username_tracker, phone_intel, geolocate,
        dork_generator, wayback_intel, shodan_intel, dns_intel,
    )
except Exception:
    pass

# ─────────────────────────────────────────────────────────────────────────────
#  UI GLOBALS
# ─────────────────────────────────────────────────────────────────────────────
console = Console()

Q_STYLE = questionary.Style([
    ('qmark',       'fg:#ff0000 bold'),
    ('question',    'fg:#ffffff bold'),
    ('answer',      'fg:#ff0000 bold'),
    ('pointer',     'fg:#ff0000 bold'),
    ('highlighted', 'fg:#ff0000 bold'),
    ('selected',    'fg:#cc5454'),
    ('separator',   'fg:#666666'),
    ('instruction', 'fg:#666666 italic'),
])

# ─────────────────────────────────────────────────────────────────────────────
#  SYSTEM HELPERS
# ─────────────────────────────────────────────────────────────────────────────


def _is_root():
    """Cross-platform root/admin check."""
    if hasattr(os, 'getuid'):
        return os.getuid() == 0
    try:
        import ctypes
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False


def detect_network_environment():
    """
    Auto-fingerprints IP, gateway, and interface.
    Fully wrapped — never crashes startup if scapy is missing or broken.
    """
    try:
        from scapy.all import conf, get_if_addr
        iface = str(conf.iface)
        ctx.set("INTERFACE", iface)

        try:
            local_ip = get_if_addr(iface)
            if local_ip and local_ip != "0.0.0.0":
                ctx.set("LHOST", local_ip)
        except Exception:
            pass

        gw = "Unknown"
        try:
            if sys.platform == "darwin":
                out = subprocess.check_output(
                    ["route", "-n", "get", "default"],
                    stderr=subprocess.DEVNULL, timeout=5
                ).decode()
                for line in out.splitlines():
                    if "gateway:" in line:
                        gw = line.split(":")[1].strip()
                        break
            else:
                out = subprocess.check_output(
                    ["ip", "route"],
                    stderr=subprocess.DEVNULL, timeout=5
                ).decode()
                for line in out.splitlines():
                    if line.startswith("default via"):
                        gw = line.split()[2].strip()
                        break
        except Exception:
            pass

        if gw == "Unknown":
            try:
                gw = str(conf.route.route("0.0.0.0")[1])
            except Exception:
                pass

        ctx.set("GATEWAY", gw)
        return True
    except Exception:
        return False


def execute_vanish_protocol():
    """
    Wipes generated artifacts.
    Deliberately keeps logs/ by default — it contains the mission DB and C2 AES key.
    Asks before destroying logs.
    """
    console.print("\n[bold red]INITIATING VANISH SEQUENCE...[/bold red]")

    # Safe wipe targets
    for target_dir in ["clones", "payloads", "__pycache__"]:
        if os.path.exists(target_dir):
            shutil.rmtree(target_dir, ignore_errors=True)
            console.print(f"[dim]  Wiped: {target_dir}/[/dim]")

    # Wipe nested __pycache__ directories
    for root, dirs, _ in os.walk("."):
        for d in dirs:
            if d == "__pycache__":
                shutil.rmtree(os.path.join(root, d), ignore_errors=True)

    # logs/ contains mission DB + C2 key — confirm before wiping
    if os.path.exists("logs"):
        wipe_logs = questionary.confirm(
            "Also wipe logs/ ? (Mission DB + C2 AES key will be lost)",
            default=False, style=Q_STYLE
        ).ask()
        if wipe_logs:
            shutil.rmtree("logs", ignore_errors=True)
            console.print("[dim]  Wiped: logs/[/dim]")

    console.print("[bold green][*] Evidence cleared. Ghost out.[/bold green]")
    sys.exit(0)


def configure_global_context():
    """View and override global mission variables."""
    while True:
        os.system('cls' if os.name == 'nt' else 'clear')
        draw_header("Global Configuration", context=ctx)

        table = Table(title="Mission Context", border_style="bold magenta")
        table.add_column("Variable", style="cyan")
        table.add_column("Value",    style="white")
        for k, v in ctx.vars.items():
            table.add_row(k, str(v))
        console.print(table)
        console.print()

        action = questionary.select(
            "Options:",
            choices=[
                Choice("Set Variable",                         value="set"),
                Choice("Rotate Identity (Refresh Network)",    value="rotate"),
                Choice("Back",                                 value="back"),
            ],
            style=Q_STYLE
        ).ask()

        if not action or action == "back":
            break
        elif action == "set":
            key = questionary.text(
                "Variable name (blank = cancel):", style=Q_STYLE).ask()
            if key:
                val = questionary.text(
                    f"Value for {key}:", style=Q_STYLE).ask()
                ctx.set(key, val)
        elif action == "rotate":
            console.print("[dim]Refreshing network identity...[/dim]")
            time.sleep(1)
            detect_network_environment()

# ─────────────────────────────────────────────────────────────────────────────
#  SAFE EXECUTE
#  Wraps every module call. If the module failed to import (func is None),
#  shows a clean error instead of crashing. Also catches runtime exceptions.
# ─────────────────────────────────────────────────────────────────────────────


def safe_execute(func, *args, **kwargs):
    """
    Call func(*args, **kwargs) safely.
    - func=None  → "module offline" message
    - runtime exception → print error, keep hub alive
    """
    if func is None:
        console.print(
            "\n[bold red][!] Module offline or missing dependencies.[/bold red]"
            "\n[dim]Check requirements.txt and re-run: pip install -r requirements.txt[/dim]")
        time.sleep(1.5)
        return
    try:
        func(*args, **kwargs)
    except KeyboardInterrupt:
        pass
    except Exception as e:
        console.print(f"\n[bold red][!] Module runtime error:[/bold red] {e}")
        time.sleep(1.5)

# ─────────────────────────────────────────────────────────────────────────────
#  MODULE ROUTERS
# ─────────────────────────────────────────────────────────────────────────────


def run_net_scan():
    sub = questionary.select(
        "Network Tool:",
        choices=["Active Discovery (Nmap)", "Passive Sniffer", "Back"],
        style=Q_STYLE
    ).ask()
    if not sub or sub == "Back":
        return
    if "Active" in sub:
        safe_execute(network_discovery)
    elif "Sniffer" in sub:
        # Check None before constructing lambda — prevents silent None return
        if SnifferEngine is None:
            safe_execute(None)
        else:
            safe_execute(lambda: SnifferEngine().start())


def run_mitm():
    if MITMEngine is None:
        safe_execute(None)
    else:
        safe_execute(lambda: MITMEngine().run())


def run_person_osint():
    sub = questionary.select(
        "Mode:",
        choices=["Username Tracker", "Phone Intel", "Back"],
        style=Q_STYLE
    ).ask()
    if not sub or sub == "Back":
        return
    if "Username" in sub:
        safe_execute(username_tracker)
    else:
        safe_execute(phone_intel)


def run_ai_ops():
    sub = questionary.select(
        "AI Ops:",
        choices=["Launch Cortex", "Generate Report (DB)", "Back"],
        style=Q_STYLE
    ).ask()
    if not sub or sub == "Back":
        return
    if "Cortex" in sub:
        safe_execute(run_ai_console)
    else:
        safe_execute(generate_report)


def run_encrypt():
    if encrypt_payload is None:
        safe_execute(None)
        return
    path = questionary.text(
        "Payload path to encrypt (blank = cancel):", style=Q_STYLE).ask()
    if path:
        safe_execute(encrypt_payload, path)


def run_persist():
    if PersistenceEngine is None:
        safe_execute(None)
        return
    path = questionary.text(
        "Payload path (blank = cancel):", style=Q_STYLE).ask()
    if path:
        safe_execute(lambda: PersistenceEngine(path).run())

# ─────────────────────────────────────────────────────────────────────────────
#  MENU PANELS
# ─────────────────────────────────────────────────────────────────────────────


def show_reconnaissance_menu():
    actions = {
        "net":     run_net_scan,
        "web": lambda: safe_execute(web_ghost),
        "shodan": lambda: safe_execute(shodan_intel),
        "dns": lambda: safe_execute(dns_intel),
        "wayback": lambda: safe_execute(wayback_intel),
        "dork": lambda: safe_execute(dork_generator),
        "person":  run_person_osint,
        "geo": lambda: safe_execute(geolocate),
        "recon": lambda: safe_execute(dns_recon),
    }

    while True:
        os.system('cls' if os.name == 'nt' else 'clear')
        draw_header("Target Acquisition & Intelligence", context=ctx)

        choice = questionary.select(
            "Select Recon Module:",
            choices=[
                Separator("─── ACTIVE SCANNING ───────────────────"),
                Choice("Network Scanner (Nmap)",           value="net"),
                Choice("Web Vulnerability Scanner",        value="web"),
                Choice("DNS Infrastructure Recon",         value="recon"),
                Separator("─── PASSIVE OSINT ──────────────────────"),
                Choice("Shodan API (Attack Surface)",      value="shodan"),
                Choice("DNS & Subdomain Mapping",          value="dns"),
                Separator("─── DEEP ARCHIVE ───────────────────────"),
                Choice("Wayback Machine (Archive Mining)", value="wayback"),
                Choice("Google Dork Generator",            value="dork"),
                Separator("─── IDENTITY / GEO ─────────────────────"),
                Choice("Social OSINT (Identity Tracker)",  value="person"),
                Choice("Geo-IP Tracker",                   value="geo"),
                Separator("─── NAVIGATION ─────────────────────────"),
                Choice("Return to Main Menu",              value="back"),
            ],
            style=Q_STYLE
        ).ask()

        if not choice or choice == "back":
            break
        if choice in actions:
            actions[choice]()


def show_assault_menu():
    actions = {
        "msf": lambda: safe_execute(run_msf),
        "ad": lambda: safe_execute(run_ad_ops),
        "loot": lambda: safe_execute(run_looter),
        "mitm":  run_mitm,
        "dns": lambda: safe_execute(start_dns_spoof),
        "wifi": lambda: safe_execute(run_wifi_suite),
        "clone": lambda: safe_execute(run_cloner),
        "crack": lambda: safe_execute(crack_hash),
    }

    while True:
        os.system('cls' if os.name == 'nt' else 'clear')
        draw_header("Direct Action", context=ctx)

        choice = questionary.select(
            "Select Assault Vector:",
            choices=[
                Separator("─── EXPLOITATION ───────────────────────"),
                Choice("Metasploit Framework (MSF-RPC)",   value="msf"),
                Choice("Active Directory Ops",             value="ad"),
                Choice("PrivEsc Looter (Post-Exploit)",    value="loot"),
                Separator("─── NETWORK ATTACKS ────────────────────"),
                Choice("MITM Interceptor (ARP Poison)",    value="mitm"),
                Choice("DNS Spoofer",                      value="dns"),
                Choice("WiFi Attack Suite",                value="wifi"),
                Separator("─── SOCIAL & CREDENTIAL ─────────────────"),
                Choice("AitM Web Cloner (Phishing Proxy)", value="clone"),
                Choice("Hash Cracker",                     value="crack"),
                Separator("─── NAVIGATION ─────────────────────────"),
                Choice("Return to Main Menu",              value="back"),
            ],
            style=Q_STYLE
        ).ask()

        if not choice or choice == "back":
            break
        if choice in actions:
            actions[choice]()


def show_infrastructure_menu():
    actions = {
        "forge": lambda: safe_execute(generate_shell),
        "crypt":   run_encrypt,
        "persist": run_persist,
        "c2": lambda: safe_execute(run_ghost_hub),
        "audit": lambda: safe_execute(run_auditor),
    }

    while True:
        os.system('cls' if os.name == 'nt' else 'clear')
        draw_header("Infrastructure & C2", context=ctx)

        choice = questionary.select(
            "Select C2 Operation:",
            choices=[
                Separator("─── WEAPONIZATION ──────────────────────"),
                Choice("Payload Generator (Forge)",        value="forge"),
                Choice("Payload Encryptor (CryptKeeper)",  value="crypt"),
                Separator("─── PERSISTENCE & C2 ───────────────────"),
                Choice("Persistence Installer",            value="persist"),
                Choice("GhostHub C2 Server",               value="c2"),
                Separator("─── AUDIT ───────────────────────────────"),
                Choice("System Posture Auditor",           value="audit"),
                Separator("─── NAVIGATION ─────────────────────────"),
                Choice("Return to Main Menu",              value="back"),
            ],
            style=Q_STYLE
        ).ask()

        if not choice or choice == "back":
            break
        if choice in actions:
            actions[choice]()

# ─────────────────────────────────────────────────────────────────────────────
#  MAIN LOOP
# ─────────────────────────────────────────────────────────────────────────────


def main():
    if len(sys.argv) > 1 and sys.argv[1] == "--update":
        perform_update()
        sys.exit(0)

    # Boot tasks
    detect_network_environment()
    load_config()

    # Ensure essential directories exist
    os.makedirs("logs",    exist_ok=True)
    os.makedirs("payloads", exist_ok=True)

    actions = {
        "recon":   show_reconnaissance_menu,
        "assault": show_assault_menu,
        "infra":   show_infrastructure_menu,
        "ai":      run_ai_ops,
        "sys":     configure_global_context,
        "update":  perform_update,
    }

    while True:
        try:
            os.system('cls' if os.name == 'nt' else 'clear')
            draw_header("Master Command Hub", context=ctx)
            check_version()

            phase = questionary.select(
                "Select Mission Phase:",
                choices=[
                    Separator("─── OFFENSIVE OPERATIONS ───────────────"),
                    Choice("1.  Recon & OSINT",           value="recon"),
                    Choice("2.  Assault & Exploitation",  value="assault"),
                    Choice("3.  C2 & Payloads",           value="infra"),
                    Separator("─── INTELLIGENCE ───────────────────────"),
                    Choice("4.  AI Cortex & Reporting",   value="ai"),
                    Separator("─── SYSTEM ─────────────────────────────"),
                    Choice("    Configuration & Context", value="sys"),
                    Choice("    Framework Update",        value="update"),
                    Choice("    Execute Vanish Protocol", value="exit"),
                ],
                style=Q_STYLE,
                pointer="▶"
            ).ask()

            if not phase:
                continue

            if phase == "exit":
                if questionary.confirm(
                    "Execute Vanish Protocol?", default=True, style=Q_STYLE
                ).ask():
                    execute_vanish_protocol()
            elif phase in actions:
                actions[phase]()

        except KeyboardInterrupt:
            execute_vanish_protocol()
        except Exception as e:
            console.print(
                f"\n[bold red]Critical error in main loop:[/bold red] {e}")
            input("Press Enter to continue...")


if __name__ == "__main__":
    main()
