"""
main.py — Davoid Red Team Framework (Enterprise Edition)
Full Navigation Overhaul: All modules wired, structured submenus, fixed imports.
"""

import sys
import os
import warnings
import shutil
import time
import importlib.util
from typing import Callable, Optional

import questionary
from questionary import Choice, Separator
from rich.console import Console
from rich.table import Table

# ── Suppress noisy warnings ──────────────────────────────────────────────────
warnings.filterwarnings("ignore", message=".*OpenSSL 1.1.1+.*")
warnings.filterwarnings("ignore", category=UserWarning, module='urllib3')
warnings.filterwarnings("ignore", category=UserWarning, module='scapy')

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
if SCRIPT_DIR not in sys.path:
    sys.path.insert(0, SCRIPT_DIR)

# Enforce secure working directories
for _dir in ["logs", "payloads", "plugins", "reports"]:
    os.makedirs(os.path.join(SCRIPT_DIR, _dir), exist_ok=True)

# ─────────────────────────────────────────────────────────────────────────────
#  CORE IMPORTS
# ─────────────────────────────────────────────────────────────────────────────
try:
    from core.ui import draw_header, Q_STYLE
    from core.updater import check_version, perform_update
    from core.context import ctx
    from core.database import db
    from core.config import load_config
except ImportError as e:
    print(f"[!] Critical core component missing. Error: {e}")
    sys.exit(1)

console = Console()


# ─────────────────────────────────────────────────────────────────────────────
#  MODULE LOADER
# ─────────────────────────────────────────────────────────────────────────────
def load_module(module_path: str, attr: str) -> Optional[Callable]:
    """Safely import a module attribute; returns None if unavailable."""
    try:
        mod = importlib.import_module(module_path)
        return getattr(mod, attr)
    except Exception:
        return None


# ── Reconnaissance & OSINT ───────────────────────────────────────────────────
network_discovery = load_module("modules.scanner",     "network_discovery")
dns_recon = load_module("modules.recon",       "dns_recon")
shodan_intel = load_module("modules.recon",       "shodan_intel")
wayback_intel = load_module("modules.recon",       "wayback_intel")
dork_generator = load_module("modules.recon",       "dork_generator")
username_tracker = load_module("modules.recon",       "username_tracker")
phone_intel = load_module("modules.recon",       "phone_intel")
geolocate = load_module("modules.recon",       "geolocate")
passive_intel_menu = load_module("modules.recon",       "passive_intel_menu")
person_osint_menu = load_module("modules.recon",       "person_osint_menu")

# ── Exploitation ─────────────────────────────────────────────────────────────
run_msf = load_module("modules.msf_engine",  "run_msf")
run_ad_ops = load_module("modules.ad_ops",      "run_ad_ops")
crack_hash = load_module("modules.bruteforce",  "crack_hash")

# ── Post-Exploitation ────────────────────────────────────────────────────────
run_looter = load_module("modules.looter",      "run_looter")
run_cred_tester = load_module("modules.cred_tester", "run_cred_tester")
_PersistenceEngine = load_module("modules.persistence", "PersistenceEngine")

# ── Web Operations ───────────────────────────────────────────────────────────
web_ghost = load_module("modules.web_recon",   "web_ghost")

# ── Network Operations ───────────────────────────────────────────────────────
run_sniffer = load_module("modules.sniff",       "run_sniffer")
run_cloud_ops = load_module("modules.cloud_ops",   "run_cloud_ops")

# ── Command & Control ────────────────────────────────────────────────────────
run_ghost_hub = load_module("modules.ghost_hub",   "run_ghost_hub")
generate_shell = load_module("modules.payloads",    "generate_shell")

# ── Intelligence & AI ────────────────────────────────────────────────────────
run_ai_console = load_module("modules.ai_assist",   "run_ai_console")
run_god_mode = load_module("modules.god_mode",    "run_god_mode")

# ── Reporting & Purple Team ──────────────────────────────────────────────────
generate_report = load_module("modules.reporter",    "generate_report")
run_purple_team = load_module("modules.purple_team", "run_purple_team")

# ── Auditor ──────────────────────────────────────────────────────────────────
run_auditor = load_module("modules.auditor",     "run_auditor")


# ─────────────────────────────────────────────────────────────────────────────
#  PERSISTENCE ENTRY POINT (module only exposes a class, wrap it here)
# ─────────────────────────────────────────────────────────────────────────────
def run_persistence():
    if _PersistenceEngine is None:
        console.print("\n[bold red][!] Persistence module offline.[/bold red]")
        time.sleep(1.5)
        return
    draw_header("Persistence Engine")
    path = questionary.text(
        "Full path to payload/binary to persist:", style=Q_STYLE).ask()
    if path:
        _PersistenceEngine(path).run()
    questionary.press_any_key_to_continue(style=Q_STYLE).ask()


# ─────────────────────────────────────────────────────────────────────────────
#  SYSTEM HELPERS
# ─────────────────────────────────────────────────────────────────────────────
def detect_network_environment() -> bool:
    try:
        from scapy.all import conf, get_if_addr

        iface = str(conf.iface)
        ctx.set("INTERFACE", iface)

        local_ip = get_if_addr(iface)
        if local_ip and local_ip != "0.0.0.0":
            ctx.set("LHOST", local_ip)

        try:
            gw = conf.route.route("0.0.0.0")[2]
            ctx.set("GATEWAY", gw if gw and gw != "0.0.0.0" else "Unknown")
        except Exception:
            ctx.set("GATEWAY", "Unknown")

        return True
    except Exception:
        ctx.set("GATEWAY", "Unknown")
        return False


def execute_vanish_protocol() -> None:
    console.print(
        "\n[bold red]INITIATING FORENSIC VANISH SEQUENCE...[/bold red]")
    try:
        if hasattr(db, 'delete_all'):
            db.delete_all()
    except Exception:
        pass

    for target_dir in ["payloads", "__pycache__", "logs"]:
        path = os.path.join(SCRIPT_DIR, target_dir)
        if os.path.exists(path):
            shutil.rmtree(path, ignore_errors=True)

    console.print(
        "[bold green][*] Forensic evidence cleared. Ghost out.[/bold green]")
    sys.exit(0)


def safe_execute(func: Optional[Callable], *args, **kwargs) -> None:
    if func is None:
        console.print(
            "\n[bold red][!] Module offline or missing dependencies.[/bold red]")
        time.sleep(1.5)
        return
    try:
        func(*args, **kwargs)
    except KeyboardInterrupt:
        console.print("\n[yellow][*] Task interrupted by operator.[/yellow]")
    except Exception as e:
        console.print(
            f"\n[bold red][!] Runtime Exception in module:[/bold red]\n{e}")
        time.sleep(2)


def configure_global_context() -> None:
    while True:
        os.system('cls' if os.name == 'nt' else 'clear')
        draw_header("Configuration Manager", context=ctx)

        table = Table(title="Mission Context", border_style="bold magenta")
        table.add_column("Variable", style="cyan")
        table.add_column("Value", style="white")
        for k, v in ctx.vars.items():
            table.add_row(k, str(v))
        console.print(table)
        console.print()

        action = questionary.select(
            "Options:",
            choices=[
                Choice("Set Variable",                    value="set"),
                Choice("Rotate Identity (Refresh Network)", value="rotate"),
                Choice("Back",                            value="back"),
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
            detect_network_environment()


# ─────────────────────────────────────────────────────────────────────────────
#  MENU SYSTEMS
# ─────────────────────────────────────────────────────────────────────────────

# ── 1. Reconnaissance & OSINT ────────────────────────────────────────────────
def show_reconnaissance_menu():
    while True:
        os.system('cls' if os.name == 'nt' else 'clear')
        draw_header("Target Acquisition & Intelligence", context=ctx)
        choice = questionary.select(
            "Select Recon Module:",
            choices=[
                Separator("─── ACTIVE SCANNING ───────────────────────────"),
                Choice("Network Scanner (Nmap + NVD CVE)", value="nmap"),
                Choice("DNS & Subdomain Mapping",           value="dns"),
                Separator("─── OSINT ─────────────────────────────────────"),
                Choice("Attack Surface (Shodan/InternetDB)", value="shodan"),
                Choice("Wayback & Dork Intelligence",        value="passive"),
                Separator("─── PERSON OSINT ──────────────────────────────"),
                Choice("Username Tracker (14 platforms)",    value="username"),
                Choice("Phone Number Intel",                 value="phone"),
                Choice("Geo-IP Tracker",                     value="geo"),
                Separator("─── NAVIGATION ────────────────────────────────"),
                Choice("Return to Main Menu",                value="back"),
            ],
            style=Q_STYLE
        ).ask()

        if not choice or choice == "back":
            break

        actions = {
            "nmap": lambda: safe_execute(network_discovery),
            "dns": lambda: safe_execute(dns_recon),
            "shodan": lambda: safe_execute(shodan_intel),
            "passive": lambda: safe_execute(passive_intel_menu),
            "username": lambda: safe_execute(username_tracker),
            "phone": lambda: safe_execute(phone_intel),
            "geo": lambda: safe_execute(geolocate),
        }
        if choice in actions:
            actions[choice]()


# ── 2. Exploitation ──────────────────────────────────────────────────────────
def show_assault_menu():
    while True:
        os.system('cls' if os.name == 'nt' else 'clear')
        draw_header("Direct Action & Exploitation", context=ctx)
        choice = questionary.select(
            "Select Assault Vector:",
            choices=[
                Separator("─── EXPLOITATION ──────────────────────────────"),
                Choice("Metasploit Framework (MSF-RPC)", value="msf"),
                Choice("Active Directory Ops",            value="ad"),
                Separator("─── CREDENTIAL ATTACKS ────────────────────────"),
                Choice("Hash Cracker",                    value="crack"),
                Separator("─── NAVIGATION ────────────────────────────────"),
                Choice("Return to Main Menu",             value="back"),
            ],
            style=Q_STYLE
        ).ask()

        if not choice or choice == "back":
            break

        actions = {
            "msf": lambda: safe_execute(run_msf),
            "ad": lambda: safe_execute(run_ad_ops),
            "crack": lambda: safe_execute(crack_hash),
        }
        if choice in actions:
            actions[choice]()


# ── 3. Post-Exploitation ─────────────────────────────────────────────────────
def show_post_exploit_menu():
    while True:
        os.system('cls' if os.name == 'nt' else 'clear')
        draw_header("Post-Exploitation & Persistence", context=ctx)
        choice = questionary.select(
            "Select Post-Exploitation Module:",
            choices=[
                Separator("─── LOOT & PRIVILEGE ESCALATION ──────────────"),
                Choice("PrivEsc Looter (SSH / Dropper Scripts)", value="looter"),
                Separator("─── CREDENTIAL OPERATIONS ─────────────────────"),
                Choice("Credential Re-Use Tester",               value="creds"),
                Separator("─── PERSISTENCE ───────────────────────────────"),
                Choice("Persistence Engine (Systemd/Cron/Reg)",  value="persist"),
                Separator("─── NAVIGATION ────────────────────────────────"),
                Choice("Return to Main Menu",
                       value="back"),
            ],
            style=Q_STYLE
        ).ask()

        if not choice or choice == "back":
            break

        actions = {
            "looter": lambda: safe_execute(run_looter),
            "creds": lambda: safe_execute(run_cred_tester),
            "persist": lambda: safe_execute(run_persistence),
        }
        if choice in actions:
            actions[choice]()


# ── 4. Web Operations ────────────────────────────────────────────────────────
def show_web_menu():
    while True:
        os.system('cls' if os.name == 'nt' else 'clear')
        draw_header("Web Operations", context=ctx)
        choice = questionary.select(
            "Select Web Module:",
            choices=[
                Separator("─── WEB AUDITING ──────────────────────────────"),
                Choice("Web Ghost (Header Audit / Path Fuzz / Tor)", value="ghost"),
                Separator("─── NAVIGATION ────────────────────────────────"),
                Choice("Return to Main Menu",
                       value="back"),
            ],
            style=Q_STYLE
        ).ask()

        if not choice or choice == "back":
            break

        actions = {
            "ghost": lambda: safe_execute(web_ghost),
        }
        if choice in actions:
            actions[choice]()


# ── 5. Network Operations ────────────────────────────────────────────────────
def show_network_menu():
    while True:
        os.system('cls' if os.name == 'nt' else 'clear')
        draw_header("Network Operations", context=ctx)
        choice = questionary.select(
            "Select Network Module:",
            choices=[
                Separator("─── INTERCEPTION ──────────────────────────────"),
                Choice("Live Packet Sniffer (WLAN Intel Stream)", value="sniff"),
                Separator("─── CLOUD & CONTAINER ─────────────────────────"),
                Choice("Cloud & Container Ops",
                       value="cloud"),
                Separator("─── NAVIGATION ────────────────────────────────"),
                Choice("Return to Main Menu",
                       value="back"),
            ],
            style=Q_STYLE
        ).ask()

        if not choice or choice == "back":
            break

        actions = {
            "sniff": lambda: safe_execute(run_sniffer),
            "cloud": lambda: safe_execute(run_cloud_ops),
        }
        if choice in actions:
            actions[choice]()


# ── 6. Command & Control ─────────────────────────────────────────────────────
def show_c2_menu():
    while True:
        os.system('cls' if os.name == 'nt' else 'clear')
        draw_header("Command & Control (C2)", context=ctx)
        choice = questionary.select(
            "Select C2 Module:",
            choices=[
                Separator("─── C2 INFRASTRUCTURE ─────────────────────────"),
                Choice("GhostHub C2 (Encrypted Session Manager)", value="hub"),
                Separator("─── PAYLOAD GENERATION ────────────────────────"),
                Choice("Payload Forge (Polymorphic / AI-Mutated)",
                       value="payloads"),
                Separator("─── NAVIGATION ────────────────────────────────"),
                Choice("Return to Main Menu",
                       value="back"),
            ],
            style=Q_STYLE
        ).ask()

        if not choice or choice == "back":
            break

        actions = {
            "hub": lambda: safe_execute(run_ghost_hub),
            "payloads": lambda: safe_execute(generate_shell),
        }
        if choice in actions:
            actions[choice]()


# ── 9. Intelligence & Reporting ──────────────────────────────────────────────
def show_intel_menu():
    while True:
        os.system('cls' if os.name == 'nt' else 'clear')
        draw_header("Intelligence & Reporting", context=ctx)
        choice = questionary.select(
            "Select Intel Module:",
            choices=[
                Separator("─── REPORTING ─────────────────────────────────"),
                Choice("Generate Mission Report (HTML)",
                       value="report"),
                Separator("─── PURPLE TEAM ────────────────────────────────"),
                Choice("Purple Team / MITRE ATT&CK Mapper",
                       value="purple"),
                Separator("─── NAVIGATION ────────────────────────────────"),
                Choice("Return to Main Menu",
                       value="back"),
            ],
            style=Q_STYLE
        ).ask()

        if not choice or choice == "back":
            break

        actions = {
            "report": lambda: safe_execute(generate_report),
            "purple": lambda: safe_execute(run_purple_team),
        }
        if choice in actions:
            actions[choice]()


# ─────────────────────────────────────────────────────────────────────────────
#  MAIN ENTRY POINT
# ─────────────────────────────────────────────────────────────────────────────
def main():
    if len(sys.argv) > 1 and sys.argv[1] == "--update":
        perform_update()
        sys.exit(0)

    load_config()
    detect_network_environment()

    actions = {
        "recon":      show_reconnaissance_menu,
        "assault":    show_assault_menu,
        "postexploit": show_post_exploit_menu,
        "web":        show_web_menu,
        "network":    show_network_menu,
        "c2":         show_c2_menu,
        "ai": lambda: safe_execute(run_ai_console),
        "godmode": lambda: safe_execute(run_god_mode),
        "intel":      show_intel_menu,
        "sys":        configure_global_context,
        "audit": lambda: safe_execute(run_auditor),
        "update":     perform_update,
    }

    while True:
        try:
            os.system('cls' if os.name == 'nt' else 'clear')
            draw_header("Enterprise Master Hub", context=ctx)

            phase = questionary.select(
                "Select Operation Phase:",
                choices=[
                    Separator(
                        "─── OFFENSIVE OPERATIONS ──────────────────────"),
                    Choice("1.  Reconnaissance & OSINT",
                           value="recon"),
                    Choice("2.  Exploitation (MSF + AD + Hash)",
                           value="assault"),
                    Choice("3.  Post-Exploitation (Loot / Persist)",
                           value="postexploit"),
                    Choice("4.  Web Operations (WebGhost)",
                           value="web"),
                    Choice("5.  Network Operations (Sniffer / Cloud)",
                           value="network"),
                    Choice("6.  Command & Control (C2 / Payloads)",
                           value="c2"),
                    Separator(
                        "─── INTELLIGENCE ──────────────────────────────"),
                    Choice("7.  AI Cortex (Autonomous Agent)",
                           value="ai"),
                    Choice("8.  GOD MODE — Full Autonomous Campaign",
                           value="godmode"),
                    Choice(
                        "9.  Intel & Reporting (Report / Purple Team)", value="intel"),
                    Separator(
                        "─── SYSTEM ────────────────────────────────────"),
                    Choice("    Context Configuration",
                           value="sys"),
                    Choice("    Auditor & Dependency Check",
                           value="audit"),
                    Choice("    Framework Update",
                           value="update"),
                    Choice("    Execute Vanish Protocol",
                           value="exit"),
                ],
                style=Q_STYLE,
                pointer="▶"
            ).ask()

            if not phase:
                continue
            if phase == "exit":
                if questionary.confirm(
                    "Execute Vanish Protocol? (clears logs & payloads)",
                    default=True, style=Q_STYLE
                ).ask():
                    execute_vanish_protocol()
            elif phase in actions:
                actions[phase]()

        except KeyboardInterrupt:
            execute_vanish_protocol()
        except Exception as e:
            console.print(
                f"\n[bold red]Critical system failure:[/bold red]\n{e}")
            input("Press Enter to continue...")


if __name__ == "__main__":
    main()
