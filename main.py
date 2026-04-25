"""
main.py — Davoid Red Team Framework (Enterprise Edition)
Complete rebuild: all existing modules wired + new modules integrated.
New: osint, sniff, bruteforce, mitm, phishing, auditor, scope_manager, plugin_loader
Fixed: god_mode override_prompt bug, payloads AI mutation, ad_ops expanded
"""

import sys
import os
import warnings
import shutil
import time
import importlib
import importlib.util
from typing import Callable, Optional

import questionary
from questionary import Choice, Separator
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

warnings.filterwarnings("ignore", message=".*OpenSSL 1.1.1+.*")
warnings.filterwarnings("ignore", category=UserWarning, module='urllib3')
warnings.filterwarnings("ignore", category=UserWarning, module='scapy')

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
if SCRIPT_DIR not in sys.path:
    sys.path.insert(0, SCRIPT_DIR)

for _dir in ["logs", "payloads", "plugins", "reports", "wordlists"]:
    os.makedirs(os.path.join(SCRIPT_DIR, _dir), exist_ok=True)

# ─────────────────────────────────────────────────────────────────────────────
#  CORE IMPORTS
# ─────────────────────────────────────────────────────────────────────────────
try:
    from core.ui import draw_header, Q_STYLE
    from core.updater import perform_update
    from core.context import ctx
    from core.database import db
    from core.config import load_config
except ImportError as e:
    print(f"[!] Critical core component missing: {e}")
    sys.exit(1)

console = Console()


# ─────────────────────────────────────────────────────────────────────────────
#  MODULE LOADER
# ─────────────────────────────────────────────────────────────────────────────
def load_module(module_path: str, attr: str) -> Optional[Callable]:
    try:
        mod = importlib.import_module(module_path)
        return getattr(mod, attr)
    except Exception:
        return None


# ── Reconnaissance & OSINT ───────────────────────────────────────────────────
network_discovery = load_module("modules.scanner",       "network_discovery")
run_osint = load_module("modules.osint",         "run_osint")

# ── Exploitation ─────────────────────────────────────────────────────────────
run_msf = load_module("modules.msf_engine",    "run_msf")
run_ad_ops = load_module("modules.ad_ops",        "run_ad_ops")
crack_hash = load_module("modules.bruteforce",    "crack_hash")

# ── Post-Exploitation ────────────────────────────────────────────────────────
run_looter = load_module("modules.looter",        "run_looter")
run_cred_tester = load_module("modules.cred_tester",   "run_cred_tester")
_PersistenceEngine = load_module("modules.persistence",   "PersistenceEngine")

# ── Web Operations ───────────────────────────────────────────────────────────
web_ghost = load_module("modules.web_recon",     "web_ghost")
run_phishing = load_module("modules.phishing",      "run_phishing")

# ── Network Operations ───────────────────────────────────────────────────────
run_sniffer = load_module("modules.sniff",         "run_sniffer")
run_mitm = load_module("modules.mitm",          "run_mitm")
run_cloud_ops = load_module("modules.cloud_ops",     "run_cloud_ops")

# ── Command & Control ────────────────────────────────────────────────────────
run_ghost_hub = load_module("modules.ghost_hub",     "run_ghost_hub")
generate_shell = load_module("modules.payloads",      "generate_shell")
run_crypt_keeper = load_module("modules.crypt_keeper",  "run_crypt_keeper")

# ── Intelligence & AI ────────────────────────────────────────────────────────
run_ai_console = load_module("modules.ai_assist",     "run_ai_console")
run_god_mode = load_module("modules.god_mode",      "run_god_mode")

# ── Reporting & Purple Team ──────────────────────────────────────────────────
generate_report = load_module("modules.reporter",      "generate_report")
run_purple_team = load_module("modules.purple_team",   "run_purple_team")

# ── System ───────────────────────────────────────────────────────────────────
run_auditor = load_module("modules.auditor",       "run_auditor")
run_scope_manager = load_module("modules.scope_manager", "run_scope_manager")


# ─────────────────────────────────────────────────────────────────────────────
#  PERSISTENCE ENTRY POINT
# ─────────────────────────────────────────────────────────────────────────────
def run_persistence():
    if _PersistenceEngine is None:
        console.print("\n[bold red][!] Persistence module offline.[/bold red]")
        time.sleep(1.5)
        return
    draw_header("Persistence Engine")
    console.print(
        "[dim]Installs payload as a persistent service that survives reboots.\n"
        "Linux: systemd (root) → crontab fallback\n"
        "macOS: LaunchAgent plist\n"
        "Windows: Scheduled Task (admin) → Registry Run key[/dim]\n"
    )
    path = questionary.text(
        "Full path to payload/binary to persist:", style=Q_STYLE).ask()
    if not path:
        return
    if not os.path.exists(path):
        if not questionary.confirm(f"'{path}' not found locally. Continue anyway?",
                                   default=False, style=Q_STYLE).ask():
            return
    _PersistenceEngine(path).run()


# ─────────────────────────────────────────────────────────────────────────────
#  PLUGIN LOADER
# ─────────────────────────────────────────────────────────────────────────────
def load_plugins() -> list:
    """Discover all .py files in /plugins that expose a run() function."""
    plugins = []
    plugins_dir = os.path.join(SCRIPT_DIR, "plugins")
    for fname in sorted(os.listdir(plugins_dir)):
        if not fname.endswith(".py") or fname.startswith("_"):
            continue
        name = fname[:-3]
        fpath = os.path.join(plugins_dir, fname)
        try:
            spec = importlib.util.spec_from_file_location(
                f"plugins.{name}", fpath)
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
            if hasattr(mod, "run"):
                label = getattr(mod, "PLUGIN_NAME", name)
                plugins.append({"name": name, "label": label, "run": mod.run})
        except Exception as e:
            console.print(
                f"[dim yellow][!] Plugin '{name}' failed to load: {e}[/dim yellow]")
    return plugins


def show_plugin_menu():
    plugins = load_plugins()
    if not plugins:
        console.print(
            "\n[yellow][!] No plugins found in /plugins directory.[/yellow]")
        console.print(
            "[dim]Drop a .py file with a run() function into the plugins/ folder.[/dim]")
        questionary.press_any_key_to_continue(style=Q_STYLE).ask()
        return

    while True:
        os.system('cls' if os.name == 'nt' else 'clear')
        draw_header("Plugin Manager", context=ctx)
        choices = [Choice(p["label"], value=p["name"]) for p in plugins]
        choices.append(
            Separator("─────────────────────────────────────────────"))
        choices.append(Choice("Return to Main Menu", value="back"))

        sel = questionary.select("Installed Plugins:",
                                 choices=choices, style=Q_STYLE).ask()
        if not sel or sel == "back":
            break
        for p in plugins:
            if p["name"] == sel:
                safe_execute(p["run"])
                break


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
        console.print(f"\n[bold red][!] Runtime Exception:[/bold red]\n{e}")
        time.sleep(2)


def configure_global_context() -> None:
    while True:
        os.system('cls' if os.name == 'nt' else 'clear')
        draw_header("Configuration Manager", context=ctx)
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
                Choice("Set Variable",                      value="set"),
                Choice("Rotate Identity (Refresh Network)", value="rotate"),
                Choice("Back",                              value="back"),
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

def show_reconnaissance_menu():
    while True:
        os.system('cls' if os.name == 'nt' else 'clear')
        draw_header("Target Acquisition & Intelligence", context=ctx)
        choice = questionary.select(
            "Select Recon Module:",
            choices=[
                Separator("─── ACTIVE SCANNING ───────────────────────────"),
                Choice("Network Scanner  (Nmap + NVD CVE + ExploitDB)",
                       value="nmap"),
                Separator("─── OSINT ENGINE ──────────────────────────────"),
                Choice("OSINT Suite  (DNS / Shodan / Wayback / Person)",
                       value="osint"),
                Separator("─── NAVIGATION ────────────────────────────────"),
                Choice("Return to Main Menu",
                       value="back"),
            ],
            style=Q_STYLE
        ).ask()
        if not choice or choice == "back":
            break
        if choice == "nmap":
            safe_execute(network_discovery)
        elif choice == "osint":
            safe_execute(run_osint)


def show_assault_menu():
    while True:
        os.system('cls' if os.name == 'nt' else 'clear')
        draw_header("Direct Action & Exploitation", context=ctx)
        choice = questionary.select(
            "Select Assault Vector:",
            choices=[
                Separator("─── EXPLOITATION ──────────────────────────────"),
                Choice("Metasploit Framework  (MSF-RPC + Auto-Exploit)", value="msf"),
                Choice("Active Directory Ops  (LDAP / Kerberos / DCSync)", value="ad"),
                Separator("─── CREDENTIAL ATTACKS ────────────────────────"),
                Choice("Hash Cracker  (MD5 / SHA / NTLM + Wordlist)",
                       value="crack"),
                Separator("─── NAVIGATION ────────────────────────────────"),
                Choice("Return to Main Menu",
                       value="back"),
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


def show_post_exploit_menu():
    while True:
        os.system('cls' if os.name == 'nt' else 'clear')
        draw_header("Post-Exploitation & Persistence", context=ctx)
        choice = questionary.select(
            "Select Post-Exploitation Module:",
            choices=[
                Separator("─── LOOT & PRIVILEGE ESCALATION ──────────────"),
                Choice("PrivEsc Looter  (SSH Auto-Loot / Dropper)",
                       value="looter"),
                Separator("─── CREDENTIAL OPERATIONS ─────────────────────"),
                Choice("Credential Re-Use Tester  (SSH/FTP/HTTP)",
                       value="creds"),
                Separator("─── PERSISTENCE ───────────────────────────────"),
                Choice("Persistence Engine  (Systemd / Cron / Registry)",
                       value="persist"),
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


def show_web_menu():
    while True:
        os.system('cls' if os.name == 'nt' else 'clear')
        draw_header("Web Operations", context=ctx)
        choice = questionary.select(
            "Select Web Module:",
            choices=[
                Separator("─── WEB AUDITING ──────────────────────────────"),
                Choice("Web Ghost  (Header Audit / Path Fuzz / Tor)",
                       value="ghost"),
                Separator("─── SOCIAL ENGINEERING ────────────────────────"),
                Choice("Phishing Kit  (Clone / Serve / Harvest Creds)",
                       value="phish"),
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
            "phish": lambda: safe_execute(run_phishing),
        }
        if choice in actions:
            actions[choice]()


def show_network_menu():
    while True:
        os.system('cls' if os.name == 'nt' else 'clear')
        draw_header("Network & Cloud Operations", context=ctx)
        choice = questionary.select(
            "Select Network Module:",
            choices=[
                Separator("─── INTERCEPTION ──────────────────────────────"),
                Choice(
                    "Live Packet Sniffer  (Scapy / Cred Detect / PCAP)", value="sniff"),
                Choice(
                    "MITM Engine  (ARP Spoof / DNS Hijack / SSL Strip)",  value="mitm"),
                Separator("─── CLOUD & CONTAINER ─────────────────────────"),
                Choice("Cloud & Container Ops  (S3 / IMDS / Docker)",
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
            "mitm": lambda: safe_execute(run_mitm),
            "cloud": lambda: safe_execute(run_cloud_ops),
        }
        if choice in actions:
            actions[choice]()


def show_c2_menu():
    while True:
        os.system('cls' if os.name == 'nt' else 'clear')
        draw_header("Command & Control (C2)", context=ctx)
        choice = questionary.select(
            "Select C2 Module:",
            choices=[
                Separator("─── C2 INFRASTRUCTURE ─────────────────────────"),
                Choice("GhostHub C2  (AES Encrypted Session Manager)",
                       value="hub"),
                Separator("─── PAYLOAD GENERATION ────────────────────────"),
                Choice("Payload Forge  (Polymorphic / AI-Mutated / MSF)",
                       value="payloads"),
                Choice("Crypt-Keeper  (AV Evasion / HWID / Env Lock)",
                       value="crypt"),
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
            "crypt": lambda: safe_execute(run_crypt_keeper),
        }
        if choice in actions:
            actions[choice]()


def show_intel_menu():
    while True:
        os.system('cls' if os.name == 'nt' else 'clear')
        draw_header("Intelligence & Reporting", context=ctx)
        choice = questionary.select(
            "Select Intel Module:",
            choices=[
                Separator("─── REPORTING ─────────────────────────────────"),
                Choice("Generate Mission Report  (Interactive HTML)",
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


def show_system_menu():
    while True:
        os.system('cls' if os.name == 'nt' else 'clear')
        draw_header("System & Configuration", context=ctx)
        choice = questionary.select(
            "System Options:",
            choices=[
                Choice("Context Configuration",               value="ctx"),
                Choice("Scope Manager  (Target Whitelist)",   value="scope"),
                Choice("Auditor & Dependency Check",          value="audit"),
                Choice("Plugin Manager",                      value="plugins"),
                Choice("Framework Update",                    value="update"),
                Separator("─────────────────────────────────────────────"),
                Choice("Return to Main Menu",                 value="back"),
            ],
            style=Q_STYLE
        ).ask()
        if not choice or choice == "back":
            break
        actions = {
            "ctx":     configure_global_context,
            "scope": lambda: safe_execute(run_scope_manager),
            "audit": lambda: safe_execute(run_auditor),
            "plugins": show_plugin_menu,
            "update":  perform_update,
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
        "recon":       show_reconnaissance_menu,
        "assault":     show_assault_menu,
        "postexploit": show_post_exploit_menu,
        "web":         show_web_menu,
        "network":     show_network_menu,
        "c2":          show_c2_menu,
        "ai": lambda: safe_execute(run_ai_console),
        "godmode": lambda: safe_execute(run_god_mode),
        "intel":       show_intel_menu,
        "system":      show_system_menu,
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
                    Choice("2.  Exploitation  (MSF / AD / Hash Cracker)",
                           value="assault"),
                    Choice(
                        "3.  Post-Exploitation  (Loot / Creds / Persist)", value="postexploit"),
                    Choice(
                        "4.  Web Operations  (WebGhost / Phishing Kit)",   value="web"),
                    Choice("5.  Network & Cloud  (Sniffer / MITM / Cloud)",
                           value="network"),
                    Choice(
                        "6.  Command & Control  (C2 / Payloads / Crypt)",  value="c2"),
                    Separator(
                        "─── INTELLIGENCE ──────────────────────────────"),
                    Choice("7.  AI Cortex  (Autonomous Pentest Agent)",
                           value="ai"),
                    Choice("8.  GOD MODE  — Full Autonomous Campaign",
                           value="godmode"),
                    Choice(
                        "9.  Intel & Reporting  (HTML Report / ATT&CK)",   value="intel"),
                    Separator(
                        "─── SYSTEM ────────────────────────────────────"),
                    Choice(
                        "    System & Config  (Scope / Auditor / Plugins)", value="system"),
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
                    "Execute Vanish Protocol? (clears logs, payloads, DB)",
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
