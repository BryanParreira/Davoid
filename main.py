"""
main.py — Davoid Red Team Framework (Legendary Edition)
Master entry point featuring Cloud Warfare, AI Polymorphism, God Mode, and Purple Team emulation.
"""

import sys
import os
import warnings
import subprocess
import shutil
import time
import importlib.util
import inspect
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

# Ensure essential directories exist
os.makedirs("logs", exist_ok=True)
os.makedirs("payloads", exist_ok=True)
os.makedirs("plugins", exist_ok=True)

# ─────────────────────────────────────────────────────────────────────────────
#  CORE IMPORTS
# ─────────────────────────────────────────────────────────────────────────────
try:
    from core.ui import draw_header
    from core.updater import check_version, perform_update
    from core.context import ctx
    from core.database import db
    from core.plugin import DavoidPlugin
    try:
        from core.config import load_config
    except ImportError:
        def load_config(): return None
except ImportError as e:
    print(f"[!] Critical core component missing: {e}")
    sys.exit(1)

# ─────────────────────────────────────────────────────────────────────────────
#  SAFE MODULE LOADER
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
crack_hash = _try_import("modules.bruteforce",   "crack_hash")
PersistenceEngine = _try_import("modules.persistence",  "PersistenceEngine")
run_ai_console = _try_import("modules.ai_assist",    "run_ai_console")
generate_report = _try_import("modules.reporter",     "generate_report")
run_ad_ops = _try_import("modules.ad_ops",       "run_ad_ops")
run_msf = _try_import("modules.msf_engine",   "run_msf")
run_looter = _try_import("modules.looter",       "run_looter")
run_cloud_ops = _try_import("modules.cloud_ops",    "run_cloud_ops")
run_god_mode = _try_import("modules.god_mode",     "run_god_mode")
run_purple_team = _try_import("modules.purple_team",  "run_purple_team")

username_tracker = phone_intel = geolocate = None
dork_generator = wayback_intel = shodan_intel = dns_intel = None
try:
    from modules.osint_pro import (
        username_tracker, phone_intel, geolocate,
        dork_generator, wayback_intel, shodan_intel, dns_intel,
    )
except Exception:
    pass

console = Console()

Q_STYLE = questionary.Style([
    ('qmark',       'fg:#ff0000 bold'),
    ('question',    'fg:#ffffff bold'),
    ('answer',      'fg:#ff0000 bold'),
    ('pointer',     'fg:#ff0000 bold'),
    ('highlighted', 'fg:#ff0000 bold'),
    ('selected',    'fg:#cc5454'),
    ('separator',   'fg:#444444'),
    ('instruction', 'fg:#666666 italic'),
])

# ─────────────────────────────────────────────────────────────────────────────
#  PLUGIN LOADER (Davoid Scripting Engine)
# ─────────────────────────────────────────────────────────────────────────────
LOADED_PLUGINS = []


def load_plugins():
    global LOADED_PLUGINS
    LOADED_PLUGINS = []
    plugins_dir = os.path.join(SCRIPT_DIR, "plugins")
    if not os.path.exists(plugins_dir):
        return

    for filename in os.listdir(plugins_dir):
        if filename.endswith(".py") and not filename.startswith("__"):
            file_path = os.path.join(plugins_dir, filename)
            module_name = f"plugins.{filename[:-3]}"
            try:
                spec = importlib.util.spec_from_file_location(
                    module_name, file_path)
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)

                for name, obj in inspect.getmembers(module, inspect.isclass):
                    if issubclass(obj, DavoidPlugin) and obj is not DavoidPlugin:
                        LOADED_PLUGINS.append(obj())
            except Exception as e:
                console.print(
                    f"[dim red]Failed to load plugin {filename}: {e}[/dim red]")

# ─────────────────────────────────────────────────────────────────────────────
#  SYSTEM HELPERS
# ─────────────────────────────────────────────────────────────────────────────


def detect_network_environment():
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
        return True
    except Exception:
        return False


def execute_vanish_protocol():
    console.print("\n[bold red]INITIATING VANISH SEQUENCE...[/bold red]")
    for target_dir in ["clones", "payloads", "__pycache__"]:
        if os.path.exists(target_dir):
            shutil.rmtree(target_dir, ignore_errors=True)
            console.print(f"[dim]  Wiped: {target_dir}/[/dim]")
    for root, dirs, _ in os.walk("."):
        for d in dirs:
            if d == "__pycache__":
                shutil.rmtree(os.path.join(root, d), ignore_errors=True)
    if os.path.exists("logs"):
        if questionary.confirm("Also wipe logs/ ? (Mission DB + C2 AES key will be lost)", default=False, style=Q_STYLE).ask():
            shutil.rmtree("logs", ignore_errors=True)
            console.print("[dim]  Wiped: logs/[/dim]")
    console.print("[bold green][*] Evidence cleared. Ghost out.[/bold green]")
    sys.exit(0)


def safe_execute(func, *args, **kwargs):
    if func is None:
        console.print(
            "\n[bold red][!] Module offline or missing dependencies.[/bold red]")
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
#  MENU ROUTERS
# ─────────────────────────────────────────────────────────────────────────────


def show_reconnaissance_menu():
    actions = {
        "net": lambda: safe_execute(network_discovery),
        "web": lambda: safe_execute(web_ghost),
        "shodan": lambda: safe_execute(shodan_intel),
        "dns": lambda: safe_execute(dns_intel),
        "person": lambda: safe_execute(username_tracker),
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
                Choice("Social OSINT (Identity Tracker)",  value="person"),
                Separator("─── NAVIGATION ─────────────────────────"),
                Choice("Return to Main Menu",              value="back"),
            ], style=Q_STYLE
        ).ask()
        if not choice or choice == "back":
            break
        if choice in actions:
            actions[choice]()


def show_assault_menu():
    actions = {
        "msf": lambda: safe_execute(run_msf),
        "ad": lambda: safe_execute(run_ad_ops),
        "cloud": lambda: safe_execute(run_cloud_ops),
        "loot": lambda: safe_execute(run_looter),
        "mitm": lambda: safe_execute(lambda: MITMEngine().run()) if MITMEngine else safe_execute(None),
        "dns": lambda: safe_execute(start_dns_spoof),
        "wifi": lambda: safe_execute(run_wifi_suite),
        "clone": lambda: safe_execute(run_cloner),
    }
    while True:
        os.system('cls' if os.name == 'nt' else 'clear')
        draw_header("Direct Action & Exploitation", context=ctx)
        choice = questionary.select(
            "Select Assault Vector:",
            choices=[
                Separator("─── ENTERPRISE EXPLOITATION ────────────"),
                Choice("Metasploit Framework (MSF-RPC)",   value="msf"),
                Choice("Active Directory Ops",             value="ad"),
                Choice("Cloud & Container Warfare",        value="cloud"),
                Choice("PrivEsc Looter (Post-Exploit)",    value="loot"),
                Separator("─── NETWORK ATTACKS ────────────────────"),
                Choice("MITM Interceptor (ARP Poison)",    value="mitm"),
                Choice("DNS Spoofer",                      value="dns"),
                Choice("WiFi Attack Suite",                value="wifi"),
                Separator("─── SOCIAL & CREDENTIAL ─────────────────"),
                Choice("AitM Web Cloner (Phishing Proxy)", value="clone"),
                Separator("─── NAVIGATION ─────────────────────────"),
                Choice("Return to Main Menu",              value="back"),
            ], style=Q_STYLE
        ).ask()
        if not choice or choice == "back":
            break
        if choice in actions:
            actions[choice]()


def show_infrastructure_menu():
    actions = {
        "forge": lambda: safe_execute(generate_shell),
        "persist": lambda: safe_execute(lambda: PersistenceEngine(questionary.text("Path:", style=Q_STYLE).ask()).run()) if PersistenceEngine else safe_execute(None),
        "c2": lambda: safe_execute(run_ghost_hub),
    }
    while True:
        os.system('cls' if os.name == 'nt' else 'clear')
        draw_header("Infrastructure, C2 & Evasion", context=ctx)
        choice = questionary.select(
            "Select C2 Operation:",
            choices=[
                Separator("─── WEAPONIZATION ──────────────────────"),
                Choice("AI Polymorphic Payload Forge",     value="forge"),
                Separator("─── PERSISTENCE & C2 ───────────────────"),
                Choice("Persistence Installer",            value="persist"),
                Choice("GhostHub C2 Server",               value="c2"),
                Separator("─── NAVIGATION ─────────────────────────"),
                Choice("Return to Main Menu",              value="back"),
            ], style=Q_STYLE
        ).ask()
        if not choice or choice == "back":
            break
        if choice in actions:
            actions[choice]()


def show_plugins_menu():
    while True:
        os.system('cls' if os.name == 'nt' else 'clear')
        draw_header("Davoid Scripting Engine (DSE)", context=ctx)

        if not LOADED_PLUGINS:
            console.print(
                "[yellow][!] No community plugins found in /plugins directory.[/yellow]")
            questionary.press_any_key_to_continue(style=Q_STYLE).ask()
            break

        choices = [Separator("─── LOADED PLUGINS ────────────────────")]
        for idx, plugin in enumerate(LOADED_PLUGINS):
            choices.append(
                Choice(f"{plugin.name} (by {plugin.author})", value=idx))
        choices.append(Separator("───────────────────────────────────────"))
        choices.append(Choice("Return to Main Menu", value="back"))

        choice = questionary.select(
            "Select Plugin to Execute:", choices=choices, style=Q_STYLE).ask()

        if choice == "back" or choice is None:
            break

        try:
            plugin = LOADED_PLUGINS[choice]
            console.print(
                f"\n[*] Executing Plugin: [bold cyan]{plugin.name}[/bold cyan]")
            console.print(f"[dim]{plugin.description}[/dim]\n")
            plugin.run()
            questionary.press_any_key_to_continue(style=Q_STYLE).ask()
        except Exception as e:
            console.print(
                f"[bold red][!] Plugin execution failed:[/bold red] {e}")
            questionary.press_any_key_to_continue(style=Q_STYLE).ask()

# ─────────────────────────────────────────────────────────────────────────────
#  MAIN LOOP
# ─────────────────────────────────────────────────────────────────────────────


def main():
    if len(sys.argv) > 1 and sys.argv[1] == "--update":
        perform_update()
        sys.exit(0)

    detect_network_environment()
    load_config()
    load_plugins()

    actions = {
        "recon":   show_reconnaissance_menu,
        "assault": show_assault_menu,
        "infra":   show_infrastructure_menu,
        "god": lambda: safe_execute(run_god_mode),
        "purple": lambda: safe_execute(run_purple_team),
        "ai": lambda: safe_execute(run_ai_console),
        "plugins": show_plugins_menu,
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
                    Choice("3.  C2 & Polymorphic Forge",  value="infra"),
                    Separator("─── INTELLIGENCE & AUTOMATION ────────"),
                    Choice("4.  AI Cortex Console",       value="ai"),
                    Choice("5.  GOD MODE (Auto-Campaign)", value="god"),
                    Choice("6.  Purple Team Emulation",   value="purple"),
                    Separator("─── ECOSYSTEM ──────────────────────────"),
                    Choice(
                        f"    Community Plugins ({len(LOADED_PLUGINS)})", value="plugins"),
                    Separator("─── SYSTEM ─────────────────────────────"),
                    Choice("    Execute Vanish Protocol", value="exit"),
                ],
                style=Q_STYLE,
                pointer="▶"
            ).ask()

            if not phase:
                continue
            if phase == "exit":
                if questionary.confirm("Execute Vanish Protocol?", default=True, style=Q_STYLE).ask():
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
