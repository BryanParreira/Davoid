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
encrypt_payload = _try_import("modules.crypt_keeper", "encrypt_payload")
crack_hash = _try_import("modules.bruteforce",   "crack_hash")
PersistenceEngine = _try_import("modules.persistence",  "PersistenceEngine")
run_ai_console = _try_import("modules.ai_assist",    "run_ai_console")
generate_report = _try_import("modules.reporter",     "generate_report")
run_ad_ops = _try_import("modules.ad_ops",       "run_ad_ops")
run_msf = _try_import("modules.msf_engine",   "run_msf")
run_looter = _try_import("modules.looter",       "run_looter")
run_auditor = _try_import("modules.auditor",      "run_auditor")
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
    ('separator',   'fg:#666666'),
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

        gw = "Unknown"
        try:
            if sys.platform == "darwin":
                out = subprocess.check_output(
                    ["route", "-n", "get", "default"], stderr=subprocess.DEVNULL, timeout=5).decode()
                for line in out.splitlines():
                    if "gateway:" in line:
                        gw = line.split(":")[1].strip()
                        break
            else:
                out = subprocess.check_output(
                    ["ip", "route"], stderr=subprocess.DEVNULL, timeout=5).decode()
                for line in out.splitlines():
                    if line.startswith("default via"):
                        gw = line.split()[2].strip()
                        break
        except Exception:
            pass

        ctx.set("GATEWAY", gw)
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


def configure_global_context():
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
            choices=[Choice("Set Variable", value="set"), Choice(
                "Rotate Identity (Refresh Network)", value="rotate"), Choice("Back", value="back")],
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
#  WRAPPER ROUTERS & MENUS (REORGANIZED)
# ─────────────────────────────────────────────────────────────────────────────


def run_net_scan():
    sub = questionary.select("Network Tool:", choices=[
                             "Active Discovery (Nmap)", "Passive Sniffer", "Back"], style=Q_STYLE).ask()
    if not sub or sub == "Back":
        return
    if "Active" in sub:
        safe_execute(network_discovery)
    elif "Sniffer" in sub:
        if SnifferEngine is None:
            safe_execute(None)
        else:
            safe_execute(lambda: SnifferEngine().start())


def run_person_osint():
    sub = questionary.select("Mode:", choices=[
                             "Username Tracker", "Phone Intel", "Geo-IP Tracker", "Back"], style=Q_STYLE).ask()
    if not sub or sub == "Back":
        return
    if "Username" in sub:
        safe_execute(username_tracker)
    elif "Phone" in sub:
        safe_execute(phone_intel)
    elif "Geo-IP" in sub:
        safe_execute(geolocate)


def run_ai_ops():
    sub = questionary.select("AI Ops:", choices=[
                             "Launch Cortex", "Generate Report (DB)", "Back"], style=Q_STYLE).ask()
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


def show_reconnaissance_menu():
    while True:
        os.system('cls' if os.name == 'nt' else 'clear')
        draw_header("Intelligence & Reconnaissance", context=ctx)
        cat = questionary.select(
            "Select Recon Category:",
            choices=[
                Choice("1. Active Scanning & Probing", value="active"),
                Choice("2. Passive OSINT & Archives", value="passive"),
                Choice("3. Target Identity & Geo-Tracking", value="identity"),
                Separator("────────────────────────────────────────"),
                Choice("Back to Main Menu", value="back"),
            ], style=Q_STYLE
        ).ask()

        if not cat or cat == "back":
            break

        if cat == "active":
            while True:
                os.system('cls' if os.name == 'nt' else 'clear')
                draw_header("Active Scanning & Probing", context=ctx)
                sub = questionary.select("Select Module:", choices=[
                    Choice("Network Scanner (Nmap) & Sniffer", value="net"),
                    Choice("Web Vulnerability Scanner",        value="web"),
                    Choice("DNS Infrastructure Recon",         value="recon"),
                    Separator("────────────────────────────────────────"),
                    Choice("Back to Recon Menu", value="back"),
                ], style=Q_STYLE).ask()
                if not sub or sub == "back":
                    break
                if sub == "net":
                    run_net_scan()
                elif sub == "web":
                    safe_execute(web_ghost)
                elif sub == "recon":
                    safe_execute(dns_recon)

        elif cat == "passive":
            while True:
                os.system('cls' if os.name == 'nt' else 'clear')
                draw_header("Passive OSINT & Archives", context=ctx)
                sub = questionary.select("Select Module:", choices=[
                    Choice("Shodan API (Attack Surface)",      value="shodan"),
                    Choice("DNS & Subdomain Mapping",          value="dns"),
                    Choice("Wayback Machine (Archive Mining)", value="wayback"),
                    Choice("Google Dork Generator",            value="dork"),
                    Separator("────────────────────────────────────────"),
                    Choice("Back to Recon Menu", value="back"),
                ], style=Q_STYLE).ask()
                if not sub or sub == "back":
                    break
                if sub == "shodan":
                    safe_execute(shodan_intel)
                elif sub == "dns":
                    safe_execute(dns_intel)
                elif sub == "wayback":
                    safe_execute(wayback_intel)
                elif sub == "dork":
                    safe_execute(dork_generator)

        elif cat == "identity":
            run_person_osint()


def show_assault_menu():
    while True:
        os.system('cls' if os.name == 'nt' else 'clear')
        draw_header("Exploitation & Assault", context=ctx)
        cat = questionary.select(
            "Select Assault Category:",
            choices=[
                Choice("1. Enterprise Exploitation & Post-Exploit",
                       value="enterprise"),
                Choice("2. Network & MITM Attacks", value="network"),
                Choice("3. Social Engineering & Credentials", value="social"),
                Separator("────────────────────────────────────────"),
                Choice("Back to Main Menu", value="back"),
            ], style=Q_STYLE
        ).ask()

        if not cat or cat == "back":
            break

        if cat == "enterprise":
            while True:
                os.system('cls' if os.name == 'nt' else 'clear')
                draw_header("Enterprise Exploitation", context=ctx)
                sub = questionary.select("Select Module:", choices=[
                    Choice("Metasploit Framework (MSF-RPC)",   value="msf"),
                    Choice("Active Directory Ops",             value="ad"),
                    Choice("Cloud & Container Warfare",        value="cloud"),
                    Choice("PrivEsc Looter (Post-Exploit)",    value="loot"),
                    Separator("────────────────────────────────────────"),
                    Choice("Back to Assault Menu", value="back"),
                ], style=Q_STYLE).ask()
                if not sub or sub == "back":
                    break
                if sub == "msf":
                    safe_execute(run_msf)
                elif sub == "ad":
                    safe_execute(run_ad_ops)
                elif sub == "cloud":
                    safe_execute(run_cloud_ops)
                elif sub == "loot":
                    safe_execute(run_looter)

        elif cat == "network":
            while True:
                os.system('cls' if os.name == 'nt' else 'clear')
                draw_header("Network & MITM Attacks", context=ctx)
                sub = questionary.select("Select Module:", choices=[
                    Choice("MITM Interceptor (ARP Poison)",    value="mitm"),
                    Choice("DNS Spoofer",                      value="dns"),
                    Choice("WiFi Attack Suite",                value="wifi"),
                    Separator("────────────────────────────────────────"),
                    Choice("Back to Assault Menu", value="back"),
                ], style=Q_STYLE).ask()
                if not sub or sub == "back":
                    break
                if sub == "mitm":
                    safe_execute(lambda: MITMEngine().run()
                                 ) if MITMEngine else safe_execute(None)
                elif sub == "dns":
                    safe_execute(start_dns_spoof)
                elif sub == "wifi":
                    safe_execute(run_wifi_suite)

        elif cat == "social":
            while True:
                os.system('cls' if os.name == 'nt' else 'clear')
                draw_header("Social & Credential", context=ctx)
                sub = questionary.select("Select Module:", choices=[
                    Choice("AitM Web Cloner (Phishing Proxy)", value="clone"),
                    Choice("Hash Cracker",                     value="crack"),
                    Separator("────────────────────────────────────────"),
                    Choice("Back to Assault Menu", value="back"),
                ], style=Q_STYLE).ask()
                if not sub or sub == "back":
                    break
                if sub == "clone":
                    safe_execute(run_cloner)
                elif sub == "crack":
                    safe_execute(crack_hash)


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
        draw_header("Infrastructure, C2 & Evasion", context=ctx)
        choice = questionary.select(
            "Select Infra Operation:",
            choices=[
                Choice("1. AI Polymorphic Payload Forge",     value="forge"),
                Choice("2. Payload Encryptor (CryptKeeper)",  value="crypt"),
                Choice("3. Persistence Installer",            value="persist"),
                Choice("4. GhostHub C2 Server",               value="c2"),
                Choice("5. System Posture Auditor",           value="audit"),
                Separator("────────────────────────────────────────"),
                Choice("Back to Main Menu",              value="back"),
            ],
            style=Q_STYLE
        ).ask()
        if not choice or choice == "back":
            break
        if choice in actions:
            actions[choice]()


def show_autonomous_menu():
    while True:
        os.system('cls' if os.name == 'nt' else 'clear')
        draw_header("AI & Autonomous Operations", context=ctx)
        choice = questionary.select(
            "Select Autonomous Module:",
            choices=[
                Choice("1. AI Cortex & Reporting", value="ai"),
                Choice("2. GOD MODE (Auto-Campaign)", value="god"),
                Choice("3. Purple Team Emulation", value="purple"),
                Separator("────────────────────────────────────────"),
                Choice("Back to Main Menu", value="back")
            ],
            style=Q_STYLE
        ).ask()

        if not choice or choice == "back":
            break
        elif choice == "ai":
            run_ai_ops()
        elif choice == "god":
            safe_execute(run_god_mode)
        elif choice == "purple":
            safe_execute(run_purple_team)


def show_system_menu():
    while True:
        os.system('cls' if os.name == 'nt' else 'clear')
        draw_header("Framework Configuration", context=ctx)
        choice = questionary.select(
            "Select System Option:",
            choices=[
                Choice("1. Configuration & Context", value="sys"),
                Choice(
                    f"2. Community Plugins ({len(LOADED_PLUGINS)})", value="plugins"),
                Choice("3. Framework Update", value="update"),
                Separator("────────────────────────────────────────"),
                Choice("Back to Main Menu", value="back")
            ],
            style=Q_STYLE
        ).ask()

        if not choice or choice == "back":
            break
        elif choice == "sys":
            configure_global_context()
        elif choice == "plugins":
            show_plugins_menu()
        elif choice == "update":
            perform_update()


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
        "auto":    show_autonomous_menu,
        "system":  show_system_menu,
    }

    while True:
        try:
            os.system('cls' if os.name == 'nt' else 'clear')
            draw_header("Master Command Hub", context=ctx)
            check_version()

            phase = questionary.select(
                "Select Mission Phase:",
                choices=[
                    Choice("1. Intelligence & Reconnaissance", value="recon"),
                    Choice("2. Exploitation & Assault",
                           value="assault"),
                    Choice("3. Infrastructure, C2 & Evasion",  value="infra"),
                    Choice("4. AI & Autonomous Operations",    value="auto"),
                    Choice("5. Framework Settings & Plugins",  value="system"),
                    Separator("────────────────────────────────────────"),
                    Choice("6. Execute Vanish Protocol (Exit)", value="exit"),
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
