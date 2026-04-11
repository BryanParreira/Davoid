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

os.makedirs("logs",    exist_ok=True)
os.makedirs("payloads", exist_ok=True)
os.makedirs("plugins",  exist_ok=True)

# ─────────────────────────────────────────────────────────────────────────────
#  CORE IMPORTS
# ─────────────────────────────────────────────────────────────────────────────
try:
    from core.ui import draw_header, Q_STYLE
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


# ── Recon & OSINT ─────────────────────────────────────────────────────────────
network_discovery  = _try_import("modules.scanner",  "network_discovery")
SnifferEngine      = _try_import("modules.sniff",     "SnifferEngine")
web_ghost          = _try_import("modules.web_recon", "web_ghost")
run_burp_proxy     = _try_import("modules.burp_proxy","run_burp_proxy")

# All OSINT/recon now lives in modules.recon
dns_recon          = _try_import("modules.recon", "dns_recon")
shodan_intel       = _try_import("modules.recon", "shodan_intel")
wayback_intel      = _try_import("modules.recon", "wayback_intel")
dork_generator     = _try_import("modules.recon", "dork_generator")
person_osint_menu  = _try_import("modules.recon", "person_osint_menu")
passive_intel_menu = _try_import("modules.recon", "passive_intel_menu")

# ── Assault ───────────────────────────────────────────────────────────────────
MITMEngine         = _try_import("modules.spoof",      "MITMEngine")
start_dns_spoof    = _try_import("modules.dns_spoofer","start_dns_spoof")
run_cloner         = _try_import("modules.cloner",     "run_cloner")
run_wifi_suite     = _try_import("modules.wifi_ops",   "run_wifi_suite")
crack_hash         = _try_import("modules.bruteforce", "crack_hash")
run_ad_ops         = _try_import("modules.ad_ops",     "run_ad_ops")
run_msf            = _try_import("modules.msf_engine", "run_msf")
run_looter         = _try_import("modules.looter",     "run_looter")
run_cloud_ops      = _try_import("modules.cloud_ops",  "run_cloud_ops")

# ── Infrastructure ────────────────────────────────────────────────────────────
generate_shell     = _try_import("modules.payloads",    "generate_shell")
encrypt_payload    = _try_import("modules.crypt_keeper","encrypt_payload")
PersistenceEngine  = _try_import("modules.persistence", "PersistenceEngine")
run_ghost_hub      = _try_import("modules.ghost_hub",   "run_ghost_hub")
run_auditor        = _try_import("modules.auditor",     "run_auditor")
run_stego          = _try_import("modules.stego",       "run_stego")

# ── Intelligence & Reporting ──────────────────────────────────────────────────
run_ai_console     = _try_import("modules.ai_assist",   "run_ai_console")
generate_report    = _try_import("modules.reporter",    "generate_report")
run_purple_team    = _try_import("modules.purple_team", "run_purple_team")

# ── Autonomous ────────────────────────────────────────────────────────────────
run_god_mode       = _try_import("modules.god_mode",    "run_god_mode")

console = Console()

# ─────────────────────────────────────────────────────────────────────────────
#  SECURITY ENFORCEMENT
# ─────────────────────────────────────────────────────────────────────────────

def enforce_security_context():
    pass


# ─────────────────────────────────────────────────────────────────────────────
#  PLUGIN LOADER
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
            file_path   = os.path.join(plugins_dir, filename)
            module_name = f"plugins.{filename[:-3]}"
            try:
                spec   = importlib.util.spec_from_file_location(module_name, file_path)
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)
                for name, obj in inspect.getmembers(module, inspect.isclass):
                    if issubclass(obj, DavoidPlugin) and obj is not DavoidPlugin:
                        LOADED_PLUGINS.append(obj())
            except Exception as e:
                console.print(f"[dim red]Failed to load plugin {filename}: {e}[/dim red]")


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
                    ["route", "-n", "get", "default"],
                    stderr=subprocess.DEVNULL, timeout=5).decode()
                for line in out.splitlines():
                    if "gateway:" in line:
                        gw = line.split(":")[1].strip()
                        break
            else:
                out = subprocess.check_output(
                    ["ip", "route"],
                    stderr=subprocess.DEVNULL, timeout=5).decode()
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


def secure_wipe(filepath, passes=3):
    if not os.path.exists(filepath):
        return
    length = os.path.getsize(filepath)
    try:
        with open(filepath, "ba+", buffering=0) as f:
            for _ in range(passes):
                f.seek(0)
                f.write(os.urandom(length))
        os.remove(filepath)
    except Exception:
        pass


def execute_vanish_protocol():
    console.print("\n[bold red]INITIATING FORENSIC VANISH SEQUENCE...[/bold red]")
    try:
        db.delete_all()
        console.print("[dim]  Mission DB records wiped.[/dim]")
    except Exception:
        pass
    critical_files = [
        os.path.join(os.path.expanduser("~"), ".davoid", "davoid_mission.db"),
        os.path.join(os.path.expanduser("~"), ".davoid", ".db_key"),
        "logs/c2_aes.key",
        "/opt/davoid/.db_key",
    ]
    for f in critical_files:
        if os.path.exists(f):
            secure_wipe(f)
            console.print(f"[dim]  Shredded: {f}[/dim]")
    for target_dir in ["clones", "payloads", "__pycache__", "logs"]:
        if os.path.exists(target_dir):
            for root, dirs, files in os.walk(target_dir):
                for file in files:
                    secure_wipe(os.path.join(root, file), passes=1)
            shutil.rmtree(target_dir, ignore_errors=True)
            console.print(f"[dim]  Wiped & Removed: {target_dir}/[/dim]")
    for root, dirs, _ in os.walk("."):
        for d in dirs:
            if d == "__pycache__":
                shutil.rmtree(os.path.join(root, d), ignore_errors=True)
    console.print("[bold green][*] Forensic evidence cleared. Ghost out.[/bold green]")
    sys.exit(0)


def safe_execute(func, *args, **kwargs):
    if func is None:
        console.print("\n[bold red][!] Module offline or missing dependencies.[/bold red]")
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
            key = questionary.text("Variable name (blank = cancel):", style=Q_STYLE).ask()
            if key:
                val = questionary.text(f"Value for {key}:", style=Q_STYLE).ask()
                ctx.set(key, val)
        elif action == "rotate":
            console.print("[dim]Refreshing network identity...[/dim]")
            time.sleep(1)
            detect_network_environment()


# ─────────────────────────────────────────────────────────────────────────────
#  WRAPPER HELPERS
# ─────────────────────────────────────────────────────────────────────────────

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
    path = questionary.text("Payload path (blank = cancel):", style=Q_STYLE).ask()
    if path:
        safe_execute(lambda: PersistenceEngine(path).run())


# ─────────────────────────────────────────────────────────────────────────────
#  MENU: RECON & OSINT  (consolidated — no redundant submenus)
# ─────────────────────────────────────────────────────────────────────────────

def show_reconnaissance_menu():
    actions = {
        # ── Active ──────────────────────────────────────────────────────────
        "nmap":    lambda: safe_execute(network_discovery),
        "sniff":   lambda: safe_execute(
                       lambda: SnifferEngine().start()) if SnifferEngine else safe_execute(None),
        "web":     lambda: safe_execute(web_ghost),
        "burp":    lambda: safe_execute(run_burp_proxy),
        # ── Infrastructure ──────────────────────────────────────────────────
        "dns":     lambda: safe_execute(dns_recon),
        "shodan":  lambda: safe_execute(shodan_intel),
        # ── Person OSINT (username + phone + geo merged) ─────────────────────
        "person":  lambda: safe_execute(person_osint_menu),
        # ── Passive archive (wayback + dork merged) ──────────────────────────
        "passive": lambda: safe_execute(passive_intel_menu),
    }

    while True:
        os.system('cls' if os.name == 'nt' else 'clear')
        draw_header("Target Acquisition & Intelligence", context=ctx)
        choice = questionary.select(
            "Select Recon Module:",
            choices=[
                Separator("─── ACTIVE SCANNING ───────────────────────"),
                Choice("Network Scanner (Nmap)",            value="nmap"),
                Choice("Passive Traffic Sniffer",           value="sniff"),
                Choice("Web Header & Path Auditor",         value="web"),
                Choice("Web Interception Proxy (HTTPS)",    value="burp"),
                Separator("─── INFRASTRUCTURE ────────────────────────"),
                Choice("DNS & Subdomain Mapping",           value="dns"),
                Choice("Attack Surface — InternetDB/Shodan",value="shodan"),
                Separator("─── OSINT ────────────────────────────────"),
                Choice("Person OSINT  (Username/Phone/Geo)",value="person"),
                Choice("Passive Intel (Wayback / Dorks)",   value="passive"),
                Separator("─── NAVIGATION ───────────────────────────"),
                Choice("Return to Main Menu",               value="back"),
            ],
            style=Q_STYLE
        ).ask()
        if not choice or choice == "back":
            break
        if choice in actions:
            actions[choice]()


# ─────────────────────────────────────────────────────────────────────────────
#  MENU: ASSAULT & EXPLOITATION
# ─────────────────────────────────────────────────────────────────────────────

def show_assault_menu():
    actions = {
        "msf":   lambda: safe_execute(run_msf),
        "ad":    lambda: safe_execute(run_ad_ops),
        "cloud": lambda: safe_execute(run_cloud_ops),
        "loot":  lambda: safe_execute(run_looter),
        "mitm":  lambda: safe_execute(
                     lambda: MITMEngine().run()) if MITMEngine else safe_execute(None),
        "dns":   lambda: safe_execute(start_dns_spoof),
        "wifi":  lambda: safe_execute(run_wifi_suite),
        "clone": lambda: safe_execute(run_cloner),
        "crack": lambda: safe_execute(crack_hash),
    }

    while True:
        os.system('cls' if os.name == 'nt' else 'clear')
        draw_header("Direct Action & Exploitation", context=ctx)
        choice = questionary.select(
            "Select Assault Vector:",
            choices=[
                Separator("─── ENTERPRISE EXPLOITATION ─────────────"),
                Choice("Metasploit Framework (MSF-RPC)",    value="msf"),
                Choice("Active Directory Ops",              value="ad"),
                Choice("Cloud & Container Warfare",         value="cloud"),
                Choice("PrivEsc Looter (Post-Exploit)",     value="loot"),
                Separator("─── NETWORK ATTACKS ──────────────────────"),
                Choice("MITM Interceptor (ARP Poison)",     value="mitm"),
                Choice("DNS Spoofer",                       value="dns"),
                Choice("WiFi Attack Suite",                 value="wifi"),
                Separator("─── SOCIAL & CREDENTIAL ──────────────────"),
                Choice("AitM Web Cloner (Phishing Proxy)",  value="clone"),
                Choice("Hash Cracker",                      value="crack"),
                Separator("─── NAVIGATION ───────────────────────────"),
                Choice("Return to Main Menu",               value="back"),
            ],
            style=Q_STYLE
        ).ask()
        if not choice or choice == "back":
            break
        if choice in actions:
            actions[choice]()


# ─────────────────────────────────────────────────────────────────────────────
#  MENU: C2 & PAYLOAD FORGE
# ─────────────────────────────────────────────────────────────────────────────

def show_infrastructure_menu():
    actions = {
        "forge":   lambda: safe_execute(generate_shell),
        "crypt":   run_encrypt,
        "persist": run_persist,
        "c2":      lambda: safe_execute(run_ghost_hub),
        "audit":   lambda: safe_execute(run_auditor),
        "stego":   lambda: safe_execute(run_stego),
    }

    while True:
        os.system('cls' if os.name == 'nt' else 'clear')
        draw_header("Infrastructure, C2 & Evasion", context=ctx)
        choice = questionary.select(
            "Select C2 Operation:",
            choices=[
                Separator("─── WEAPONIZATION ────────────────────────"),
                Choice("AI Polymorphic Payload Forge",       value="forge"),
                Choice("Payload Encryptor (CryptKeeper)",    value="crypt"),
                Choice("Steganography (Hide Data in Image)", value="stego"),
                Separator("─── PERSISTENCE & C2 ─────────────────────"),
                Choice("Persistence Installer",              value="persist"),
                Choice("GhostHub C2 Server",                 value="c2"),
                Separator("─── AUDIT ────────────────────────────────"),
                Choice("System Posture Auditor",             value="audit"),
                Separator("─── NAVIGATION ───────────────────────────"),
                Choice("Return to Main Menu",                value="back"),
            ],
            style=Q_STYLE
        ).ask()
        if not choice or choice == "back":
            break
        if choice in actions:
            actions[choice]()


# ─────────────────────────────────────────────────────────────────────────────
#  MENU: INTELLIGENCE & REPORTING  (AI Cortex + Purple Team merged)
# ─────────────────────────────────────────────────────────────────────────────

def show_intel_reporting_menu():
    actions = {
        "cortex":  lambda: safe_execute(run_ai_console),
        "report":  lambda: safe_execute(generate_report),
        "purple":  lambda: safe_execute(run_purple_team),
    }

    while True:
        os.system('cls' if os.name == 'nt' else 'clear')
        draw_header("Intelligence, AI & Reporting", context=ctx)
        choice = questionary.select(
            "Select Operation:",
            choices=[
                Separator("─── AI CORTEX ────────────────────────────"),
                Choice("Launch AI Cortex (Tactical Advisor)", value="cortex"),
                Separator("─── REPORTING ────────────────────────────"),
                Choice("Generate Mission Report (HTML)",      value="report"),
                Separator("─── PURPLE TEAM ──────────────────────────"),
                Choice("Purple Team — MITRE ATT&CK Mapping",  value="purple"),
                Separator("─── NAVIGATION ───────────────────────────"),
                Choice("Return to Main Menu",                 value="back"),
            ],
            style=Q_STYLE
        ).ask()
        if not choice or choice == "back":
            break
        if choice in actions:
            actions[choice]()


# ─────────────────────────────────────────────────────────────────────────────
#  MENU: PLUGINS
# ─────────────────────────────────────────────────────────────────────────────

def show_plugins_menu():
    while True:
        os.system('cls' if os.name == 'nt' else 'clear')
        draw_header("Davoid Scripting Engine (DSE)", context=ctx)
        if not LOADED_PLUGINS:
            console.print(
                "[yellow][!] No community plugins found in /plugins directory.[/yellow]")
            questionary.press_any_key_to_continue(style=Q_STYLE).ask()
            break
        choices = [Separator("─── LOADED PLUGINS ───────────────────────")]
        for idx, plugin in enumerate(LOADED_PLUGINS):
            choices.append(
                Choice(f"{plugin.name} (by {plugin.author})", value=idx))
        choices.append(Separator("─────────────────────────────────────────"))
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
            console.print(f"[bold red][!] Plugin failed:[/bold red] {e}")
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
        "recon":    show_reconnaissance_menu,
        "assault":  show_assault_menu,
        "infra":    show_infrastructure_menu,
        "intel":    show_intel_reporting_menu,   # merged AI + Purple Team
        "god":      lambda: safe_execute(run_god_mode),
        "sys":      configure_global_context,
        "plugins":  show_plugins_menu,
        "update":   perform_update,
    }

    while True:
        try:
            os.system('cls' if os.name == 'nt' else 'clear')
            draw_header("Master Command Hub", context=ctx)
            check_version()

            phase = questionary.select(
                "Select Mission Phase:",
                choices=[
                    Separator("─── OFFENSIVE OPERATIONS ─────────────────"),
                    Choice("1.  Recon & OSINT",                value="recon"),
                    Choice("2.  Assault & Exploitation",       value="assault"),
                    Choice("3.  C2 & Payload Forge",           value="infra"),
                    Separator("─── INTELLIGENCE ─────────────────────────"),
                    Choice("4.  AI · Reporting · Purple Team", value="intel"),
                    Choice("5.  GOD MODE (Auto-Campaign)",     value="god"),
                    Separator("─── ECOSYSTEM ────────────────────────────"),
                    Choice(f"    Community Plugins ({len(LOADED_PLUGINS)})", value="plugins"),
                    Separator("─── SYSTEM ───────────────────────────────"),
                    Choice("    Configuration & Context",      value="sys"),
                    Choice("    Framework Update",             value="update"),
                    Choice("    Execute Vanish Protocol",      value="exit"),
                ],
                style=Q_STYLE,
                pointer="▶"
            ).ask()

            if not phase:
                continue
            if phase == "exit":
                if questionary.confirm(
                        "Execute Vanish Protocol?",
                        default=True, style=Q_STYLE).ask():
                    execute_vanish_protocol()
            elif phase in actions:
                actions[phase]()

        except KeyboardInterrupt:
            execute_vanish_protocol()
        except Exception as e:
            console.print(f"\n[bold red]Critical error in main loop:[/bold red] {e}")
            input("Press Enter to continue...")


if __name__ == "__main__":
    enforce_security_context()
    main()