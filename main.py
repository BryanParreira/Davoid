"""
main.py — Davoid Red Team Framework (Enterprise Edition)
Laser-focused on Network Exploitation, Active Directory, and Autonomous AI.
"""

import sys
import os
import warnings
import shutil
import time
import importlib.util
from typing import Callable, Optional

# Suppress noisy warnings safely before third-party imports
warnings.filterwarnings("ignore", message=".*OpenSSL 1.1.1+.*")
warnings.filterwarnings("ignore", category=UserWarning, module='urllib3')
warnings.filterwarnings("ignore", category=UserWarning, module='scapy')

import questionary
from questionary import Choice, Separator
from rich.console import Console
from rich.table import Table

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
if SCRIPT_DIR not in sys.path:
    sys.path.insert(0, SCRIPT_DIR)

# Enforce secure directories
for directory in ["logs", "payloads", "plugins", "reports"]:
    os.makedirs(os.path.join(SCRIPT_DIR, directory), exist_ok=True)

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

def load_module(module_path: str, attr: str) -> Optional[Callable]:
    try:
        mod = importlib.import_module(module_path)
        return getattr(mod, attr)
    except Exception:
        return None

# ── Core Enterprise Modules ──
network_discovery  = load_module("modules.scanner", "network_discovery")
run_msf            = load_module("modules.msf_engine", "run_msf")
run_ad_ops         = load_module("modules.ad_ops", "run_ad_ops")
crack_hash         = load_module("modules.bruteforce", "crack_hash")
run_ghost_hub      = load_module("modules.ghost_hub", "run_ghost_hub")
run_ai_console     = load_module("modules.ai_assist", "run_ai_console")
generate_report    = load_module("modules.reporter", "generate_report")

# ── Newly Linked Modules ──
run_god_mode       = load_module("modules.god_mode", "run_god_mode")
run_cloud_ops      = load_module("modules.cloud_ops", "run_cloud_ops")
run_auditor        = load_module("modules.auditor", "run_auditor")
run_cred_tester    = load_module("modules.cred_tester", "run_cred_tester")
encrypt_payload    = load_module("modules.crypt_keeper", "encrypt_payload")
run_looter         = load_module("modules.looter", "run_looter")
generate_shell     = load_module("modules.payloads", "generate_shell")
run_purple_team    = load_module("modules.purple_team", "run_purple_team")
run_sniffer        = load_module("modules.sniff", "run_sniffer")
web_ghost          = load_module("modules.web_recon", "web_ghost")

# Recon sub-menus
dns_recon          = load_module("modules.recon", "dns_recon")
shodan_intel       = load_module("modules.recon", "shodan_intel")
passive_intel_menu = load_module("modules.recon", "passive_intel_menu")
person_osint_menu  = load_module("modules.recon", "person_osint_menu")

# ─────────────────────────────────────────────────────────────────────────────
#  SYSTEM HELPERS
# ─────────────────────────────────────────────────────────────────────────────
def detect_network_environment() -> bool:
    try:
        from scapy.all import conf, get_if_addr
        
        # 1. Get Interface
        iface = str(conf.iface)
        ctx.set("INTERFACE", iface)
        
        # 2. Get Local IP
        local_ip = get_if_addr(iface)
        if local_ip and local_ip != "0.0.0.0":
            ctx.set("LHOST", local_ip)
            
        # 3. Get Default Gateway
        try:
            gw = conf.route.route("0.0.0.0")[2]
            if gw and gw != "0.0.0.0":
                ctx.set("GATEWAY", gw)
            else:
                ctx.set("GATEWAY", "Unknown")
        except Exception:
            ctx.set("GATEWAY", "Unknown")
            
        return True
    except Exception:
        ctx.set("GATEWAY", "Unknown")
        return False

def execute_vanish_protocol() -> None:
    console.print("\n[bold red]INITIATING FORENSIC VANISH SEQUENCE...[/bold red]")
    try:
        if hasattr(db, 'delete_all'):
            db.delete_all()
    except Exception: pass
    
    for target_dir in ["payloads", "__pycache__", "logs"]:
        path = os.path.join(SCRIPT_DIR, target_dir)
        if os.path.exists(path):
            shutil.rmtree(path, ignore_errors=True)
            
    console.print("[bold green][*] Forensic evidence cleared. Ghost out.[/bold green]")
    sys.exit(0)

def safe_execute(func: Optional[Callable], *args, **kwargs) -> None:
    if func is None:
        console.print("\n[bold red][!] Module offline or missing dependencies.[/bold red]")
        time.sleep(1.5)
        return
    try:
        func(*args, **kwargs)
    except KeyboardInterrupt:
        console.print("\n[yellow][*] Task interrupted by operator.[/yellow]")
    except Exception as e:
        console.print(f"\n[bold red][!] Runtime Exception in module:[/bold red]\n{e}")
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
                Choice("Set Variable", value="set"),
                Choice("Rotate Identity (Refresh Network)", value="rotate"),
                Choice("Back", value="back"),
            ],
            style=Q_STYLE
        ).ask()
        
        if not action or action == "back": break
        elif action == "set":
            key = questionary.text("Variable name (blank = cancel):", style=Q_STYLE).ask()
            if key:
                val = questionary.text(f"Value for {key}:", style=Q_STYLE).ask()
                ctx.set(key, val)
        elif action == "rotate":
            detect_network_environment()

# ─────────────────────────────────────────────────────────────────────────────
#  MENU SYSTEMS
# ─────────────────────────────────────────────────────────────────────────────
def show_reconnaissance_menu():
    actions = {
        "nmap":    lambda: safe_execute(network_discovery),
        "dns":     lambda: safe_execute(dns_recon),
        "shodan":  lambda: safe_execute(shodan_intel),
        "web":     lambda: safe_execute(web_ghost),
        "sniff":   lambda: safe_execute(run_sniffer),
        "cloud":   lambda: safe_execute(run_cloud_ops),
        "passive": lambda: safe_execute(passive_intel_menu),
        "osint":   lambda: safe_execute(person_osint_menu),
    }
    while True:
        os.system('cls' if os.name == 'nt' else 'clear')
        draw_header("Target Acquisition & Intelligence", context=ctx)
        choice = questionary.select(
            "Select Recon Module:",
            choices=[
                Separator("─── ACTIVE SCANNING ───────────────────────"),
                Choice("Network Scanner (Nmap)", value="nmap"),
                Choice("Web Infrastructure Recon (Web Ghost)", value="web"),
                Choice("DNS & Subdomain Mapping", value="dns"),
                Choice("Live WLAN Sniffer", value="sniff"),
                Separator("─── CLOUD & OSINT ─────────────────────────"),
                Choice("Cloud & Container Warfare", value="cloud"),
                Choice("Attack Surface (Shodan/InternetDB)", value="shodan"),
                Choice("Passive Archive Intel (Wayback/Dorks)", value="passive"),
                Choice("Person OSINT (Username/Phone/Geo)", value="osint"),
                Separator("─── NAVIGATION ────────────────────────────"),
                Choice("Return to Main Menu", value="back"),
            ],
            style=Q_STYLE
        ).ask()
        if not choice or choice == "back": break
        if choice in actions: actions[choice]()

def show_assault_menu():
    actions = {
        "god":     lambda: safe_execute(run_god_mode),
        "msf":     lambda: safe_execute(run_msf),
        "ad":      lambda: safe_execute(run_ad_ops),
        "crack":   lambda: safe_execute(crack_hash),
        "cred":    lambda: safe_execute(run_cred_tester),
        "payload": lambda: safe_execute(generate_shell),
        "crypt":   lambda: safe_execute(encrypt_payload),
        "loot":    lambda: safe_execute(run_looter),
    }
    while True:
        os.system('cls' if os.name == 'nt' else 'clear')
        draw_header("Direct Action & Exploitation", context=ctx)
        choice = questionary.select(
            "Select Assault Vector:",
            choices=[
                Separator("─── AUTONOMOUS ────────────────────────────"),
                Choice("GOD MODE (Auto Campaign Engine)", value="god"),
                Separator("─── EXPLOITATION ──────────────────────────"),
                Choice("Metasploit Framework (MSF-RPC)", value="msf"),
                Choice("Active Directory Ops", value="ad"),
                Separator("─── WEAPONIZATION & POST-EXPLOIT ──────────"),
                Choice("Payload Forge (Shell Generator)", value="payload"),
                Choice("Crypt-Keeper (Payload Obfuscation)", value="crypt"),
                Choice("PrivEsc Looter", value="loot"),
                Separator("─── CREDENTIAL ATTACKS ───────────────────"),
                Choice("Hash Cracker", value="crack"),
                Choice("Credential Re-Use Tester", value="cred"),
                Separator("─── NAVIGATION ───────────────────────────"),
                Choice("Return to Main Menu", value="back"),
            ],
            style=Q_STYLE
        ).ask()
        if not choice or choice == "back": break
        if choice in actions: actions[choice]()

def main():
    if len(sys.argv) > 1 and sys.argv[1] == "--update":
        perform_update()
        sys.exit(0)

    load_config()
    detect_network_environment()

    actions = {
        "recon":   show_reconnaissance_menu,
        "assault": show_assault_menu,
        "ai":      lambda: safe_execute(run_ai_console),
        "c2":      lambda: safe_execute(run_ghost_hub),
        "report":  lambda: safe_execute(generate_report),
        "purple":  lambda: safe_execute(run_purple_team),
        "audit":   lambda: safe_execute(run_auditor),
        "sys":     configure_global_context,
        "update":  perform_update,
    }

    while True:
        try:
            os.system('cls' if os.name == 'nt' else 'clear')
            draw_header("Enterprise Master Hub", context=ctx)
            
            phase = questionary.select(
                "Select Operation Phase:",
                choices=[
                    Separator("─── OFFENSIVE OPERATIONS ─────────────────"),
                    Choice("1. Reconnaissance & Target Acquisition", value="recon"),
                    Choice("2. Assault, Exploitation & Weapons", value="assault"),
                    Choice("3. Command & Control (C2 GhostHub)", value="c2"),
                    Separator("─── INTELLIGENCE & BLUE TEAM ─────────────"),
                    Choice("4. LangChain AI Agent Cortex", value="ai"),
                    Choice("5. Purple Team MITRE ATT&CK Mapper", value="purple"),
                    Choice("6. Generate Mission HTML Report", value="report"),
                    Separator("─── SYSTEM ───────────────────────────────"),
                    Choice("   Setup Auditor & Posture Scout", value="audit"),
                    Choice("   Context Configuration", value="sys"),
                    Choice("   Framework Update", value="update"),
                    Choice("   Execute Vanish Protocol", value="exit"),
                ],
                style=Q_STYLE,
                pointer="▶"
            ).ask()

            if not phase: continue
            if phase == "exit":
                if questionary.confirm("Execute Vanish Protocol?", default=True, style=Q_STYLE).ask():
                    execute_vanish_protocol()
            elif phase in actions:
                actions[phase]()
        except KeyboardInterrupt:
            execute_vanish_protocol()
        except Exception as e:
            console.print(f"\n[bold red]Critical system failure:[/bold red]\n{e}")
            input("Press Enter to continue...")

if __name__ == "__main__":
    main()