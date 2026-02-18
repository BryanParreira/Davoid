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

# --- 1. SYSTEM SUPPRESSION LAYER ---
warnings.filterwarnings("ignore", message=".*OpenSSL 1.1.1+.*")
warnings.filterwarnings("ignore", category=UserWarning, module='urllib3')
warnings.filterwarnings("ignore", category=UserWarning, module='scapy')

# --- 2. ENVIRONMENT SETUP ---
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
if SCRIPT_DIR not in sys.path:
    sys.path.append(SCRIPT_DIR)

BASE_DIR = "/opt/davoid"
if os.path.exists(BASE_DIR) and BASE_DIR not in sys.path:
    sys.path.append(BASE_DIR)

# --- 3. CORE & UI LOGIC ---
try:
    from core.ui import draw_header
    from core.updater import check_version, perform_update
    from core.context import ctx
    try:
        from core.config import load_config
    except ImportError:
        load_config = lambda: None
except ImportError as e:
    print(f"Core components missing: {e}")
    sys.exit(1)

# --- 4. MODULE IMPORTS ---
try:
    from modules.auditor import run_auditor
except ImportError: run_auditor = None

try:
    from modules.scanner import network_discovery
    from modules.sniff import SnifferEngine
    from modules.recon import dns_recon
    from modules.web_recon import web_ghost
    from modules.osint_pro import (username_tracker, phone_intel, geolocate,
                                   dork_generator, robots_scraper, reputation_check, dns_intel)
except ImportError: pass

try:
    from modules.spoof import MITMEngine
    from modules.dns_spoofer import start_dns_spoof
    from modules.cloner import clone_site
    from modules.ghost_hub import run_ghost_hub
    from modules.wifi_ops import run_wifi_suite
    from modules.payloads import generate_shell
    from modules.crypt_keeper import encrypt_payload
    from modules.bruteforce import crack_hash
    from modules.persistence import PersistenceEngine
    # NEW AUTOPILOT IMPORT
    from modules.autopilot import run_autopilot
except ImportError: pass

try:
    from modules.ai_assist import run_ai_console
    from modules.reporter import generate_report
except ImportError: pass

console = Console()

# --- 5. NAVIGATION STYLE ---
q_style = Style([
    ('qmark', 'fg:#ff0000 bold'),
    ('question', 'fg:#ffffff bold'),
    ('answer', 'fg:#ff0000 bold'),
    ('pointer', 'fg:#ff0000 bold'),
    ('highlighted', 'fg:#ff0000 bold'),
    ('selected', 'fg:#cc5454'),
    ('separator', 'fg:#666666'),
    ('instruction', 'fg:#666666 italic')
])

# --- 6. SUPPORT FUNCTIONS ---

def auto_discovery():
    """Automatic Interface and Network Detection."""
    try:
        from scapy.all import conf, get_if_addr
        active_iface = str(conf.iface)
        local_ip = get_if_addr(active_iface)
        try:
            gw_ip = conf.route.route("0.0.0.0")[2]
        except:
            gw_ip = "Unknown"
        
        ctx.set("INTERFACE", active_iface)
        ctx.set("LHOST", local_ip)
        ctx.vars["GATEWAY"] = gw_ip
        return True
    except:
        return False

def vanish_sequence():
    """Forensic Cleanup."""
    console.print("\n[bold red]INITIATING VANISH SEQUENCE...[/bold red]")
    targets = ["logs", "clones", "payloads", "__pycache__"]
    for t in targets:
        path = os.path.join(os.getcwd(), t)
        if os.path.exists(path):
            try:
                shutil.rmtree(path)
                console.print(f"[dim][-] Wiped: {path}[/dim]")
            except Exception as e:
                console.print(f"[red][!] Failed to wipe {t}: {e}[/red]")
    console.print("[bold green][*] Evidence cleared. Ghost out.[/bold green]")
    sys.exit(0)

def configure_context():
    """Global Settings Menu."""
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
                Choice("Set Variable", value="s"),
                Choice("Rotate Identity (MAC)", value="m"),
                Choice("Back", value="b")
            ],
            style=q_style
        ).ask()

        if action == 's':
            key = questionary.text("Variable Name:", style=q_style).ask()
            if key:
                val = questionary.text(f"Value for {key}:", style=q_style).ask()
                ctx.set(key, val)
        elif action == 'm':
            iface = ctx.get("INTERFACE") or "eth0"
            console.print(f"[dim][*] Rotating Identity on {iface}...[/dim]")
            try:
                if shutil.which("macchanger"):
                    subprocess.run(f"ifconfig {iface} down && macchanger -r {iface} && ifconfig {iface} up", shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    console.print(f"[bold green][+] Identity Randomized[/bold green]")
                else:
                    import random
                    mac = "02:00:00:%02x:%02x:%02x" % (random.randint(0, 255), random.randint(0, 255), random.randint(0, 255))
                    subprocess.run(f"ip link set dev {iface} address {mac}", shell=True, stderr=subprocess.DEVNULL)
                    console.print(f"[bold green][+] Identity Randomized (Manual)[/bold green]")
                time.sleep(1)
                auto_discovery()
            except:
                console.print("[yellow]Rotation failed.[/yellow]")
        else:
            break

# --- 7. MISSION MENUS ---

def menu_recon():
    """Streamlined Reconnaissance Menu"""
    while True:
        os.system('cls' if os.name == 'nt' else 'clear')
        draw_header("Reconnaissance", context=ctx)
        
        choice = questionary.select(
            "Select Target Type:",
            choices=[
                questionary.Separator("--- AUTOMATION ---"),
                Choice("AUTO-PILOT (Hunter Killer Mode)", value="auto"),
                
                questionary.Separator("--- NETWORK & INFRASTRUCTURE ---"),
                Choice("Network Mapper (Active Discovery)", value="net"),
                Choice("Web Vulnerability Scanner", value="web"),
                Choice("DNS Intelligence (Active & Passive)", value="dns"),
                Choice("Robots.txt & Reputation", value="meta"),
                
                questionary.Separator("--- PERSON & IDENTITY ---"),
                Choice("Username & Social Media", value="user"),
                Choice("Phone Number Intelligence", value="phone"),
                Choice("Geo-Location Tracking", value="geo"),
                
                questionary.Separator("--- NAVIGATION ---"),
                Choice("Back", value="back")
            ],
            style=q_style
        ).ask()

        if choice == "auto": run_autopilot()
        elif choice == "net": network_discovery()
        elif choice == "web": 
            sub = questionary.select("Web Module:", choices=["Vulnerability Scan", "Google Dorks"], style=q_style).ask()
            if sub == "Vulnerability Scan": web_ghost()
            else: dork_generator()
        elif choice == "dns":
            sub = questionary.select("DNS Mode:", choices=["Active Recon (Brute Force)", "Passive Intel (Logs)"], style=q_style).ask()
            if "Active" in sub: dns_recon()
            else: dns_intel()
        elif choice == "meta":
            sub = questionary.select("Metadata Tool:", choices=["Robots.txt", "Reputation Check"], style=q_style).ask()
            if "Robots" in sub: robots_scraper()
            else: reputation_check()
        elif choice == "user": username_tracker()
        elif choice == "phone": phone_intel()
        elif choice == "geo": geolocate()
        elif choice == "back": break

def menu_interception():
    """Traffic Operations Menu"""
    while True:
        os.system('cls' if os.name == 'nt' else 'clear')
        draw_header("Traffic Interception", context=ctx)

        choice = questionary.select(
            "Select Operation:",
            choices=[
                Choice("Live Traffic Sniffer", value="sniff"),
                Choice("Man-in-the-Middle (MITM)", value="mitm"),
                Choice("DNS Hijacker (Spoofer)", value="dns"),
                Choice("Back", value="back")
            ],
            style=q_style
        ).ask()

        if choice == "sniff": 
            e = SnifferEngine()
            e.start()
        elif choice == "mitm": 
            try:
                e = MITMEngine()
                e.run()
            except Exception as e: console.print(f"[red]{e}[/red]")
        elif choice == "dns": start_dns_spoof()
        elif choice == "back": break

def menu_weaponization():
    """Payloads & Persistence Menu"""
    while True:
        os.system('cls' if os.name == 'nt' else 'clear')
        draw_header("Weaponization", context=ctx)

        choice = questionary.select(
            "Select Tool:",
            choices=[
                Choice("Payload Builder (Shell Forge)", value="forge"),
                Choice("Payload Encryptor (Crypt-Keeper)", value="crypt"),
                Choice("Persistence Installer", value="persist"),
                Choice("Back", value="back")
            ],
            style=q_style
        ).ask()

        if choice == "forge": generate_shell()
        elif choice == "crypt": 
            p = console.input("[bold yellow]Path to payload: [/bold yellow]")
            if p: encrypt_payload(p)
        elif choice == "persist": 
            p = console.input("[bold yellow]Target file path: [/bold yellow]")
            if p: 
                e = PersistenceEngine(p)
                e.run()
        elif choice == "back": break

def menu_assault():
    """Direct Action Menu"""
    while True:
        os.system('cls' if os.name == 'nt' else 'clear')
        draw_header("Assault Operations", context=ctx)

        choice = questionary.select(
            "Select Attack Vector:",
            choices=[
                Choice("WiFi Warfare Suite", value="wifi"),
                Choice("Website Cloner (Phishing)", value="clone"),
                Choice("Hash Cracker", value="crack"),
                Choice("Back", value="back")
            ],
            style=q_style
        ).ask()

        if choice == "wifi": run_wifi_suite()
        elif choice == "clone": clone_site()
        elif choice == "crack": 
            h = console.input("[bold yellow]Hash to crack: [/bold yellow]")
            if h: crack_hash(h)
        elif choice == "back": break

# --- 8. MASTER LOOP ---

def main():
    if len(sys.argv) > 1 and sys.argv[1].lower() == "--update":
        perform_update()
        sys.exit(0)
    
    auto_discovery()
    config = load_config()
    if config:
        sys_conf = config.get('system', {})
        if sys_conf.get('default_interface', 'auto') != 'auto':
            ctx.set("INTERFACE", sys_conf['default_interface'])
    
    try:
        while True:
            os.system('cls' if os.name == 'nt' else 'clear')
            draw_header("Master Command Hub", context=ctx)
            check_version()
            
            category = questionary.select(
                "Mission Phase:",
                choices=[
                    questionary.Separator("--- PHASE 1: GATHER ---"),
                    Choice("1. Reconnaissance", value="recon"),
                    
                    questionary.Separator("--- PHASE 2: ENGAGE ---"),
                    Choice("2. Interception", value="intercept"),
                    Choice("3. Weaponization", value="weapon"),
                    Choice("4. Assault", value="assault"),
                    
                    questionary.Separator("--- PHASE 3: CONTROL & ANALYZE ---"),
                    Choice("5. Command & Control (C2)", value="c2"),
                    Choice("6. AI Analysis & Reporting", value="ai"),
                    
                    questionary.Separator("--- SYSTEM ---"),
                    Choice("Settings", value="config"),
                    Choice("Auditor", value="audit"),
                    Choice("Update", value="update"),
                    Choice("VANISH", value="exit")
                ],
                style=q_style,
                use_indicator=True,
                pointer=">"
            ).ask()
            
            if category == "recon": menu_recon()
            elif category == "intercept": menu_interception()
            elif category == "weapon": menu_weaponization()
            elif category == "assault": menu_assault()
            elif category == "c2": run_ghost_hub()
            elif category == "ai":
                sub = questionary.select("AI Operations:", choices=["Launch AI Cortex", "Generate Threat Map"], style=q_style).ask()
                if "Cortex" in sub: run_ai_console()
                else: generate_report()
            elif category == "config": configure_context()
            elif category == "audit":
                if run_auditor: 
                    run_auditor()
                    console.input("\n[dim]Press Enter...[/dim]")
            elif category == "update": perform_update()
            elif category == "exit": 
                if questionary.confirm("Execute Vanish Sequence?", default=True, style=q_style).ask():
                    vanish_sequence()
            
    except KeyboardInterrupt:
        vanish_sequence()
    except Exception as e:
        console.print(f"\n[bold red]CRITICAL FAILURE:[/bold red] {e}")
        console.input("\nPress Enter to restart...")

if __name__ == "__main__":
    main()