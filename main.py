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
# We wrap these in try/except to prevent the app from crashing if one file is missing
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
    # FIXED: Added the Autopilot Import here
    from modules.autopilot import run_autopilot
except ImportError: 
    # Fallback if autopilot module is missing
    run_autopilot = None

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

# --- 7. MISSION MENUS (Consolidated) ---

def mission_recon():
    """
    Consolidated Reconnaissance Menu.
    Combines Network, Web, DNS, and OSINT into logical flows.
    """
    while True:
        os.system('cls' if os.name == 'nt' else 'clear')
        draw_header("Target Acquisition", context=ctx)
        
        choice = questionary.select(
            "Select Recon Objective:",
            choices=[
                questionary.Separator("--- AUTOMATION ---"),
                Choice("Auto-Pilot (Hunter Killer)", value="auto"),
                
                questionary.Separator("--- TARGET INFRASTRUCTURE ---"),
                Choice("Scan Network (Discovery)", value="net"),
                Choice("Scan Website (Vulnerabilities)", value="web"),
                Choice("Analyze DNS (Domains)", value="dns"),
                
                questionary.Separator("--- TARGET IDENTITY ---"),
                Choice("Profile Person (OSINT)", value="person"),
                Choice("Profile Location (Geo)", value="geo"),
                
                questionary.Separator("--- NAVIGATION ---"),
                Choice("Back", value="back")
            ],
            style=q_style
        ).ask()

        if choice == "auto":
            if run_autopilot: run_autopilot()
            else: console.print("[red]Autopilot module not found.[/red]"); time.sleep(2)
        
        elif choice == "net":
            # Combined Scanner and Sniffer
            sub = questionary.select("Network Tool:", choices=["Active Discovery (Mapper)", "Passive Sniffer (Interceptor)"], style=q_style).ask()
            if "Active" in sub: network_discovery()
            else: 
                e = SnifferEngine()
                e.start()
        
        elif choice == "web":
            # Combined Web Tools
            sub = questionary.select("Web Tool:", choices=["Vulnerability Scanner", "Dork Generator", "Robots.txt Scraper", "Reputation Check"], style=q_style).ask()
            if "Scanner" in sub: web_ghost()
            elif "Dork" in sub: dork_generator()
            elif "Robots" in sub: robots_scraper()
            elif "Reputation" in sub: reputation_check()
            
        elif choice == "dns":
            # Combined DNS Tools
            sub = questionary.select("DNS Mode:", choices=["Active (Brute Force)", "Passive (Logs)"], style=q_style).ask()
            if "Active" in sub: dns_recon()
            else: dns_intel()
            
        elif choice == "person":
            # Combined Person OSINT
            sub = questionary.select("Tracking Mode:", choices=["Username Tracker", "Phone Intelligence"], style=q_style).ask()
            if "Username" in sub: username_tracker()
            else: phone_intel()
            
        elif choice == "geo": geolocate()
        elif choice == "back": break

def mission_assault():
    """
    Consolidated Assault Menu.
    Combines Network Attacks, WiFi, and Cracking.
    """
    while True:
        os.system('cls' if os.name == 'nt' else 'clear')
        draw_header("Direct Action", context=ctx)

        choice = questionary.select(
            "Select Attack Vector:",
            choices=[
                questionary.Separator("--- NETWORK & WIFI ---"),
                Choice("Man-in-the-Middle (MITM)", value="mitm"),
                Choice("DNS Hijacker (Spoofer)", value="dns"),
                Choice("WiFi Warfare Suite", value="wifi"),
                
                questionary.Separator("--- SOCIAL & CREDENTIALS ---"),
                Choice("Website Cloner (Phishing)", value="clone"),
                Choice("Hash Cracker", value="crack"),
                
                questionary.Separator("--- NAVIGATION ---"),
                Choice("Back", value="back")
            ],
            style=q_style
        ).ask()

        if choice == "mitm": 
            try:
                e = MITMEngine()
                e.run()
            except Exception as e: console.print(f"[red]{e}[/red]")
        elif choice == "dns": start_dns_spoof()
        elif choice == "wifi": run_wifi_suite()
        elif choice == "clone": clone_site()
        elif choice == "crack": 
            h = console.input("[bold yellow]Hash to crack: [/bold yellow]")
            if h: crack_hash(h)
        elif choice == "back": break

def mission_infra():
    """
    Consolidated Infrastructure Menu.
    Combines Payloads, C2, and Persistence.
    """
    while True:
        os.system('cls' if os.name == 'nt' else 'clear')
        draw_header("Infrastructure & C2", context=ctx)

        choice = questionary.select(
            "Select Operation:",
            choices=[
                Choice("Generate Payload", value="forge"),
                Choice("Encrypt Payload", value="crypt"),
                Choice("Install Persistence", value="persist"),
                Choice("Launch C2 Server (Ghost Hub)", value="c2"),
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
        elif choice == "c2": run_ghost_hub()
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
                    questionary.Separator("--- OPERATIONAL ---"),
                    Choice("1. Reconnaissance & Intel", value="recon"),
                    Choice("2. Assault & Exploitation", value="assault"),
                    Choice("3. Infrastructure & C2", value="infra"),
                    
                    questionary.Separator("--- INTELLIGENCE ---"),
                    Choice("4. AI Cortex & Reporting", value="ai"),
                    
                    questionary.Separator("--- SYSTEM ---"),
                    Choice("Settings & Audit", value="sys"),
                    Choice("Update Framework", value="update"),
                    Choice("VANISH (Exit)", value="exit")
                ],
                style=q_style,
                use_indicator=True,
                pointer=">"
            ).ask()
            
            if category == "recon": mission_recon()
            elif category == "assault": mission_assault()
            elif category == "infra": mission_infra()
            elif category == "ai":
                sub = questionary.select("AI Operations:", choices=["Launch AI Assistant", "Generate Threat Map"], style=q_style).ask()
                if "Assistant" in sub: run_ai_console()
                else: generate_report()
            elif category == "sys":
                sub = questionary.select("System Tools:", choices=["Configuration", "Security Audit"], style=q_style).ask()
                if "Config" in sub: configure_context()
                else: 
                    if run_auditor: run_auditor(); console.input("\n[dim]Press Enter...[/dim]")
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