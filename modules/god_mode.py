# modules/god_mode.py
import time
import questionary
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from core.ui import draw_header, Q_STYLE
from core.database import db

# Import existing engines
from modules.scanner import NmapEngine
from modules.ai_assist import AIEngine
from modules.msf_engine import MetasploitRPCEngine

console = Console()


class CampaignEngine:
    def __init__(self):
        self.scanner = NmapEngine()
        self.ai = AIEngine()
        self.msf = MetasploitRPCEngine()

    def run(self):
        draw_header("GOD MODE: Autonomous Campaign")

        console.print(
            "[dim]This module links Recon, AI Analysis, and Exploitation into a single chain.[/dim]\n")

        target = questionary.text(
            "Enter Target IP/CIDR to decimate:", style=Q_STYLE).ask()
        if not target:
            return

        # Phase 1: Reconnaissance
        console.print(
            Panel(f"PHASE 1: Target Acquisition ({target})", border_style="bold red"))
        if not self.scanner.check_dependencies():
            return

        console.print("[*] Initiating Stealth SYN & Service Scan...")
        try:
            # Force a stealth/service scan programmatically
            with console.status("[bold cyan]Nmap Engine Active...[/bold cyan]", spinner="bouncingBar"):
                self.scanner.nm.scan(hosts=target, arguments="-sS -sV -T4")
        except Exception as e:
            console.print(f"[bold red][!] Nmap Engine Failure:[/bold red] {e}")
            return

        # NmapEngine handles DB logging natively. We just wait for it.
        hosts = self.scanner.nm.all_hosts()
        if not hosts:
            console.print(
                "[yellow][!] No hosts responded to Phase 1. Aborting campaign.[/yellow]")
            questionary.press_any_key_to_continue(style=Q_STYLE).ask()
            return

        for host in hosts:
            state = self.scanner.nm[host].state()
            console.print(f"[+] Discovered active host: {host} ({state})")
            for proto in self.scanner.nm[host].all_protocols():
                for port in self.scanner.nm[host][proto].keys():
                    name = self.scanner.nm[host][proto][port].get('name', '')
                    version = self.scanner.nm[host][proto][port].get(
                        'version', '')
                    info = f"{port}/{proto} ({name} {version})"
                    db.log("Campaign-Scanner", host, info, "HIGH")

        # Phase 2: AI Cortex Analysis
        console.print()  # Fixed: Print newline separately
        console.print(Panel("PHASE 2: Cortex Threat Analysis",
                      border_style="bold magenta"))

        if not self.ai.check_connection():
            console.print(
                "[yellow][!] Local AI Offline. Skipping cognitive analysis.[/yellow]")
        else:
            prompt = f"I just scanned the target {target}. Here is the raw data from the database. Identify the single most likely path to a remote shell and give me the exact Metasploit module path."
            console.print("[*] Feeding target telemetry to local LLM...")
            self.ai.analyze_mission_database()

        # Phase 3: Weaponization & Exploitation
        console.print()  # Fixed: Print newline separately
        console.print(Panel("PHASE 3: Exploitation Engine",
                      border_style="bold green"))

        execute = questionary.confirm(
            "Do you want to hand off to the MSF-RPC engine for auto-exploitation?", default=True, style=Q_STYLE).ask()

        if execute:
            if not self.msf._check_deps():
                return
            if not self.msf.connect_rpc():
                return

            console.print(
                f"[*] Handoff complete. Launching MSF Engine against {target}...")
            # We call the interactive auto_exploit so the user can confirm the payload
            self.msf.auto_exploit()

            # Show sessions
            console.print("\n[*] Checking for secured shells...")
            self.msf.interact_session()

        console.print("\n[bold green][+] Campaign Terminated.[/bold green]")
        questionary.press_any_key_to_continue(style=Q_STYLE).ask()


def run_god_mode():
    CampaignEngine().run()
