"""
modules/god_mode.py — Autonomous Campaign Engine
Orchestrates Recon, AI Threat Analysis, and Metasploit Exploitation in a seamless chain.
"""

import time
import threading
import questionary
from rich.console import Console
from rich.panel import Panel
from core.ui import draw_header, Q_STYLE
from core.database import db
from core.context import ctx

# Import existing engines
from modules.scanner import NmapEngine
from modules.ai_assist import AutonomousCortex
from modules.msf_engine import MetasploitRPCEngine

console = Console()

class CampaignEngine:
    def __init__(self):
        self.scanner = NmapEngine()
        self.ai = AutonomousCortex()
        self.msf = MetasploitRPCEngine()

    def _phase_recon(self, target: str) -> str | None:
        console.print(Panel(f"PHASE 1: Target Acquisition ({target})", border_style="bold red"))
        if not self.scanner.check_dependencies(): return None

        console.print("[*] Initiating Full Audit Scan (OS, Services, Scripts)...")
        try:
            with console.status("[bold cyan]Nmap Engine Active (Full Audit)...[/bold cyan]", spinner="bouncingBar"):
                self.scanner.nm.scan(hosts=target, arguments="-sS -sV -O -sC -T4")
        except Exception as e:
            console.print(f"[bold red][!] Nmap Engine Failure:[/bold red] {e}")
            return None

        hosts = self.scanner.nm.all_hosts()
        if not hosts:
            console.print("[yellow][!] No hosts responded. Aborting campaign.[/yellow]")
            return None

        scan_context = ""
        for host in hosts:
            state = self.scanner.nm[host].state()
            os_match = self.scanner.nm[host].get('osmatch', [{'name': 'Unknown'}])[0]['name']
            
            console.print(f"[+] Discovered active host: {host} ({state})")
            console.print(f"[*] Detected OS: [bold cyan]{os_match}[/bold cyan]")

            scan_context += f"\nTarget Host: {host}\nOS: {os_match}\nOpen Ports:\n"

            for proto in self.scanner.nm[host].all_protocols():
                for port in self.scanner.nm[host][proto].keys():
                    pd = self.scanner.nm[host][proto][port]
                    info = f"Port {port}/{proto} - {pd.get('name', '')} {pd.get('product', '')} {pd.get('version', '')}"
                    db.log("Campaign-Scanner", host, info, "HIGH")
                    scan_context += f"- {info}\n"

        return scan_context

    def _phase_ai(self, target: str, scan_context: str) -> bool:
        console.print(Panel("PHASE 2: Cortex Threat Analysis", border_style="bold magenta"))

        if not self.ai.check_connection():
            console.print("[yellow][!] Local AI Offline. Skipping cognitive analysis → Phase 3.[/yellow]")
            return False

        console.print(f"\n[*] Feeding telemetry to [cyan]{self.ai.model_name}[/cyan]...")

        # Overriding standard AI chat to force strict JSON-like output for the Metasploit handoff
        system_override = (
            "You are an elite Metasploit expert. Map the provided Nmap scan results to exact Metasploit module paths. "
            "Output ONLY a bulleted list of ports and modules. No explanations."
        )
        user_prompt = f"Analyze these scan results and map the exploits:\n{scan_context}"

        try:
            self.ai.chat(user_prompt) # The AI will print its thought process and suggested modules
            return True
        except Exception as e:
            console.print(f"[dim red][!] AI error: {e}[/dim red]")
            return False

    def _phase_exploit(self, target: str):
        console.print(Panel("PHASE 3: Exploitation Engine", border_style="bold green"))

        execute = questionary.confirm("Hand off to MSF-RPC engine for auto-exploitation?", default=True, style=Q_STYLE).ask()
        if not execute:
            console.print("[dim]Phase 3 skipped by operator.[/dim]")
            return

        if not self.msf._check_deps() or not self.msf.connect_rpc():
            return

        console.print(f"[*] Handoff complete. Launching MSF Engine against {target}...")
        self.msf.auto_exploit()
        console.print("\n[*] Checking for secured shells...")
        self.msf.interact_session()

    def run(self):
        draw_header("GOD MODE: Autonomous Campaign")
        target = questionary.text("Enter Target IP/CIDR:", style=Q_STYLE).ask()
        if not target: return
        ctx.set("RHOST", target)

        scan_context = self._phase_recon(target)
        if not scan_context: return

        ai_ok = self._phase_ai(target, scan_context)
        self._phase_exploit(target)

        console.print("\n[bold green][+] Campaign Terminated.[/bold green]")
        questionary.press_any_key_to_continue(style=Q_STYLE).ask()

def run_god_mode():
    CampaignEngine().run()