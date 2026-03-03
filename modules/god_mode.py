# modules/god_mode.py
import time
import questionary
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from core.ui import draw_header, Q_STYLE
from core.database import db
from core.context import ctx

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

        # Auto-set the global context so MSF knows the target in Phase 3
        ctx.set("RHOST", target)

        # Phase 1: Reconnaissance
        console.print(
            Panel(f"PHASE 1: Target Acquisition ({target})", border_style="bold red"))
        if not self.scanner.check_dependencies():
            return

        console.print(
            "[*] Initiating Full Audit Scan (OS, Services, Scripts)...")
        try:
            # Force a full audit scan for maximum OS and Service intel
            with console.status("[bold cyan]Nmap Engine Active (Full Audit)...[/bold cyan]", spinner="bouncingBar"):
                self.scanner.nm.scan(
                    hosts=target, arguments="-sS -sV -O -sC -T4")
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

        # Capture the exact scan results cleanly for the AI
        scan_context = ""

        for host in hosts:
            state = self.scanner.nm[host].state()

            # Extract precise OS Information
            os_match = "Unknown OS"
            if self.scanner.nm[host].get('osmatch') and len(self.scanner.nm[host]['osmatch']) > 0:
                os_match = self.scanner.nm[host]['osmatch'][0]['name']

            console.print(f"[+] Discovered active host: {host} ({state})")
            console.print(
                f"[*] Detected OS: [bold cyan]{os_match}[/bold cyan]")

            scan_context += f"\nTarget Host: {host}\nDetected Operating System: {os_match}\nOpen Ports & Services:\n"

            for proto in self.scanner.nm[host].all_protocols():
                for port in self.scanner.nm[host][proto].keys():
                    pd = self.scanner.nm[host][proto][port]

                    # Get deep service details
                    name = pd.get('name', '')
                    product = pd.get('product', '')
                    version = pd.get('version', '')
                    extrainfo = pd.get('extrainfo', '')

                    # Combine product, version, and extra info for rich context
                    full_service_info = f"{product} {version} {extrainfo}".strip(
                    )
                    if not full_service_info:
                        full_service_info = name  # Fallback

                    info = f"Port {port}/{proto} - Service: {name} - Details: {full_service_info}"

                    db.log("Campaign-Scanner", host, info, "HIGH")
                    scan_context += f"- {info}\n"

        # Phase 2: AI Cortex Analysis
        console.print()
        console.print(Panel("PHASE 2: Cortex Threat Analysis",
                      border_style="bold magenta"))

        if not self.ai.check_connection():
            console.print(
                "[yellow][!] Local AI Offline. Skipping cognitive analysis.[/yellow]")
        else:
            models = self.ai.list_models()

            if not models:
                console.print(
                    "[red][!] Ollama is online, but no models are installed locally.[/red]")
                console.print(
                    "[white]Please run: 'ollama pull llama3' or 'ollama pull mistral' in another terminal.[/white]")
            else:
                selected_model = questionary.select(
                    "Select AI Model for Threat Analysis:",
                    choices=models,
                    style=Q_STYLE
                ).ask()

                if selected_model:
                    self.ai.model = selected_model
                    console.print(
                        f"\n[*] Feeding specific target telemetry to [cyan]{self.ai.model}[/cyan]...")

                    # Strict system override enforcing OS-awareness
                    system_override = (
                        "You are an elite Red Team Exploit Mapper. Your ONLY job is to look at the provided Nmap scan results "
                        "and list the exact Metasploit module paths (e.g., exploit/windows/smb/ms17_010_eternalblue or exploit/linux/http/...) "
                        "that correspond to the open ports, services, AND the exact Operating System detected. "
                        "Do NOT give generic advice. Do NOT write paragraphs. "
                        "Give me a strict bulleted list of the open ports and their most likely Metasploit modules. "
                        "CRITICAL: If the OS is Linux, DO NOT suggest Windows exploits. If it is Windows, DO NOT suggest Linux exploits."
                    )

                    user_prompt = f"Analyze these specific scan results for {target} and tell me exactly which Metasploit modules to run based on the OS and versions:\n{scan_context}"

                    self.ai.chat(user_prompt, override_prompt=system_override)

        # Phase 3: Weaponization & Exploitation
        console.print()
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
