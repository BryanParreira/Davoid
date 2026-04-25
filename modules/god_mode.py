"""
modules/god_mode.py — Autonomous Campaign Engine
FIXED:
  - _phase_ai() now correctly passes system_override to self.ai.chat()
    (previously built the string but never used it)
  - Added Phase 4: auto-generates HTML mission report after campaign
  - Graceful AI timeout with configurable value from ctx
"""

import time
import threading
import questionary
from rich.console import Console
from rich.panel import Panel
from core.ui import draw_header, Q_STYLE
from core.database import db
from core.context import ctx

from modules.scanner import NmapEngine
from modules.ai_assist import AutonomousCortex
from modules.msf_engine import MetasploitRPCEngine

console = Console()


def _get_ai_timeout() -> int:
    try:
        val = ctx.get("AI_TIMEOUT")
        if val:
            return int(val)
    except Exception:
        pass
    return 60


class CampaignEngine:
    def __init__(self):
        self.scanner = NmapEngine()
        self.ai = AutonomousCortex()
        self.msf = MetasploitRPCEngine()

    # ── Phase 1: Recon ────────────────────────────────────────────────────────

    def _phase_recon(self, target: str) -> str | None:
        console.print(Panel(
            f"PHASE 1: Target Acquisition — {target}",
            border_style="bold red"
        ))

        if not self.scanner.check_dependencies():
            return None

        console.print(
            "[*] Initiating full audit scan (OS, Services, Scripts)...")
        try:
            with console.status(
                "[bold cyan]Nmap Engine Active (Full Audit)...[/bold cyan]",
                spinner="bouncingBar"
            ):
                self.scanner.nm.scan(
                    hosts=target, arguments="-sS -sV -O -sC -T4")
        except Exception as e:
            console.print(f"[bold red][!] Nmap Engine Failure:[/bold red] {e}")
            return None

        hosts = self.scanner.nm.all_hosts()
        if not hosts:
            console.print(
                "[yellow][!] No hosts responded. Aborting campaign.[/yellow]")
            return None

        scan_context = ""
        for host in hosts:
            state = self.scanner.nm[host].state()
            os_match = "Unknown"
            if self.scanner.nm[host].get("osmatch"):
                os_match = self.scanner.nm[host]["osmatch"][0]["name"]

            console.print(
                f"[bold green][+] Host:[/bold green] {host} ({state})")
            console.print(f"[*] OS: [bold cyan]{os_match}[/bold cyan]")

            scan_context += f"\nTarget: {host}\nOS: {os_match}\nOpen Ports:\n"

            for proto in self.scanner.nm[host].all_protocols():
                for port in sorted(self.scanner.nm[host][proto].keys()):
                    pd = self.scanner.nm[host][proto][port]
                    info = (f"Port {port}/{proto} - "
                            f"{pd.get('name','')} "
                            f"{pd.get('product','')} "
                            f"{pd.get('version','')}")
                    db.log("Campaign-Scanner", host, info, "HIGH")
                    scan_context += f"  - {info}\n"

        return scan_context

    # ── Phase 2: AI Analysis ──────────────────────────────────────────────────

    def _phase_ai(self, target: str, scan_context: str) -> bool:
        console.print(Panel("PHASE 2: Cortex Threat Analysis",
                      border_style="bold magenta"))

        ai_timeout = _get_ai_timeout()

        if not self.ai.check_connection():
            console.print(
                "[yellow][!] AI Offline. Skipping Phase 2 → Phase 3.[/yellow]")
            return False

        console.print(
            f"[*] Feeding scan telemetry to [cyan]{self.ai.model_name}[/cyan]...")

        # ── FIXED: system_override is now PASSED to chat() ──────────────────
        system_override = (
            "You are an elite Metasploit exploitation expert. "
            "Analyze the Nmap scan results below and map each open port/service "
            "to the most likely Metasploit module path. "
            "Output a bulleted list in this format:\n"
            "  • Port <number> (<service>): use/<module/path>\n"
            "No explanations. No markdown headers. Bullet list only."
        )
        user_prompt = f"Analyze and map exploits for:\n{scan_context}"

        ai_result = {"success": False}
        ai_done = threading.Event()

        def _run_ai():
            try:
                # FIXED: passes override_prompt so system message is actually used
                self.ai.chat(user_prompt, override_prompt=system_override)
                ai_result["success"] = True
            except Exception as e:
                console.print(f"[dim red][!] AI error: {e}[/dim red]")
            finally:
                ai_done.set()

        ai_thread = threading.Thread(target=_run_ai, daemon=True)
        ai_thread.start()

        finished = ai_done.wait(timeout=ai_timeout)

        if not finished:
            console.print(
                f"\n[yellow][!] AI timed out after {ai_timeout}s. "
                f"Continuing to Phase 3.[/yellow]"
            )
            console.print(
                "[dim]Set AI_TIMEOUT in Context to increase timeout.[/dim]")
            return False

        return ai_result["success"]

    # ── Phase 3: Exploitation ─────────────────────────────────────────────────

    def _phase_exploit(self, target: str):
        console.print(Panel("PHASE 3: Exploitation Engine",
                      border_style="bold green"))

        execute = questionary.confirm(
            "Hand off to MSF-RPC for auto-exploitation?",
            default=True, style=Q_STYLE
        ).ask()

        if not execute:
            console.print("[dim]Phase 3 skipped by operator.[/dim]")
            return

        if not self.msf._check_deps():
            return
        if not self.msf.connect_rpc():
            return

        console.print(f"[*] Launching MSF Engine against {target}...")
        self.msf.auto_exploit()
        console.print("[*] Checking for active sessions...")
        self.msf.interact_session()

    # ── Phase 4: Auto-Report ─────────────────────────────────────────────────

    def _phase_report(self):
        console.print(Panel("PHASE 4: Mission Report Generation",
                      border_style="bold cyan"))

        generate = questionary.confirm(
            "Auto-generate HTML mission report?",
            default=True, style=Q_STYLE
        ).ask()

        if not generate:
            console.print("[dim]Report generation skipped.[/dim]")
            return

        try:
            from modules.reporter import generate_report
            fname = generate_report()
            if fname:
                console.print(
                    f"[bold green][+] Mission report saved: {fname}[/bold green]")
        except Exception as e:
            console.print(
                f"[yellow][!] Report generation failed: {e}[/yellow]")

    # ── Campaign Orchestrator ─────────────────────────────────────────────────

    def run(self):
        draw_header("GOD MODE: Autonomous Campaign")

        console.print(
            "[dim]Chains: Recon → AI Analysis → Exploitation → Report\n"
            "AI phase is skipped automatically if Ollama is offline or times out.[/dim]\n"
        )

        target = questionary.text("Enter Target IP/CIDR:", style=Q_STYLE).ask()
        if not target:
            return

        target = target.strip()
        ctx.set("RHOST", target)

        start_time = time.time()

        # Phase 1
        scan_context = self._phase_recon(target)
        if not scan_context:
            questionary.press_any_key_to_continue(style=Q_STYLE).ask()
            return

        console.print(f"\n[bold green][+] Phase 1 complete.[/bold green] "
                      f"Scan context: {len(scan_context)} chars")

        # Phase 2
        ai_ok = self._phase_ai(target, scan_context)
        if ai_ok:
            console.print("\n[bold green][+] Phase 2 complete.[/bold green]")
        else:
            console.print("\n[dim][~] Phase 2 skipped — continuing.[/dim]")

        # Phase 3
        self._phase_exploit(target)

        # Phase 4
        self._phase_report()

        elapsed = time.time() - start_time
        console.print(
            f"\n[bold green][+] Campaign terminated in {elapsed:.0f}s.[/bold green]")
        questionary.press_any_key_to_continue(style=Q_STYLE).ask()


def run_god_mode():
    CampaignEngine().run()


if __name__ == "__main__":
    run_god_mode()
