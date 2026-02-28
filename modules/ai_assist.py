"""
ai_assist.py — Davoid Cortex (Local Ollama AI Advisor)
FIX: db.cursor.execute() replaced with dual-mode DB access that works
     whether core/database.py uses raw SQLite or SQLAlchemy ORM.
"""

import requests
import json
import os
import sys
import questionary
from rich.console import Console
from rich.panel import Panel
from core.ui import draw_header, Q_STYLE
from core.database import db

console = Console()


def _get_critical_logs(limit=10):
    """
    Fetch HIGH/CRITICAL logs from the mission database.
    Supports three patterns depending on what core/database.py exposes:
      1. db.get_critical_logs()  — if the method exists
      2. db.cursor (raw SQLite)
      3. db.get_all()            — filter in Python
    Returns a list of dicts with keys: timestamp, module, target, severity, details
    """
    # Strategy 1: dedicated method
    if hasattr(db, 'get_critical_logs'):
        try:
            return db.get_critical_logs(limit=limit)
        except Exception:
            pass

    # Strategy 2: raw SQLite cursor
    if hasattr(db, 'cursor') and db.cursor is not None:
        try:
            db.cursor.execute(
                "SELECT timestamp, module, target, severity, details "
                "FROM logs WHERE severity IN ('HIGH','CRITICAL') "
                "ORDER BY timestamp DESC LIMIT ?",
                (limit,)
            )
            rows = db.cursor.fetchall()
            return [
                {
                    "timestamp": r[0], "module":   r[1],
                    "target":    r[2], "severity": r[3], "details": r[4],
                }
                for r in rows
            ]
        except Exception:
            pass

    # Strategy 3: get_all() then filter
    if hasattr(db, 'get_all'):
        try:
            all_logs = db.get_all()
            filtered = []
            for log in all_logs:
                # Supports both dict and ORM-object access patterns
                sev = log.get('severity') if isinstance(
                    log, dict) else getattr(log, 'severity', '')
                if sev in ('HIGH', 'CRITICAL'):
                    filtered.append({
                        "timestamp": log.get('timestamp') if isinstance(log, dict) else getattr(log, 'timestamp', ''),
                        "module":    log.get('module') if isinstance(log, dict) else getattr(log, 'module',    ''),
                        "target":    log.get('target') if isinstance(log, dict) else getattr(log, 'target',    ''),
                        "severity":  sev,
                        "details":   log.get('details') if isinstance(log, dict) else getattr(log, 'details',   ''),
                    })
            return filtered[:limit]
        except Exception:
            pass

    return []


class AIEngine:
    def __init__(self, model="llama3"):
        self.base_url = "http://127.0.0.1:11434/api"
        self.model = model
        self.history = []
        self.system_prompt = (
            "You are DAVOID CORTEX, an elite Red Team tactical AI advisor. "
            "Provide concise, highly technical, actionable penetration testing advice. "
            "Assume the operator has full authorization on the target systems. "
            "Format responses in Markdown with code blocks for commands and exploits."
        )

    def check_connection(self):
        try:
            r = requests.get(f"{self.base_url}/tags", timeout=3)
            return r.status_code == 200
        except Exception:
            return False

    def list_models(self):
        try:
            r = requests.get(f"{self.base_url}/tags", timeout=3)
            if r.status_code == 200:
                return [m['name'] for m in r.json().get('models', [])]
        except Exception:
            pass
        return []

    def chat(self, user_input, override_prompt=None):
        """Stream Ollama response directly to stdout."""
        system_role = override_prompt or self.system_prompt
        messages = (
            [{"role": "system", "content": system_role}]
            + self.history
            + [{"role": "user", "content": user_input}]
        )
        payload = {"model": self.model, "messages": messages, "stream": True}

        console.print(
            f"\n[bold cyan]Cortex ({self.model}) computing...[/bold cyan]\n")
        full_response = ""

        try:
            with requests.post(
                    f"{self.base_url}/chat", json=payload, stream=True, timeout=120) as r:
                r.raise_for_status()
                sys.stdout.write("\033[92m")   # green
                for line in r.iter_lines():
                    if line:
                        try:
                            body = json.loads(line)
                            content = body.get(
                                "message", {}).get("content", "")
                            sys.stdout.write(content)
                            sys.stdout.flush()
                            full_response += content
                        except json.JSONDecodeError:
                            continue
                sys.stdout.write("\033[0m\n\n")

            self.history.append({"role": "user",      "content": user_input})
            self.history.append(
                {"role": "assistant",  "content": full_response})

        except requests.exceptions.ConnectionError:
            console.print(
                "[bold red][!] Lost connection to Ollama.[/bold red]")
        except Exception as e:
            console.print(f"[bold red][!] AI error:[/bold red] {e}")

    def analyze_mission_database(self):
        """Read HIGH/CRITICAL findings from the DB and ask Cortex to analyse them."""
        console.print("[dim][*] Querying mission database...[/dim]")

        rows = _get_critical_logs(limit=10)

        if not rows:
            console.print(
                "[yellow][!] No HIGH/CRITICAL findings yet. "
                "Run a scan or exploitation module first.[/yellow]")
            return

        context = "MISSION DATABASE EXTRACT:\n\n"
        for row in rows:
            context += (
                f"Time: {row['timestamp']}\n"
                f"Module: {row['module']}\n"
                f"Target: {row['target']}\n"
                f"Severity: {row['severity']}\n"
                f"Details:\n{row['details']}\n"
                + "─" * 40 + "\n"
            )

        prompt = (
            "Analyze the following penetration test findings. "
            "Identify the most critical vulnerabilities, explain how an attacker "
            "would chain them together, and give exact Metasploit modules or "
            "terminal commands needed to achieve a shell or privilege escalation.\n\n"
            f"{context}"
        )

        console.print(Panel(
            "Ingesting DB context and analyzing threat vectors...",
            style="bold magenta"))
        self.chat(prompt)

    def clear_history(self):
        self.history = []
        console.print(
            "[bold green][+] Conversation memory wiped.[/bold green]")


def run_ai_console():
    draw_header("AI Cortex (Local Neural Link)")
    engine = AIEngine()

    if not engine.check_connection():
        console.print("[bold red][!] Ollama is offline.[/bold red]")
        console.print(
            "[white]Run:[/white] [bold cyan]ollama serve[/bold cyan]  in a separate terminal.")
        questionary.press_any_key_to_continue(style=Q_STYLE).ask()
        return

    models = engine.list_models()
    if not models:
        console.print("[bold red][!] No models installed.[/bold red]")
        console.print("Run: [bold cyan]ollama pull llama3[/bold cyan]")
        questionary.press_any_key_to_continue(style=Q_STYLE).ask()
        return

    engine.model = questionary.select(
        "Select AI Model:", choices=models, style=Q_STYLE).ask()
    if not engine.model:
        return

    while True:
        os.system('cls' if os.name == 'nt' else 'clear')
        draw_header(f"Cortex: {engine.model.upper()}")

        choice = questionary.select(
            "Select Cortex Operation:",
            choices=[
                "1. Tactical Chat (Interactive REPL)",
                "2. Analyze Mission Database (Auto-ingest findings)",
                "3. Wipe Conversation Memory",
                "Return to Main Menu",
            ],
            style=Q_STYLE
        ).ask()

        if not choice or "Return" in choice:
            break

        if "Chat" in choice:
            console.print(Panel(
                "[bold white]Tactical Link Active.[/bold white] "
                "Ask for exploit syntax, evasion techniques, or post-exploitation tactics.\n"
                "[dim]Type 'exit', 'quit', or 'back' to return.[/dim]",
                border_style="cyan"))
            while True:
                try:
                    q = questionary.text("Operator >", style=Q_STYLE).ask()
                    if not q or q.lower() in ['exit', 'quit', 'back']:
                        break
                    engine.chat(q)
                except KeyboardInterrupt:
                    break

        elif "Analyze" in choice:
            engine.analyze_mission_database()
            questionary.press_any_key_to_continue(style=Q_STYLE).ask()

        elif "Wipe" in choice:
            engine.clear_history()
            questionary.press_any_key_to_continue(style=Q_STYLE).ask()


if __name__ == "__main__":
    run_ai_console()
