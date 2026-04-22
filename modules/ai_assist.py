"""
ai_assist.py — Davoid Cortex (Local Ollama AI Advisor)
Modernized: Uses Ollama native API directly (no LangChain dependency).
Fixes LangChainDeprecationWarning by removing LangChain entirely.
Adds structured tool-calling simulation and multi-turn memory.
"""

import requests
import json
import os
import sys
import questionary
from rich.console import Console
from rich.panel import Panel
from rich.markdown import Markdown
from rich.table import Table
from core.ui import draw_header, Q_STYLE
from core.database import db

console = Console()

# ─────────────────────────────────────────────────────────────────────────────
#  DB HELPER
# ─────────────────────────────────────────────────────────────────────────────

def _get_critical_logs(limit=10):
    """
    Fetch HIGH/CRITICAL logs from the mission database.
    Supports three patterns depending on what core/database.py exposes:
      1. db.get_critical_logs()
      2. db.cursor (raw SQLite)
      3. db.get_all() — filter in Python
    """
    if hasattr(db, 'get_critical_logs'):
        try:
            return db.get_critical_logs(limit=limit)
        except Exception:
            pass

    if hasattr(db, 'cursor') and db.cursor is not None:
        try:
            db.cursor.execute(
                "SELECT timestamp, module, target, severity, data "
                "FROM mission_logs WHERE severity IN ('HIGH','CRITICAL') "
                "ORDER BY timestamp DESC LIMIT ?",
                (limit,)
            )
            rows = db.cursor.fetchall()
            return [
                {"timestamp": r[0], "module": r[1], "target": r[2],
                 "severity": r[3], "details": r[4]}
                for r in rows
            ]
        except Exception:
            pass

    if hasattr(db, 'get_all'):
        try:
            all_logs = db.get_all()
            filtered = []
            for log in all_logs:
                sev = log.get('severity') if isinstance(log, dict) else getattr(log, 'severity', '')
                if sev in ('HIGH', 'CRITICAL'):
                    filtered.append({
                        "timestamp": log.get('timestamp') if isinstance(log, dict) else getattr(log, 'timestamp', ''),
                        "module":    log.get('module')    if isinstance(log, dict) else getattr(log, 'module',    ''),
                        "target":    log.get('target')    if isinstance(log, dict) else getattr(log, 'target',    ''),
                        "severity":  sev,
                        "details":   log.get('data')      if isinstance(log, dict) else getattr(log, 'data',      ''),
                    })
            return filtered[:limit]
        except Exception:
            pass

    return []


# ─────────────────────────────────────────────────────────────────────────────
#  SYSTEM PROMPTS
# ─────────────────────────────────────────────────────────────────────────────

SYSTEM_PROMPTS = {
    "tactical": (
        "You are DAVOID CORTEX, an elite cybersecurity advisor assisting a "
        "penetration tester who has full authorization on their target systems. "
        "Provide concise, technically accurate advice about:\n"
        "- Interpreting scan results and findings\n"
        "- Explaining vulnerabilities and their impact\n"
        "- Suggesting defensive mitigations\n"
        "- MITRE ATT&CK mappings\n"
        "- Writing SIEM detection rules (Splunk SPL, Sigma)\n"
        "Format responses using Markdown. Use code blocks for commands and queries."
    ),
    "report": (
        "You are a professional security report writer. "
        "Convert raw penetration test findings into clear, structured reports "
        "suitable for technical and executive audiences. "
        "Include: Executive Summary, Technical Findings, Risk Ratings, Remediation Steps. "
        "Use professional language and Markdown formatting."
    ),
    "mitre": (
        "You are a MITRE ATT&CK expert. Map the provided findings to ATT&CK tactics "
        "and techniques. For each finding provide:\n"
        "- Tactic (e.g., Initial Access, Lateral Movement)\n"
        "- Technique ID and name\n"
        "- Detection opportunity\n"
        "- Splunk SPL query to detect it\n"
        "- Sigma rule YAML\n"
        "Format as structured Markdown with code blocks."
    ),
    "explain": (
        "You are a cybersecurity educator. Explain the provided vulnerability or concept "
        "clearly, covering: what it is, why it matters, how it's exploited, and how to defend against it. "
        "Assume the reader has intermediate technical knowledge. Use Markdown formatting."
    ),
}


# ─────────────────────────────────────────────────────────────────────────────
#  CORE ENGINE
# ─────────────────────────────────────────────────────────────────────────────

class AIEngine:
    def __init__(self, model="llama3"):
        self.base_url = "http://127.0.0.1:11434/api"
        self.model = model
        self.history: list[dict] = []
        self.mode = "tactical"

    # ── Connection ────────────────────────────────────────────────

    def check_connection(self) -> bool:
        try:
            r = requests.get(f"{self.base_url}/tags", timeout=3)
            return r.status_code == 200
        except Exception:
            return False

    def list_models(self) -> list[str]:
        try:
            r = requests.get(f"{self.base_url}/tags", timeout=3)
            if r.status_code == 200:
                return [m['name'] for m in r.json().get('models', [])]
        except Exception:
            pass
        return []

    # ── Streaming chat ────────────────────────────────────────────

    def chat(self, user_input: str, override_prompt: str | None = None) -> str:
        """Stream response from Ollama, return full text."""
        system_content = override_prompt or SYSTEM_PROMPTS.get(self.mode, SYSTEM_PROMPTS["tactical"])

        messages = (
            [{"role": "system", "content": system_content}]
            + self.history[-20:]   # keep last 20 turns for context window management
            + [{"role": "user", "content": user_input}]
        )

        payload = {
            "model": self.model,
            "messages": messages,
            "stream": True,
            "options": {
                "temperature": 0.7,
                "num_ctx": 8192,
            }
        }

        console.print(f"\n[bold cyan]Cortex ({self.model}) thinking...[/bold cyan]\n")
        full_response = ""
        printed_chars = 0

        try:
            with requests.post(
                f"{self.base_url}/chat",
                json=payload,
                stream=True,
                timeout=120
            ) as r:
                r.raise_for_status()
                sys.stdout.write("\033[92m")  # green
                for line in r.iter_lines():
                    if line:
                        try:
                            body = json.loads(line)
                            content = body.get("message", {}).get("content", "")
                            sys.stdout.write(content)
                            sys.stdout.flush()
                            full_response += content
                        except json.JSONDecodeError:
                            continue
                sys.stdout.write("\033[0m\n\n")

            # Save to history
            self.history.append({"role": "user",      "content": user_input})
            self.history.append({"role": "assistant",  "content": full_response})

        except requests.exceptions.ConnectionError:
            console.print("[bold red][!] Lost connection to Ollama.[/bold red]")
        except requests.exceptions.Timeout:
            console.print("[bold red][!] Ollama response timed out.[/bold red]")
        except Exception as e:
            console.print(f"[bold red][!] AI error:[/bold red] {e}")

        return full_response

    # ── Non-streaming (for structured output) ────────────────────

    def query(self, prompt: str, system: str | None = None) -> str:
        """Single synchronous query, returns full response string."""
        system_content = system or SYSTEM_PROMPTS.get(self.mode, SYSTEM_PROMPTS["tactical"])
        payload = {
            "model": self.model,
            "messages": [
                {"role": "system",  "content": system_content},
                {"role": "user",    "content": prompt},
            ],
            "stream": False,
            "options": {"temperature": 0.3},
        }
        try:
            r = requests.post(f"{self.base_url}/chat", json=payload, timeout=120)
            r.raise_for_status()
            return r.json().get("message", {}).get("content", "")
        except Exception as e:
            return f"[error] {e}"

    # ── Specialized analysis functions ────────────────────────────

    def analyze_mission_database(self):
        """Pull HIGH/CRITICAL findings and ask Cortex to analyze them."""
        console.print("[dim][*] Querying mission database for HIGH/CRITICAL findings...[/dim]")
        rows = _get_critical_logs(limit=15)

        if not rows:
            console.print(
                "[yellow][!] No HIGH/CRITICAL findings yet. Run scans first.[/yellow]"
            )
            return

        context_lines = ["PENETRATION TEST FINDINGS:\n"]
        for row in rows:
            context_lines.append(
                f"Time    : {row.get('timestamp', 'N/A')}\n"
                f"Module  : {row.get('module', 'N/A')}\n"
                f"Target  : {row.get('target', 'N/A')}\n"
                f"Severity: {row.get('severity', 'N/A')}\n"
                f"Details : {str(row.get('details', ''))[:500]}\n"
                + "─" * 40
            )

        prompt = (
            "Analyze these penetration test findings:\n\n"
            + "\n".join(context_lines)
            + "\n\nProvide:\n"
            "1. The most critical vulnerabilities and their business risk\n"
            "2. How an attacker could chain these findings\n"
            "3. Recommended remediation priorities\n"
            "4. Relevant MITRE ATT&CK technique IDs\n"
        )

        console.print(Panel(
            "Ingesting DB findings and analyzing threat vectors...",
            style="bold magenta"
        ))
        self.chat(prompt)

    def generate_detection_rules(self):
        """Pull findings and generate SIEM detection rules."""
        rows = _get_critical_logs(limit=10)
        if not rows:
            console.print("[yellow][!] No findings in database.[/yellow]")
            return

        modules_seen = set(r.get('module', '') for r in rows)
        prompt = (
            f"Generate Splunk SPL queries and Sigma rules to detect these attack techniques "
            f"based on the following modules that were executed: {', '.join(modules_seen)}.\n\n"
            "For each technique provide:\n"
            "1. A Splunk SPL query\n"
            "2. A Sigma rule in YAML format\n"
            "3. The MITRE ATT&CK technique ID\n"
            "Format each as a Markdown section with code blocks."
        )
        self.chat(prompt, override_prompt=SYSTEM_PROMPTS["mitre"])

    def explain_vulnerability(self):
        """Ask Cortex to explain a specific vulnerability."""
        vuln = questionary.text(
            "Vulnerability or concept to explain (e.g., 'AS-REP Roasting', 'EternalBlue'):",
            style=Q_STYLE
        ).ask()
        if not vuln:
            return
        self.chat(f"Explain: {vuln}", override_prompt=SYSTEM_PROMPTS["explain"])

    def generate_report_summary(self):
        """Generate an executive-style summary from DB findings."""
        rows = _get_critical_logs(limit=20)
        if not rows:
            console.print("[yellow][!] No findings to report.[/yellow]")
            return

        findings_text = "\n".join(
            f"- [{r.get('severity')}] {r.get('module')} on {r.get('target')}: "
            f"{str(r.get('details', ''))[:200]}"
            for r in rows
        )
        prompt = (
            "Generate a professional penetration test executive summary from these findings:\n\n"
            + findings_text
        )
        self.chat(prompt, override_prompt=SYSTEM_PROMPTS["report"])

    def clear_history(self):
        self.history = []
        console.print("[bold green][+] Conversation memory cleared.[/bold green]")

    def show_history_summary(self):
        """Display a brief summary of the current conversation."""
        if not self.history:
            console.print("[yellow]No conversation history.[/yellow]")
            return
        table = Table(title="Conversation History", border_style="dim")
        table.add_column("Turn", style="cyan", justify="center")
        table.add_column("Role", style="magenta")
        table.add_column("Preview", style="white")
        for i, msg in enumerate(self.history[-10:], 1):
            preview = msg['content'][:80].replace('\n', ' ')
            table.add_row(str(i), msg['role'].upper(), preview + "...")
        console.print(table)


# ─────────────────────────────────────────────────────────────────────────────
#  MAIN ENTRY POINT
# ─────────────────────────────────────────────────────────────────────────────

def run_ai_console():
    draw_header("AI Cortex (Local Neural Link)")
    engine = AIEngine()

    if not engine.check_connection():
        console.print("[bold red][!] Ollama is offline.[/bold red]")
        console.print("[white]Start it with:[/white] [bold cyan]ollama serve[/bold cyan]")
        questionary.press_any_key_to_continue(style=Q_STYLE).ask()
        return

    models = engine.list_models()
    if not models:
        console.print("[bold red][!] No models installed.[/bold red]")
        console.print("Run: [bold cyan]ollama pull llama3[/bold cyan]")
        questionary.press_any_key_to_continue(style=Q_STYLE).ask()
        return

    engine.model = questionary.select(
        "Select AI Model:", choices=models, style=Q_STYLE
    ).ask()
    if not engine.model:
        return

    # Mode selection
    mode_map = {
        "Tactical Advisor (General Q&A)": "tactical",
        "MITRE ATT&CK Mapper":             "mitre",
        "Report Writer":                   "report",
        "Vulnerability Explainer":         "explain",
    }
    mode_choice = questionary.select(
        "Select Cortex Mode:",
        choices=list(mode_map.keys()),
        style=Q_STYLE
    ).ask()
    if mode_choice:
        engine.mode = mode_map.get(mode_choice, "tactical")

    MENU = [
        "1. Tactical Chat (Interactive REPL)",
        "2. Analyze Mission Database Findings",
        "3. Generate SIEM Detection Rules",
        "4. Explain a Vulnerability/Concept",
        "5. Generate Executive Report Summary",
        "6. View Conversation History",
        "7. Clear Conversation Memory",
        "Return to Main Menu",
    ]

    while True:
        os.system('cls' if os.name == 'nt' else 'clear')
        draw_header(f"Cortex: {engine.model.upper()} [{engine.mode.upper()}]")

        choice = questionary.select(
            "Select Cortex Operation:", choices=MENU, style=Q_STYLE
        ).ask()

        if not choice or "Return" in choice:
            break

        if "Chat" in choice:
            console.print(Panel(
                "[bold white]Tactical Link Active.[/bold white]\n"
                "Ask about vulnerabilities, CVEs, detection rules, or findings.\n"
                "[dim]Type 'exit', 'quit', or 'back' to return.[/dim]",
                border_style="cyan"
            ))
            while True:
                try:
                    q = questionary.text("Operator >", style=Q_STYLE).ask()
                    if not q or q.lower() in ['exit', 'quit', 'back']:
                        break
                    engine.chat(q)
                except KeyboardInterrupt:
                    break

        elif "Analyze Mission" in choice:
            engine.analyze_mission_database()
            questionary.press_any_key_to_continue(style=Q_STYLE).ask()

        elif "SIEM" in choice:
            engine.generate_detection_rules()
            questionary.press_any_key_to_continue(style=Q_STYLE).ask()

        elif "Explain" in choice:
            engine.explain_vulnerability()
            questionary.press_any_key_to_continue(style=Q_STYLE).ask()

        elif "Executive Report" in choice:
            engine.generate_report_summary()
            questionary.press_any_key_to_continue(style=Q_STYLE).ask()

        elif "History" in choice:
            engine.show_history_summary()
            questionary.press_any_key_to_continue(style=Q_STYLE).ask()

        elif "Clear" in choice:
            engine.clear_history()
            questionary.press_any_key_to_continue(style=Q_STYLE).ask()


if __name__ == "__main__":
    run_ai_console()