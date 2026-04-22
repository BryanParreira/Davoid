"""
modules/ai_assist.py — Davoid Cortex (Agentic AI Workflow)
UPGRADED: Replaced basic requests with LangChain + Ollama for intelligent,
          tool-capable agentic workflows.
"""

import os
import sys
import questionary
from rich.console import Console
from rich.panel import Panel
from rich.markdown import Markdown

# Langchain Enterprise Imports
from langchain_community.chat_models import ChatOllama
from langchain_core.messages import SystemMessage, HumanMessage, AIMessage
from langchain_core.prompts import ChatPromptTemplate

from core.ui import draw_header, Q_STYLE
from core.database import db

console = Console()


def _get_critical_logs(limit: int = 10) -> list[dict]:
    """Fetch HIGH/CRITICAL logs from the mission database securely."""
    if hasattr(db, 'get_critical_logs'):
        try:
            return db.get_critical_logs(limit=limit)
        except Exception:
            pass

    if hasattr(db, 'cursor') and db.cursor is not None:
        try:
            db.cursor.execute(
                "SELECT timestamp, module, target, severity, details "
                "FROM logs WHERE severity IN ('HIGH','CRITICAL') "
                "ORDER BY timestamp DESC LIMIT ?",
                (limit,)
            )
            rows = db.cursor.fetchall()
            return [{"timestamp": r[0], "module": r[1], "target": r[2], "severity": r[3], "details": r[4]} for r in rows]
        except Exception:
            pass
    return []


class AgenticCortex:
    def __init__(self, model: str = None):
        try:
            from core.context import ctx
            # Clean base URL for Langchain
            raw_url = ctx.get("AI_URL") or "http://127.0.0.1:11434/api"
            self.base_url = raw_url.replace("/api", "")
            self.model_name = model or ctx.get("AI_MODEL") or "llama3"
        except Exception:
            self.base_url = "http://127.0.0.1:11434"
            self.model_name = model or "llama3"

        self.history = []

        # Initialize LangChain Chat Model
        self.llm = ChatOllama(
            base_url=self.base_url,
            model=self.model_name,
            temperature=0.3,
        )

        self.system_prompt = SystemMessage(content=(
            "You are DAVOID CORTEX, an autonomous Red Team tactical AI agent. "
            "Provide highly technical, actionable penetration testing advice. "
            "Assume the operator has explicit authorization on target systems. "
            "Format your output purely in Markdown, prioritizing exact terminal commands."
        ))

    def check_connection(self) -> bool:
        """Test connection to local Ollama instance via Langchain."""
        try:
            # Send a tiny ping to verify
            self.llm.invoke([HumanMessage(content="ping")])
            return True
        except Exception:
            return False

    def chat(self, user_input: str):
        """Execute chat utilizing LangChain memory components."""
        console.print(
            f"\n[bold cyan]Cortex ({self.model_name}) analyzing...[/bold cyan]\n")

        messages = [self.system_prompt] + self.history + \
            [HumanMessage(content=user_input)]

        try:
            # Stream the response using LangChain's native streaming
            full_response = ""
            sys.stdout.write("\033[92m")  # Green text

            for chunk in self.llm.stream(messages):
                content = chunk.content
                sys.stdout.write(content)
                sys.stdout.flush()
                full_response += content

            sys.stdout.write("\033[0m\n\n")  # Reset

            # Update conversational memory
            self.history.append(HumanMessage(content=user_input))
            self.history.append(AIMessage(content=full_response))

        except Exception as e:
            console.print(
                f"[bold red][!] AI Agent Execution Error:[/bold red] {e}")

    def analyze_mission_database(self):
        """Ingests mission DB state and processes via LangChain."""
        console.print("[dim][*] Querying mission database...[/dim]")
        rows = _get_critical_logs(limit=10)

        if not rows:
            console.print(
                "[yellow][!] No HIGH/CRITICAL findings in database. Run a module first.[/yellow]")
            return

        context_data = "\n".join(
            f"[{r['timestamp']}] MODULE: {r['module']} | TARGET: {r['target']} | SEVERITY: {r['severity']}\nDETAILS: {r['details']}\n"
            for r in rows
        )

        prompt = (
            "Analyze the following database extract from the current penetration test. "
            "Identify the attack path, how to chain these vulnerabilities, and provide "
            "the exact MSFvenom payloads or Metasploit commands required for exploitation.\n\n"
            f"DATABASE EXTRACT:\n{context_data}"
        )

        console.print(
            Panel("Agent digesting DB context...", style="bold magenta"))
        self.chat(prompt)

    def clear_history(self):
        self.history = []
        console.print("[bold green][+] Agent memory wiped.[/bold green]")


def run_ai_console():
    draw_header("AI Cortex (Agentic Workflow)")

    # Instantiate without predefined model to check connection first
    agent = AgenticCortex()

    if not agent.check_connection():
        console.print(
            "[bold red][!] Local AI backend (Ollama) is offline or unreachable.[/bold red]")
        console.print(
            "Ensure Ollama is running: [bold cyan]ollama serve[/bold cyan]")
        questionary.press_any_key_to_continue(style=Q_STYLE).ask()
        return

    # User Model Selection
    agent.model_name = questionary.text(
        "Enter AI Model Name (Default: llama3):",
        default="llama3",
        style=Q_STYLE
    ).ask()

    # Re-initialize with correct model
    agent = AgenticCortex(model=agent.model_name)

    while True:
        os.system('cls' if os.name == 'nt' else 'clear')
        draw_header(f"Cortex: {agent.model_name.upper()}")

        choice = questionary.select(
            "Select Cortex Operation:",
            choices=[
                "1. Tactical Chat (LangChain REPL)",
                "2. Analyze Mission Database (Context-Aware)",
                "3. Wipe Agent Memory",
                "Return to Main Menu",
            ],
            style=Q_STYLE
        ).ask()

        if not choice or "Return" in choice:
            break

        if "Chat" in choice:
            console.print(Panel(
                "[bold white]Agent Link Active.[/bold white] Ask for strategies or exploits.\n"
                "[dim]Type 'exit', 'quit', or 'back' to return.[/dim]",
                border_style="cyan"
            ))
            while True:
                try:
                    q = questionary.text("Operator >", style=Q_STYLE).ask()
                    if not q or q.lower() in ['exit', 'quit', 'back']:
                        break
                    agent.chat(q)
                except KeyboardInterrupt:
                    break

        elif "Analyze" in choice:
            agent.analyze_mission_database()
            questionary.press_any_key_to_continue(style=Q_STYLE).ask()

        elif "Wipe" in choice:
            agent.clear_history()
            questionary.press_any_key_to_continue(style=Q_STYLE).ask()


if __name__ == "__main__":
    run_ai_console()
