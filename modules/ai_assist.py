"""
modules/ai_assist.py — Davoid Cortex (Autonomous AI Agent)
True LangChain implementation. The AI has tools to ping targets and read databases autonomously.
"""

import os
import sys
import requests
import questionary
import subprocess
import warnings
from rich.console import Console
from rich.panel import Panel

# --- SILENCE ALL LANGCHAIN WARNINGS COMPLETELY ---
warnings.filterwarnings("ignore")
os.environ["LANGCHAIN_TRACING_V2"] = "false"

# Modern Langchain Agent Imports
from langchain_ollama import ChatOllama
from langchain.agents import initialize_agent, AgentType, Tool
from langchain_core.messages import SystemMessage

from core.ui import draw_header, Q_STYLE
from core.database import db

console = Console()

# ─────────────────────────────────────────────────────────────────────────────
#  AGENT TOOLS (Functions the AI executes autonomously)
# ─────────────────────────────────────────────────────────────────────────────

def tool_query_mission_db(query: str = "") -> str:
    """Tool for the AI to read the penetration testing database."""
    if hasattr(db, 'cursor') and db.cursor is not None:
        try:
            db.cursor.execute("SELECT timestamp, module, target, severity, details FROM logs ORDER BY timestamp DESC LIMIT 10")
            rows = db.cursor.fetchall()
            if not rows:
                return "The database is empty. No vulnerabilities found yet."
            result = "Recent Findings:\n"
            for r in rows:
                result += f"- Target: {r[2]} | Severity: {r[3]} | Detail: {r[4]}\n"
            return result
        except Exception as e:
            return f"Error reading database: {e}"
    return "Database not accessible."

def tool_ping_target(target_ip: str) -> str:
    """Tool for the AI to check if a target is online."""
    try:
        output = subprocess.check_output(f"ping -c 1 -W 1 {target_ip}", shell=True, stderr=subprocess.STDOUT)
        return f"Target {target_ip} is ONLINE.\n{output.decode('utf-8')}"
    except subprocess.CalledProcessError:
        return f"Target {target_ip} is OFFLINE or blocking ICMP."

# ─────────────────────────────────────────────────────────────────────────────
#  CORTEX ENGINE
# ─────────────────────────────────────────────────────────────────────────────

class AutonomousCortex:
    def __init__(self, model: str = None):
        try:
            from core.context import ctx
            self.model_name = model or ctx.get("AI_MODEL") or "llama3"
        except Exception:
            self.model_name = model or "llama3"

        self.base_url = self._auto_detect_ollama()
        
        # Initialize the LLM with low temperature for tool accuracy
        self.llm = ChatOllama(
            base_url=self.base_url,
            model=self.model_name,
            temperature=0.1, 
        )
        
        # Register the Tools
        self.tools = [
            Tool(
                name="QueryMissionDatabase",
                func=tool_query_mission_db,
                description="Use this to check what vulnerabilities have been found in the database."
            ),
            Tool(
                name="PingTarget",
                func=tool_ping_target,
                description="Use this to check if an IP address is online. Input must be an IP (e.g., 192.168.1.5)."
            )
        ]
        
        # Suppress standard output warnings while creating agent
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            self.agent = initialize_agent(
                tools=self.tools,
                llm=self.llm,
                agent=AgentType.CHAT_ZERO_SHOT_REACT_DESCRIPTION,
                verbose=False,
                handle_parsing_errors=True,
                agent_kwargs={
                    "system_message": (
                        "You are DAVOID CORTEX, an autonomous Red Team AI agent. "
                        "You have access to tools to query the database and ping targets. "
                        "Always use your tools if you need context to answer the user's question."
                    )
                }
            )

    def _auto_detect_ollama(self) -> str:
        """Silently route network traffic based on environment detection."""
        if os.path.exists('/.dockerenv'):
            target_url = "http://host.docker.internal:11434"
        else:
            target_url = "http://127.0.0.1:11434"

        try:
            if requests.get(f"{target_url}/api/tags", timeout=1).status_code == 200:
                return target_url
        except requests.exceptions.RequestException:
            pass
        return target_url

    def check_connection(self) -> bool:
        try: return requests.get(f"{self.base_url}/api/tags", timeout=2).status_code == 200
        except Exception: return False

    def list_models(self) -> list:
        try:
            r = requests.get(f"{self.base_url}/api/tags", timeout=2)
            if r.status_code == 200:
                return [model.get("name") for model in r.json().get("models", [])]
        except Exception: pass
        return []

    def chat(self, user_input: str):
        console.print(f"\n[bold cyan]Cortex ({self.model_name}) thinking and running tools...[/bold cyan]")
        try:
            # Execute the LangChain Agent
            with warnings.catch_warnings():
                warnings.simplefilter("ignore")
                result = self.agent.invoke({"input": user_input})
            
            response = result.get("output", str(result))
            console.print("\n[bold green]Cortex:[/bold green]")
            console.print(response + "\n")
            
        except Exception as e:
            console.print(f"[bold red][!] Agent Execution Error:[/bold red] {e}")


def run_ai_console():
    draw_header("AI Cortex (Autonomous Agent)")
    agent = AutonomousCortex()

    if not agent.check_connection():
        console.print(f"[bold red][!] Ollama is unreachable at {agent.base_url}[/bold red]")
        console.print("Ensure Ollama is running in the background on your machine.")
        questionary.press_any_key_to_continue(style=Q_STYLE).ask()
        return

    available_models = agent.list_models()
    if not available_models:
        console.print("[bold red][!] No models found installed in Ollama.[/bold red]")
        return

    agent.model_name = questionary.select(
        "Select an Installed AI Model:",
        choices=available_models,
        style=Q_STYLE
    ).ask()

    if not agent.model_name: return

    agent = AutonomousCortex(model=agent.model_name)

    while True:
        os.system('cls' if os.name == 'nt' else 'clear')
        draw_header(f"Cortex: {agent.model_name.upper()}")
        
        console.print(Panel(
            "[bold white]Autonomous Link Active.[/bold white]\n"
            "The AI now has access to [cyan]Tools[/cyan]. Try asking it:\n"
            " - [dim]'What did we find in the database so far?'[/dim]\n"
            " - [dim]'Can you check if 8.8.8.8 is online?'[/dim]\n"
            "Type 'exit' to return.",
            border_style="cyan"
        ))

        while True:
            try:
                q = questionary.text("Operator >", style=Q_STYLE).ask()
                if not q or q.lower() in ['exit', 'quit', 'back']: break
                agent.chat(q)
            except KeyboardInterrupt: break

        break

if __name__ == "__main__":
    run_ai_console()