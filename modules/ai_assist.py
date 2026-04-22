"""
modules/ai_assist.py — Davoid Cortex (Agentic AI Workflow)
"""

import os
import sys
import requests
import questionary
from rich.console import Console
from rich.panel import Panel

# Modern Langchain Imports
from langchain_ollama import ChatOllama
from langchain_core.messages import SystemMessage, HumanMessage, AIMessage

from core.ui import draw_header, Q_STYLE
from core.database import db

console = Console()

def _get_critical_logs(limit: int = 10) -> list[dict]:
    if hasattr(db, 'get_critical_logs'):
        try: return db.get_critical_logs(limit=limit)
        except Exception: pass
    if hasattr(db, 'cursor') and db.cursor is not None:
        try:
            db.cursor.execute(
                "SELECT timestamp, module, target, severity, details FROM logs WHERE severity IN ('HIGH','CRITICAL') ORDER BY timestamp DESC LIMIT ?",
                (limit,)
            )
            return [{"timestamp": r[0], "module": r[1], "target": r[2], "severity": r[3], "details": r[4]} for r in db.cursor.fetchall()]
        except Exception: pass
    return []

class AgenticCortex:
    def __init__(self, model: str = None):
        # Determine the model
        try:
            from core.context import ctx
            self.model_name = model or ctx.get("AI_MODEL") or "llama3"
        except Exception:
            self.model_name = model or "llama3"

        # Auto-detect the correct network route silently
        self.base_url = self._auto_detect_ollama()
        self.history = []
        
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

    def _auto_detect_ollama(self) -> str:
        """Silently probe the network to find Ollama, eliminating manual configuration."""
        urls_to_test = [
            "http://127.0.0.1:11434",            # Native Mac/Linux
            "http://host.docker.internal:11434", # Docker Desktop
            "http://172.17.0.1:11434"            # Raw Docker Bridge
        ]
        
        for url in urls_to_test:
            try:
                if requests.get(f"{url}/api/tags", timeout=1).status_code == 200:
                    return url
            except requests.exceptions.RequestException:
                continue
                
        # Fallback default
        return "http://127.0.0.1:11434"

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
        console.print(f"\n[bold cyan]Cortex ({self.model_name}) analyzing...[/bold cyan]\n")
        messages = [self.system_prompt] + self.history + [HumanMessage(content=user_input)]
        try:
            full_response = ""
            sys.stdout.write("\033[92m") 
            for chunk in self.llm.stream(messages):
                content = chunk.content
                sys.stdout.write(content)
                sys.stdout.flush()
                full_response += content
            sys.stdout.write("\033[0m\n\n") 
            self.history.append(HumanMessage(content=user_input))
            self.history.append(AIMessage(content=full_response))
        except Exception as e:
            console.print(f"[bold red][!] AI Agent Execution Error:[/bold red] {e}")

    def analyze_mission_database(self):
        console.print("[dim][*] Querying mission database...[/dim]")
        rows = _get_critical_logs(limit=10)
        if not rows:
            console.print("[yellow][!] No HIGH/CRITICAL findings in database. Run a module first.[/yellow]")
            return
        context_data = "\n".join(
            f"[{r['timestamp']}] MODULE: {r['module']} | TARGET: {r['target']} | SEVERITY: {r['severity']}\nDETAILS: {r['details']}\n"
            for r in rows
        )
        prompt = (
            "Analyze the following database extract from the current penetration test. "
            "Identify the attack path, how to chain these vulnerabilities, and provide "
            "the exact payloads or commands required for exploitation.\n\n"
            f"DATABASE EXTRACT:\n{context_data}"
        )
        console.print(Panel("Agent digesting DB context...", style="bold magenta"))
        self.chat(prompt)

    def clear_history(self):
        self.history = []
        console.print("[bold green][+] Agent memory wiped.[/bold green]")


def run_ai_console():
    draw_header("AI Cortex (Agentic Workflow)")
    agent = AgenticCortex()

    # 1. Ensure Ollama is running
    if not agent.check_connection():
        console.print(f"[bold red][!] Ollama is unreachable at {agent.base_url}[/bold red]")
        console.print("Ensure Ollama is running in the background on your Mac and you have downloaded a model.")
        questionary.press_any_key_to_continue(style=Q_STYLE).ask()
        return

    # 2. Fetch available models dynamically
    available_models = agent.list_models()
    if not available_models:
        console.print("[bold red][!] No models found installed in Ollama.[/bold red]")
        console.print("Run `ollama pull llama3` in your terminal to download a model.")
        questionary.press_any_key_to_continue(style=Q_STYLE).ask()
        return

    # 3. Present the Dynamic Dropdown
    agent.model_name = questionary.select(
        "Select an Installed AI Model:",
        choices=available_models,
        style=Q_STYLE
    ).ask()

    if not agent.model_name: return

    # 4. Re-initialize with selected model
    agent = AgenticCortex(model=agent.model_name)

    while True:
        os.system('cls' if os.name == 'nt' else 'clear')
        draw_header(f"Cortex: {agent.model_name.upper()}")
        choice = questionary.select(
            "Select Cortex Operation:",
            choices=["1. Tactical Chat", "2. Analyze Mission Database", "3. Wipe Agent Memory", "Return to Main Menu"],
            style=Q_STYLE
        ).ask()
        
        if not choice or "Return" in choice: break
        
        if "Chat" in choice:
            while True:
                try:
                    q = questionary.text("Operator >", style=Q_STYLE).ask()
                    if not q or q.lower() in ['exit', 'quit', 'back']: break
                    agent.chat(q)
                except KeyboardInterrupt: break
        elif "Analyze" in choice:
            agent.analyze_mission_database()
            questionary.press_any_key_to_continue(style=Q_STYLE).ask()
        elif "Wipe" in choice:
            agent.clear_history()
            questionary.press_any_key_to_continue(style=Q_STYLE).ask()

if __name__ == "__main__":
    run_ai_console()