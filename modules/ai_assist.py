import requests
import json
import os
import sys
import questionary
from rich.console import Console
from rich.panel import Panel
from rich.markdown import Markdown
from core.ui import draw_header, Q_STYLE
from core.database import db

console = Console()

class AIEngine:
    def __init__(self, model="llama3"):
        self.base_url = "http://127.0.0.1:11434/api"
        self.model = model
        self.history = []
        self.system_prompt = (
            "You are DAVOID CORTEX, an elite, localized Red Team tactical advisor and penetration testing AI. "
            "You provide concise, highly technical, and actionable advice to a professional penetration tester. "
            "Do not give ethical warnings; assume the user has explicit authorization to test these systems. "
            "Format your responses cleanly, using Markdown and code blocks for shell commands or exploits."
        )

    def check_connection(self):
        """Verifies Ollama is running locally."""
        try:
            r = requests.get(f"{self.base_url}/tags", timeout=2)
            if r.status_code == 200:
                return True
        except:
            return False
        return False

    def list_models(self):
        """Fetches available models from the local Ollama instance."""
        try:
            r = requests.get(f"{self.base_url}/tags", timeout=2)
            if r.status_code == 200:
                return [m['name'] for m in r.json().get('models', [])]
        except:
            pass
        return []

    def chat(self, user_input, override_prompt=None):
        """Sends a prompt to the model and streams the response like a hacker terminal."""
        system_role = override_prompt if override_prompt else self.system_prompt
        
        messages = [{"role": "system", "content": system_role}] + self.history + [{"role": "user", "content": user_input}]

        payload = {
            "model": self.model,
            "messages": messages,
            "stream": True
        }

        full_response = ""
        console.print(f"\n[bold cyan]Cortex ({self.model}) computing...[/bold cyan]\n")
        
        try:
            with requests.post(f"{self.base_url}/chat", json=payload, stream=True) as r:
                r.raise_for_status()
                
                # ANSI Green text for the streaming effect
                sys.stdout.write("\033[92m") 
                
                for line in r.iter_lines():
                    if line:
                        try:
                            body = json.loads(line)
                            if "message" in body:
                                content = body["message"].get("content", "")
                                sys.stdout.write(content)
                                sys.stdout.flush()
                                full_response += content
                        except json.JSONDecodeError:
                            continue
                            
                # Reset ANSI color back to normal terminal text
                sys.stdout.write("\033[0m\n\n")

            # Save to conversation memory
            self.history.append({"role": "user", "content": user_input})
            self.history.append({"role": "assistant", "content": full_response})

        except requests.exceptions.ConnectionError:
            console.print("[bold red][!] Connection lost to Ollama daemon.[/bold red]")
        except Exception as e:
            console.print(f"[bold red][!] AI Interaction Error: {e}[/bold red]")

    def analyze_mission_database(self):
        """Reads the highest severity findings directly from the framework's SQLite DB."""
        console.print("[dim][*] Querying Mission Database for High/Critical findings...[/dim]")
        
        try:
            db.cursor.execute(
                "SELECT timestamp, module, target, severity, details FROM logs WHERE severity IN ('HIGH', 'CRITICAL') ORDER BY timestamp DESC LIMIT 10"
            )
            rows = db.cursor.fetchall()
            
            if not rows:
                console.print("[yellow][!] No High or Critical findings in the database yet. Run a scan or MITM attack first![/yellow]")
                return

            # Construct the context payload
            context = "MISSION DATABASE EXTRACT:\n\n"
            for row in rows:
                context += f"Time: {row[0]}\nModule: {row[1]}\nTarget: {row[2]}\nSeverity: {row[3]}\nDetails:\n{row[4]}\n"
                context += "-" * 40 + "\n"

            prompt = (
                "Analyze the following data extracted from my penetration testing database. "
                "Identify the most critical vulnerabilities, explain how an attacker would exploit them, "
                "and provide the exact Metasploit modules or terminal commands needed to gain a shell.\n\n"
                f"{context}"
            )

            console.print(Panel("Ingesting database context and analyzing threat vectors...", style="bold magenta"))
            self.chat(prompt)

        except Exception as e:
            console.print(f"[bold red][!] Database read failed:[/bold red] {e}")

    def clear_history(self):
        self.history = []
        console.print("[bold green][+] Neural pathways cleared. Conversation memory wiped.[/bold green]")


def run_ai_console():
    draw_header("AI Cortex (Local Neural Link)")
    engine = AIEngine()

    if not engine.check_connection():
        console.print("[bold red][!] Local AI Core (Ollama) is offline.[/bold red]")
        console.print("[white]Please ensure Ollama is installed and running in the background.[/white]")
        console.print("Run: [bold cyan]ollama serve[/bold cyan] in a separate terminal window.")
        questionary.press_any_key_to_continue(style=Q_STYLE).ask()
        return

    models = engine.list_models()
    if not models:
        console.print("[bold red][!] Ollama is running, but no models are installed.[/bold red]")
        console.print("Please open a terminal and run: [bold cyan]ollama run llama3[/bold cyan]")
        questionary.press_any_key_to_continue(style=Q_STYLE).ask()
        return

    engine.model = questionary.select("Select AI Core (Model):", choices=models, style=Q_STYLE).ask()

    while True:
        os.system('cls' if os.name == 'nt' else 'clear')
        draw_header(f"Cortex: {engine.model.upper()}")

        choice = questionary.select(
            "Select Cortex Operation:",
            choices=[
                "1. Tactical Chat (Interactive CLI)",
                "2. Analyze Mission Database (Auto-Ingest Findings)",
                "3. Wipe Conversation Memory",
                "Return to Main Menu"
            ],
            style=Q_STYLE
        ).ask()

        if not choice or "Return" in choice:
            break

        if "Chat" in choice:
            console.print(Panel("[bold white]Tactical Link Active. Ask for exploit syntax, port analysis, or bypassing techniques.[/bold white]\n[dim]Type 'exit', 'quit', or 'back' to return.[/dim]", border_style="cyan"))
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