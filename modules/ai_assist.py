import requests
import json
import os
import sys
import questionary
from rich.console import Console
from rich.panel import Panel
from core.ui import draw_header, Q_STYLE

console = Console()


class AIEngine:
    def __init__(self, model="llama3"):
        self.base_url = "http://localhost:11434/api"
        self.model = model
        self.history = []

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
                models = [m['name'] for m in r.json().get('models', [])]
                return models
        except:
            pass
        return []

    def chat(self, user_input, system_role="You are a senior cybersecurity expert. Be technical, concise, and focused on ethical security auditing."):
        """
        Sends a prompt to the model and streams the response.
        """
        messages = [{"role": "system", "content": system_role}] + \
            self.history + [{"role": "user", "content": user_input}]

        payload = {
            "model": self.model,
            "messages": messages,
            "stream": True
        }

        full_response = ""
        try:
            with requests.post(f"{self.base_url}/chat", json=payload, stream=True) as r:
                console.print(
                    f"\n[bold cyan]AI ({self.model}):[/bold cyan] ", end="")

                for line in r.iter_lines():
                    if line:
                        try:
                            body = json.loads(line)
                            if "message" in body:
                                content = body["message"].get("content", "")
                                print(content, end="", flush=True)
                                full_response += content
                        except json.JSONDecodeError:
                            continue
            print("\n")

            self.history.append({"role": "user", "content": user_input})
            self.history.append(
                {"role": "assistant", "content": full_response})

        except Exception as e:
            console.print(f"[red][!] AI Interaction Error: {e}[/red]")

    def analyze_log(self, log_path):
        """Reads a specific log file and asks AI for a vulnerability assessment."""
        if not os.path.exists(log_path):
            console.print("[red][!] Log file not found.[/red]")
            return

        try:
            with open(log_path, 'r', encoding='utf-8', errors='ignore') as f:
                data = f.read()[:8000]

            prompt = (
                "Analyze the following scan data. Identify critical vulnerabilities and suggest remediation.\n\n"
                f"LOG DATA:\n{data}"
            )

            console.print(Panel(
                f"Sending {os.path.basename(log_path)} to AI Cortex...", style="bold magenta"))
            self.chat(
                prompt, system_role="You are an expert vulnerability analyst. Provide a structured report.")

        except Exception as e:
            console.print(f"[red][!] Failed to read log file: {e}[/red]")

    def clear_history(self):
        self.history = []
        console.print("[dim][*] Conversation memory wiped.[/dim]")


def run_ai_console():
    """Main entry point for the AI module."""
    console.clear()
    draw_header("AI Cortex (Ollama Engine)")

    engine = AIEngine()

    # 1. Connectivity Check
    if not engine.check_connection():
        console.print(
            "[bold red][!] Ollama is not reachable on localhost:11434.[/bold red]")
        console.print(
            "[yellow]Tip: Run 'ollama serve' in a separate terminal.[/yellow]")
        questionary.press_any_key_to_continue(style=Q_STYLE).ask()
        return

    # 2. Model Selection
    models = engine.list_models()
    default_model = "llama3"

    if models:
        default_model = questionary.select(
            "Select AI Model:",
            choices=models,
            style=Q_STYLE
        ).ask()

    engine.model = default_model

    # 3. Interactive Loop
    while True:
        os.system('cls' if os.name == 'nt' else 'clear')
        draw_header(f"AI Cortex: {engine.model}")

        choice = questionary.select(
            "AI Operations:",
            choices=[
                "1. Chat / Strategize (Interactive)",
                "2. Analyze Logs (Scan Analysis)",
                "3. Clear Memory",
                "Back to Main Menu"
            ],
            style=Q_STYLE
        ).ask()

        if "Chat" in choice:
            console.print("[dim]Chat Active. Type 'exit' to return.[/dim]")
            while True:
                try:
                    q = questionary.text("Operator>", style=Q_STYLE).ask()
                    if not q or q.lower() in ['exit', 'quit', 'back']:
                        break
                    engine.chat(q)
                except KeyboardInterrupt:
                    break

        elif "Analyze" in choice:
            log_dir = "logs"
            if os.path.exists(log_dir) and os.listdir(log_dir):
                logs = sorted(os.listdir(log_dir))

                target_log = questionary.select(
                    "Select Log File:",
                    choices=logs,
                    style=Q_STYLE
                ).ask()

                if target_log:
                    engine.analyze_log(os.path.join(log_dir, target_log))
                    questionary.press_any_key_to_continue(style=Q_STYLE).ask()
            else:
                console.print("[yellow][!] No logs found.[/yellow]")
                questionary.press_any_key_to_continue(style=Q_STYLE).ask()

        elif "Clear" in choice:
            engine.clear_history()
            questionary.press_any_key_to_continue(style=Q_STYLE).ask()

        elif "Back" in choice:
            break


if __name__ == "__main__":
    run_ai_console()
