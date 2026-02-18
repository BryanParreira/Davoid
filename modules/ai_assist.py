import requests
import json
import os
from rich.console import Console
from rich.markdown import Markdown
from rich.panel import Panel
from rich.prompt import Prompt
from rich.progress import Progress, SpinnerColumn, TextColumn

console = Console()


class AIEngine:
    def __init__(self, model="llama3"):
        # Default Ollama local API endpoint
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
            r = requests.get(f"{self.base_url}/tags")
            if r.status_code == 200:
                return [m['name'] for m in r.json().get('models', [])]
        except:
            pass
        return []

    def chat(self, user_input, system_role="You are a senior penetration tester helper. Be concise, technical, and focus on ethical security auditing."):
        """Sends a prompt to the model and streams the response to the console."""
        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system_role},
                *self.history,
                {"role": "user", "content": user_input}
            ],
            "stream": True
        }

        full_response = ""
        try:
            # Stream the response for a real-time typing effect
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

            # Update history context to maintain conversation continuity
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
                # Truncate to first 8000 chars to avoid hitting context window limits on smaller models
                data = f.read()[:8000]

            prompt = (
                "Analyze the following scan data/log from a security audit. "
                "Identify critical vulnerabilities, misconfigurations, or sensitive data leaks. "
                "Suggest specific remediation steps or further exploitation verification commands (e.g., Metasploit modules, curl commands).\n\n"
                f"LOG DATA:\n{data}"
            )

            console.print(Panel(
                f"Sending {os.path.basename(log_path)} to AI Cortex...", style="bold magenta"))
            self.chat(
                prompt, system_role="You are an expert vulnerability analyst. Provide a structured report with findings and remediation.")

        except Exception as e:
            console.print(f"[red][!] Failed to read log file: {e}[/red]")


def run_ai_console():
    """Main entry point for the AI module."""
    console.clear()
    console.print(Panel.fit(
        "[bold white]Davoid AI Cortex (Powered by Ollama)[/bold white]", border_style="cyan"))

    engine = AIEngine()

    # 1. Connectivity Check
    if not engine.check_connection():
        console.print(
            "[bold red][!] Ollama is not reachable on localhost:11434.[/bold red]")
        console.print(
            "[yellow]Tip: Install Ollama and run 'ollama serve' in a separate terminal.[/yellow]")
        console.print("[dim]Download from: https://ollama.com[/dim]")
        input("\nPress Enter to return...")
        return

    # 2. Model Selection
    models = engine.list_models()
    if models:
        console.print(f"[green]Available Models:[/green] {', '.join(models)}")
        default_model = models[0] if models else "llama3"
        sel = Prompt.ask("Select Model", default=default_model)
        engine.model = sel
    else:
        console.print(
            "[yellow][!] No models found. Using default 'llama3'. Ensure you have pulled a model (e.g., 'ollama pull llama3').[/yellow]")

    # 3. Interactive Loop
    while True:
        console.print("\n[bold cyan]AI OPERATIONS[/bold cyan]")
        console.print(
            "[1] Chat / Strategize [dim](Free-form conversation)[/dim]")
        console.print(
            "[2] Analyze Logs    [dim](Feed scan results to AI)[/dim]")
        console.print("[B] Back to Main Menu")

        choice = Prompt.ask(
            "\n[bold cyan]ai[/bold cyan]@[root]", choices=["1", "2", "b"])

        if choice == "1":
            console.print(
                "[dim]Entering Chat Mode. Type 'exit' to stop.[/dim]")
            while True:
                q = console.input("[bold green]Operator>[/bold green] ")
                if q.lower() in ['exit', 'quit', 'back']:
                    break
                if q.strip():
                    engine.chat(q)

        elif choice == "2":
            log_dir = "logs"
            if os.path.exists(log_dir) and os.listdir(log_dir):
                logs = sorted(os.listdir(log_dir))

                table = Panel("\n".join([f"[{i}] {log}" for i, log in enumerate(
                    logs)]), title="Available Logs", border_style="blue")
                console.print(table)

                try:
                    idx_input = Prompt.ask("Select Log ID")
                    idx = int(idx_input)
                    if 0 <= idx < len(logs):
                        engine.analyze_log(os.path.join(log_dir, logs[idx]))
                    else:
                        console.print("[red]Invalid ID.[/red]")
                except ValueError:
                    console.print("[red]Invalid Input.[/red]")
            else:
                console.print(
                    "[yellow][!] No logs found in 'logs/' directory. Run a scan first.[/yellow]")

        elif choice == "b":
            break
