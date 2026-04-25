"""
modules/ai_assist.py — Autonomous AI Cortex (Ollama + LangChain)
FIXES:
  - Added AIEngine alias class so god_mode.py import resolves without crash
  - AIEngine.chat() supports optional override_prompt for god_mode Phase 2
  - No other behaviour changed
"""

import os
import subprocess
import warnings
import requests
import questionary

from rich.console import Console
from rich.panel import Panel

from langchain_ollama import ChatOllama
from langchain.agents import initialize_agent, AgentType, Tool

from core.ui import draw_header, Q_STYLE
from core.database import db

console = Console()


# ─────────────────────────────────────────────────────────────────────────────
#  TOOL DEFINITIONS  (called by the LangChain agent)
# ─────────────────────────────────────────────────────────────────────────────

def tool_query_mission_db(_: str) -> str:
    """Returns a summary of all mission database entries."""
    try:
        logs = db.get_all()
        if not logs:
            return "Mission database is empty."
        lines = []
        for log in logs[-20:]:
            ts = log.get("timestamp", "?")
            mod = log.get("module", "?")
            tgt = log.get("target", "?")
            det = log.get("details", "")[:120]
            lines.append(f"[{ts}] {mod} → {tgt}: {det}")
        return "\n".join(lines)
    except Exception as e:
        return f"DB query failed: {e}"


def tool_ping_target(target: str) -> str:
    """Pings a host to check if it is online."""
    try:
        flag = "-n" if os.name == "nt" else "-c"
        result = subprocess.run(
            ["ping", flag, "3", target.strip()],
            capture_output=True, text=True, timeout=10)
        if result.returncode == 0:
            return f"{target} is ONLINE.\n{result.stdout[:300]}"
        return f"{target} is OFFLINE or unreachable."
    except Exception as e:
        return f"Ping failed: {e}"


def tool_nmap_scan(target: str) -> str:
    """Runs a fast Nmap port scan on the given target."""
    try:
        result = subprocess.check_output(
            ["nmap", "-T4", "-F", "--open", target.strip()],
            stderr=subprocess.STDOUT, timeout=60)
        return f"Nmap Results:\n{result.decode('utf-8')[:2000]}"
    except subprocess.TimeoutExpired:
        return "Nmap scan timed out after 60 seconds."
    except Exception as e:
        return f"Nmap failed: {e}"


def tool_run_metasploit(commands: str) -> str:
    """Runs a sequence of semicolon-separated msfconsole commands."""
    try:
        if "exit" not in commands:
            commands += "; exit"
        output = subprocess.check_output(
            f"msfconsole -q -x '{commands}'",
            shell=True,
            stderr=subprocess.STDOUT,
            timeout=120)
        return f"Metasploit Execution Results:\n{output.decode('utf-8')}"
    except subprocess.TimeoutExpired:
        return "Metasploit execution timed out after 120 seconds."
    except Exception as e:
        return f"Metasploit failed: {e}"


def tool_dns_recon(domain: str) -> str:
    """Performs a DNS lookup on a domain to find IP addresses."""
    try:
        output = subprocess.check_output(
            f"nslookup {domain}", shell=True, stderr=subprocess.STDOUT)
        return f"DNS Results for {domain}:\n{output.decode('utf-8')}"
    except Exception as e:
        return f"DNS lookup failed: {e}"


def tool_web_headers(url: str) -> str:
    """Grabs HTTP response headers from a web server."""
    if not url.startswith("http"):
        url = "http://" + url
    try:
        r = requests.head(url, timeout=5, allow_redirects=True)
        headers_str = "\n".join([f"{k}: {v}" for k, v in r.headers.items()])
        return f"HTTP Headers for {url}:\n{headers_str}"
    except Exception as e:
        return f"Failed to connect: {e}"


# ─────────────────────────────────────────────────────────────────────────────
#  CORTEX ENGINE
# ─────────────────────────────────────────────────────────────────────────────

class AutonomousCortex:
    def __init__(self, model: str = None):
        try:
            from core.context import ctx
            self.model_name = model or ctx.get("AI_MODEL") or "llama3"
            self.operator_ip = ctx.get("LHOST") or "Unknown"
            self.gateway_ip = ctx.get("GATEWAY") or "Unknown"
        except Exception:
            self.model_name = model or "llama3"
            self.operator_ip = "Unknown"
            self.gateway_ip = "Unknown"

        self.base_url = self._auto_detect_ollama()

        self.llm = ChatOllama(
            base_url=self.base_url,
            model=self.model_name,
            temperature=0.1,
        )

        self._build_agent()

    def _build_agent(self, system_override: str = None):
        """(Re)builds the LangChain agent, optionally with a custom system prompt."""
        tools = [
            Tool(name="QueryMissionDatabase",
                 func=tool_query_mission_db,
                 description="Query the mission database to see saved vulnerabilities and targets."),
            Tool(name="PingTarget",
                 func=tool_ping_target,
                 description="Check if an IP address or hostname is online. Input: IP or domain."),
            Tool(name="NmapPortScan",
                 func=tool_nmap_scan,
                 description="Fast port scan. Input: IP, domain, or CIDR subnet."),
            Tool(name="RunMetasploit",
                 func=tool_run_metasploit,
                 description="Run msfconsole commands. Input: semicolon-separated commands."),
            Tool(name="DNSRecon",
                 func=tool_dns_recon,
                 description="DNS lookup for a domain. Input: domain name."),
            Tool(name="WebHeaders",
                 func=tool_web_headers,
                 description="Retrieve HTTP headers from a web server. Input: URL."),
        ]

        default_system = (
            f"You are an elite autonomous penetration testing AI (Cortex). "
            f"Your current Operator IP is {self.operator_ip} and the Gateway is {self.gateway_ip}. "
            "You have tools to ping targets, scan ports with Nmap, do DNS recon, "
            "grab web headers, query the mission database, and execute Metasploit exploits. "
            "If the user asks you to scan, ping, check, or exploit — USE YOUR TOOLS. "
            "Return your final answer in clean Markdown format."
        )

        self.agent = initialize_agent(
            tools=tools,
            llm=self.llm,
            agent=AgentType.ZERO_SHOT_REACT_DESCRIPTION,
            verbose=False,
            handle_parsing_errors=True,
            agent_kwargs={
                "system_message": system_override or default_system
            },
        )

    def _auto_detect_ollama(self) -> str:
        target_url = (
            "http://host.docker.internal:11434"
            if os.path.exists("/.dockerenv")
            else "http://127.0.0.1:11434"
        )
        try:
            if requests.get(f"{target_url}/api/tags", timeout=1).status_code == 200:
                return target_url
        except requests.exceptions.RequestException:
            pass
        return target_url

    def check_connection(self) -> bool:
        try:
            return requests.get(f"{self.base_url}/api/tags", timeout=2).status_code == 200
        except Exception:
            return False

    def list_models(self) -> list:
        try:
            r = requests.get(f"{self.base_url}/api/tags", timeout=2)
            if r.status_code == 200:
                return [m.get("name") for m in r.json().get("models", [])]
        except Exception:
            pass
        return []

    def chat(self, user_input: str, override_prompt: str = None):
        """Run a single query through the agent."""
        if override_prompt:
            # Rebuild with a custom system message for this call
            self._build_agent(system_override=override_prompt)

        console.print(
            f"\n[bold cyan]Cortex ({self.model_name}) thinking and deploying tools...[/bold cyan]")
        try:
            with warnings.catch_warnings():
                warnings.simplefilter("ignore")
                result = self.agent.invoke({"input": user_input})

            response = result.get("output", str(result))
            console.print("\n[bold green]Cortex:[/bold green]")
            console.print(response + "\n")

        except Exception as e:
            console.print(
                f"[bold red][!] Agent Execution Error:[/bold red] {e}")


# ─────────────────────────────────────────────────────────────────────────────
#  AIEngine — Backward-compatible alias used by god_mode.py and payloads.py
# ─────────────────────────────────────────────────────────────────────────────

class AIEngine(AutonomousCortex):
    """
    Drop-in alias for AutonomousCortex.
    god_mode.py and payloads.py import AIEngine — this keeps them working
    without any changes to those files.
    """

    def check_connection(self) -> bool:
        return super().check_connection()

    def list_models(self) -> list:
        return super().list_models()

    def chat(self, user_input: str, override_prompt: str = None):
        return super().chat(user_input, override_prompt=override_prompt)


# ─────────────────────────────────────────────────────────────────────────────
#  INTERACTIVE CONSOLE ENTRY POINT
# ─────────────────────────────────────────────────────────────────────────────

def run_ai_console():
    draw_header("AI Cortex (Autonomous Agent)")
    agent = AutonomousCortex()

    if not agent.check_connection():
        console.print(
            f"[bold red][!] Ollama is unreachable at {agent.base_url}[/bold red]")
        console.print("Ensure Ollama is running: [dim]ollama serve[/dim]")
        questionary.press_any_key_to_continue(style=Q_STYLE).ask()
        return

    available_models = agent.list_models()
    if not available_models:
        console.print(
            "[bold red][!] No models found installed in Ollama.[/bold red]")
        console.print("[dim]Pull a model first: ollama pull llama3[/dim]")
        questionary.press_any_key_to_continue(style=Q_STYLE).ask()
        return

    selected_model = questionary.select(
        "Select an Installed AI Model:",
        choices=available_models,
        style=Q_STYLE
    ).ask()

    if not selected_model:
        return

    agent = AutonomousCortex(model=selected_model)

    while True:
        os.system('cls' if os.name == 'nt' else 'clear')
        draw_header(f"Cortex: {selected_model.upper()}")

        console.print(Panel(
            "[bold white]Autonomous Link Active.[/bold white]\n"
            "The AI has access to the [bold cyan]Full Recon & Exploitation Arsenal[/bold cyan]. Try:\n"
            " - [dim]'Can you run an nmap scan on my gateway?'[/dim]\n"
            " - [dim]'Query the database to see what we found.'[/dim]\n"
            " - [dim]'Run a DNS lookup on example.com.'[/dim]\n"
            "Type [bold]exit[/bold] to return.",
            border_style="cyan"
        ))

        while True:
            try:
                q = questionary.text("Operator >", style=Q_STYLE).ask()
                if not q or q.lower() in ["exit", "quit", "back"]:
                    break
                agent.chat(q)
            except KeyboardInterrupt:
                break

        break


if __name__ == "__main__":
    run_ai_console()
