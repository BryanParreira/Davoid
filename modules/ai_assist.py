"""
modules/ai_assist.py — Davoid Cortex (Ultimate Autonomous Agent)
Equipped with Nmap, Metasploit, DNS Recon, Web Recon, DB Query, and Ping.
"""

import os
import sys
import requests
import questionary
import subprocess
import warnings
from rich.console import Console
from rich.panel import Panel

# --- SILENCE ALL WARNINGS ---
warnings.filterwarnings("ignore")
os.environ["LANGCHAIN_TRACING_V2"] = "false"
warnings.filterwarnings("ignore", category=DeprecationWarning)
warnings.filterwarnings("ignore", message=".*initialize_agent.*")

# Modern Langchain Agent Imports
from langchain_ollama import ChatOllama
from langchain.agents import initialize_agent, AgentType, Tool

from core.ui import draw_header, Q_STYLE
from core.database import db

console = Console()

# ─────────────────────────────────────────────────────────────────────────────
#  ARSENAL: AUTONOMOUS AGENT TOOLS
# ─────────────────────────────────────────────────────────────────────────────

def tool_query_mission_db(query: str = "") -> str:
    """Reads the penetration testing database for previous findings."""
    try:
        # Pull the latest findings using the new Encrypted ORM methods
        rows = db.get_critical_logs(limit=10)
        
        # If no critical logs, just grab the latest general logs
        if not rows:
            rows = db.get_all()[:10]
            
        if not rows:
            return "The database is empty. No vulnerabilities found yet."
            
        result = "Recent Findings:\n"
        for r in rows:
            # Safely access the decrypted data using the LogRow attributes
            result += f"- Target: {r.target} | Severity: {r.severity} | Detail: {r.details}\n"
        return result
    except Exception as e:
        return f"Error reading encrypted database: {e}"

def tool_ping_target(target_ip: str) -> str:
    """Checks if a target is online using ICMP Ping."""
    try:
        output = subprocess.check_output(f"ping -c 1 -W 1 {target_ip}", shell=True, stderr=subprocess.STDOUT)
        return f"Target {target_ip} is ONLINE.\n{output.decode('utf-8')}"
    except subprocess.CalledProcessError:
        return f"Target {target_ip} is OFFLINE or blocking ICMP."

def tool_nmap_scan(target: str) -> str:
    """Runs a fast Nmap port scan on a target."""
    try:
        # Runs a fast (-F), polite (-T3) scan without DNS resolution (-n)
        output = subprocess.check_output(f"nmap -F -T3 -n {target}", shell=True, stderr=subprocess.STDOUT)
        return f"Nmap Scan Results for {target}:\n{output.decode('utf-8')}"
    except Exception as e:
        return f"Nmap scan failed: {e}"

def tool_run_metasploit(commands: str) -> str:
    """Executes a Metasploit exploit autonomously."""
    try:
        if "exit" not in commands:
            commands += "; exit"
        output = subprocess.check_output(
            f"msfconsole -q -x '{commands}'", 
            shell=True, 
            stderr=subprocess.STDOUT,
            timeout=120
        )
        return f"Metasploit Execution Results:\n{output.decode('utf-8')}"
    except subprocess.TimeoutExpired:
        return "Metasploit execution timed out after 120 seconds. Exploit may have failed or required interaction."
    except Exception as e:
        return f"Metasploit failed: {e}"

def tool_dns_recon(domain: str) -> str:
    """Performs DNS lookup on a domain to find IP addresses."""
    try:
        output = subprocess.check_output(f"nslookup {domain}", shell=True, stderr=subprocess.STDOUT)
        return f"DNS Results for {domain}:\n{output.decode('utf-8')}"
    except Exception as e:
        return f"DNS lookup failed: {e}"

def tool_web_headers(url: str) -> str:
    """Grabs HTTP headers from a web server to identify software versions."""
    if not url.startswith("http"):
        url = "http://" + url
    try:
        r = requests.head(url, timeout=5, allow_redirects=True)
        headers_str = "\n".join([f"{k}: {v}" for k, v in r.headers.items()])
        return f"HTTP Headers for {url}:\n{headers_str}"
    except Exception as e:
        return f"Failed to connect to web server: {e}"

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
        
        self.llm = ChatOllama(
            base_url=self.base_url,
            model=self.model_name,
            temperature=0.1, 
        )
        
        self.tools = [
            Tool(name="QueryMissionDatabase", func=tool_query_mission_db, description="Use to see what vulnerabilities or targets have been saved to the database."),
            Tool(name="PingTarget", func=tool_ping_target, description="Use to check if an IP address is online. Input: exactly an IP or Domain."),
            Tool(name="NmapPortScan", func=tool_nmap_scan, description="Use to scan a target for open ports. Input: exactly an IP or Domain or Subnet (e.g. 192.168.1.0/24)."),
            Tool(name="RunMetasploit", func=tool_run_metasploit, description="Use to execute Metasploit exploits. Input must be semi-colon separated msfconsole commands."),
            Tool(name="DNSRecon", func=tool_dns_recon, description="Use to resolve a domain name to an IP address using DNS."),
            Tool(name="WebHeaderGrabber", func=tool_web_headers, description="Use to grab HTTP headers from a web server to find software versions.")
        ]
        
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
                        "You have access to tools to ping targets, scan ports with Nmap, do DNS recon, grab web headers, read databases, and FIRE EXPLOITS via Metasploit. "
                        "If the user asks you to scan, ping, check a target, or exploit a vulnerability, YOU MUST USE YOUR TOOLS. "
                        "Return your final answer in clean Markdown format."
                    )
                }
            )

    def _auto_detect_ollama(self) -> str:
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
        console.print(f"\n[bold cyan]Cortex ({self.model_name}) thinking and deploying tools...[/bold cyan]")
        try:
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
            "The AI now has access to the [bold cyan]Full Recon & Exploitation Arsenal[/bold cyan]. Try asking it:\n"
            " - [dim]'Can you run an nmap scan on 192.168.1.0/24?'[/dim]\n"
            " - [dim]'Can you query the database to see what we found?'[/dim]\n"
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