"""
modules/ai_assist.py — Davoid Cortex (Ultimate Autonomous Agent)
Equipped with Nmap (-Pn), Metasploit, DNS Recon, Web Recon, DB Query, and Ping.
"""

import os
import sys
import requests
import questionary
import subprocess
import warnings

from langchain_ollama import ChatOllama
from langchain.agents import initialize_agent, AgentType, Tool
from rich.console import Console
from rich.panel import Panel

from core.ui import draw_header, Q_STYLE
from core.database import db

# --- SILENCE ALL WARNINGS ---
warnings.filterwarnings("ignore")
os.environ["LANGCHAIN_TRACING_V2"] = "false"
warnings.filterwarnings("ignore", category=DeprecationWarning)
warnings.filterwarnings("ignore", message=".*initialize_agent.*")

console = Console()

# ─────────────────────────────────────────────────────────────────────────────
#  ARSENAL: AUTONOMOUS AGENT TOOLS
# ─────────────────────────────────────────────────────────────────────────────

def tool_query_mission_db(query: str = "") -> str:
    try:
        rows = db.get_critical_logs(limit=10)
        if not rows:
            rows = db.get_all()[:10]
        if not rows:
            return "The database is empty. No vulnerabilities found yet."
        result = "Recent Findings:\n"
        for r in rows:
            result += f"- Target: {r.target} | Severity: {r.severity} | Detail: {r.details}\n"
        return result
    except Exception as e:
        return f"Error reading encrypted database: {e}"

def tool_ping_target(target_ip: str) -> str:
    try:
        output = subprocess.check_output(f"ping -c 1 -W 1 {target_ip}", shell=True, stderr=subprocess.STDOUT, timeout=10)
        return f"Target {target_ip} is ONLINE.\n{output.decode('utf-8', errors='ignore')}"
    except subprocess.TimeoutExpired:
        return "Ping timed out."
    except subprocess.CalledProcessError as e:
        return f"Target {target_ip} is OFFLINE or blocking ICMP.\nOutput: {e.output.decode('utf-8', errors='ignore')}"

def tool_nmap_scan(target: str) -> str:
    try:
        output = subprocess.check_output(f"nmap -Pn -F -T3 -n {target}", shell=True, stderr=subprocess.STDOUT, timeout=60)
        return f"Nmap Scan Results for {target}:\n{output.decode('utf-8', errors='ignore')}"
    except subprocess.TimeoutExpired:
        return "Nmap scan timed out. The host might be down or filtering all ports."
    except subprocess.CalledProcessError as e:
        return f"Nmap Scan Partial/Error Results for {target}:\n{e.output.decode('utf-8', errors='ignore')}"
    except Exception as e:
        return f"Nmap scan failed: {e}"

def tool_run_metasploit(commands: str) -> str:
    try:
        if "exit" not in commands:
            commands += "; exit"
        output = subprocess.check_output(
            f"msfconsole -q -x '{commands}'", 
            shell=True, 
            stderr=subprocess.STDOUT,
            timeout=120
        )
        return f"Metasploit Execution Results:\n{output.decode('utf-8', errors='ignore')}"
    except subprocess.TimeoutExpired:
        return "Metasploit execution timed out after 120 seconds."
    except subprocess.CalledProcessError as e:
        return f"Metasploit Execution Results (with errors):\n{e.output.decode('utf-8', errors='ignore')}"
    except Exception as e:
        return f"Metasploit failed: {e}"

def tool_dns_recon(domain: str) -> str:
    try:
        output = subprocess.check_output(f"nslookup {domain}", shell=True, stderr=subprocess.STDOUT, timeout=10)
        return f"DNS Results for {domain}:\n{output.decode('utf-8', errors='ignore')}"
    except subprocess.CalledProcessError as e:
        return f"DNS lookup failed or returned partial results:\n{e.output.decode('utf-8', errors='ignore')}"
    except Exception as e:
        return f"DNS lookup failed: {e}"

def tool_web_headers(url: str) -> str:
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
        
        self.tools = [
            Tool(name="QueryMissionDatabase", func=tool_query_mission_db, description="Use to read the database. Input should be empty."),
            Tool(name="PingTarget", func=tool_ping_target, description="Use to check if an IP address is online. Input MUST be exactly an IP or Domain."),
            Tool(name="NmapPortScan", func=tool_nmap_scan, description="Use to scan a target for open ports. Input MUST be exactly an IP or Subnet (e.g. 192.168.1.0/24). Do not ping before scanning, use this tool directly."),
            Tool(name="RunMetasploit", func=tool_run_metasploit, description="Use to execute Metasploit exploits. Input MUST be exact MSF commands separated by semicolons."),
            Tool(name="DNSRecon", func=tool_dns_recon, description="Use to resolve a domain name to an IP address using DNS. Input MUST be exactly a domain name."),
            Tool(name="WebHeaderGrabber", func=tool_web_headers, description="Use to grab HTTP headers from a web server. Input MUST be exactly a URL.")
        ]
        
        system_instruction = (
            "You are DAVOID CORTEX, an autonomous Red Team AI agent. "
            f"Your current Operator IP is {self.operator_ip} and the Gateway is {self.gateway_ip}. "
            "You have access to tools to ping targets, scan ports with Nmap, do DNS recon, grab web headers, read databases, and FIRE EXPLOITS via Metasploit. "
            "If the user asks you to scan, ping, check a target, or exploit a vulnerability, YOU MUST USE YOUR TOOLS. "
            "Return your final answer in clean Markdown format."
        )

        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            self.agent = initialize_agent(
                tools=self.tools,
                llm=self.llm,
                agent=AgentType.CHAT_ZERO_SHOT_REACT_DESCRIPTION,
                verbose=False,
                handle_parsing_errors=True,
                max_iterations=5,
                early_stopping_method="generate",
                agent_kwargs={
                    "system_message_prefix": system_instruction
                }
            )

    def _auto_detect_ollama(self) -> str:
        if os.path.exists('/.dockerenv'):
            return "http://host.docker.internal:11434"
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
            " - [dim]'Can you run an nmap scan on my gateway?'[/dim]\n"
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