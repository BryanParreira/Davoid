"""
modules/ai_assist.py — Davoid Cortex (Ultimate Autonomous Agent)
Equipped with Nmap (-Pn), Metasploit, Subdomain Recon, Shodan, Web Recon, DB Query, and Ping.
"""

import os
import sys
import requests
import questionary
import subprocess
import warnings
import shlex

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
#  ARSENAL: AUTONOMOUS AGENT TOOLS (Hardened & HITL Secured)
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
        output = subprocess.check_output(
            ["ping", "-c", "1", "-W", "1", target_ip.strip()], 
            stderr=subprocess.STDOUT, 
            timeout=10
        )
        return f"Target {target_ip} is ONLINE.\n{output.decode('utf-8', errors='ignore')}"
    except subprocess.TimeoutExpired:
        return "Ping timed out."
    except subprocess.CalledProcessError as e:
        return f"Target {target_ip} is OFFLINE or blocking ICMP.\nOutput: {e.output.decode('utf-8', errors='ignore')}"
    except Exception as e:
        return f"Ping failed: {e}"

def tool_nmap_scan(target: str) -> str:
    target = target.strip()
    
    # [HITL] Operator Gate & Parameter Selection
    console.print(Panel(f"[bold yellow]Cortex is requesting an NMAP scan on: {target}[/bold yellow]", border_style="yellow"))
    profile = questionary.select(
        "Authorize and select scan profile:",
        choices=[
            "1. Quick Scan (-F -T4)",
            "2. Standard Scan (-sS -T4)",
            "3. Full Audit (-sS -sV -sC -p- -T4)",
            "Cancel / Deny Authorization"
        ],
        style=Q_STYLE
    ).ask()

    if not profile or "Cancel" in profile:
        console.print("[yellow][-] Scan denied by operator.[/yellow]")
        return "Operator denied the Nmap scan. Do not attempt to scan this target again unless asked."

    if "Quick" in profile:
        args = ["-Pn", "-F", "-T4", "--open"]
    elif "Standard" in profile:
        args = ["-Pn", "-sS", "-T4", "--open"]
    elif "Full" in profile:
        args = ["-Pn", "-sS", "-sV", "-sC", "-p-", "-T4", "--open"]
    else:
        args = ["-Pn", "-F", "-T4", "--open"]

    try:
        cmd = ["nmap"] + args + [target]
        output = subprocess.check_output(cmd, stderr=subprocess.STDOUT, timeout=120)
        return f"Nmap Scan Results for {target}:\n{output.decode('utf-8', errors='ignore')}"
    except subprocess.TimeoutExpired:
        return "Nmap scan timed out. The host might be down or filtering all ports."
    except subprocess.CalledProcessError as e:
        return f"Nmap Scan Partial/Error Results for {target}:\n{e.output.decode('utf-8', errors='ignore')}"
    except Exception as e:
        return f"Nmap scan failed: {e}"

def tool_shodan_lookup(ip: str) -> str:
    """Uses the free InternetDB API (Shodan tier) to find open ports and CVEs."""
    try:
        res = requests.get(f"https://internetdb.shodan.io/{ip.strip()}", timeout=10)
        if res.status_code == 200:
            data = res.json()
            return f"Shodan Data for {ip}:\nHostnames: {data.get('hostnames')}\nPorts: {data.get('ports')}\nCVEs: {data.get('vulns')}"
        return f"No Shodan data found for {ip}"
    except Exception as e:
        return f"Shodan lookup failed: {e}"

def tool_subdomain_recon(domain: str) -> str:
    """Quickly pulls passive subdomains using crt.sh"""
    domain = domain.strip()
    try:
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        res = requests.get(url, timeout=15)
        if res.status_code == 200:
            raw = set()
            for entry in res.json():
                for sub in entry.get('name_value', '').split('\n'):
                    if not sub.startswith('*') and domain in sub:
                        raw.add(sub.strip().lower())
            return f"Passive subdomains discovered for {domain}:\n" + "\n".join(f"- {sub}" for sub in list(raw)[:20])
        return "Subdomain lookup failed: non-200 status code."
    except Exception as e:
        return f"Subdomain lookup failed: {e}"

def tool_dns_recon(domain: str) -> str:
    try:
        output = subprocess.check_output(
            ["nslookup", domain.strip()], 
            stderr=subprocess.STDOUT, 
            timeout=10
        )
        return f"DNS Results for {domain}:\n{output.decode('utf-8', errors='ignore')}"
    except subprocess.CalledProcessError as e:
        return f"DNS lookup failed or returned partial results:\n{e.output.decode('utf-8', errors='ignore')}"
    except Exception as e:
        return f"DNS lookup failed: {e}"

def tool_web_headers(url: str) -> str:
    url = url.strip()
    if not url.startswith("http"):
        url = "http://" + url
    try:
        r = requests.head(url, timeout=5, allow_redirects=True)
        headers_str = "\n".join([f"- **{k}**: {v}" for k, v in r.headers.items()])
        return f"HTTP Headers for {url}:\n{headers_str}"
    except Exception as e:
        return f"Failed to connect to web server: {e}"

def tool_run_metasploit(commands: str) -> str:
    commands = commands.strip()
    
    # [HITL] Operator Gate for Exploitation
    console.print(Panel(f"[bold red]Cortex is attempting to execute Metasploit payload:[/bold red]\n[dim]{commands}[/dim]", border_style="red"))
    confirm = questionary.confirm("Authorize this exploit execution?", default=False, style=Q_STYLE).ask()
    
    if not confirm:
        console.print("[yellow][-] Exploit execution denied by operator.[/yellow]")
        return "Operator explicitly denied the Metasploit execution. Do not attempt this exploit again."

    try:
        if "exit" not in commands:
            commands += "; exit"
        output = subprocess.check_output(
            ["msfconsole", "-q", "-x", commands], 
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
            Tool(name="PingTarget", func=tool_ping_target, description="Check if an IP address is online. Input MUST be exactly an IP or Domain."),
            Tool(name="NmapPortScan", func=tool_nmap_scan, description="Scan a target for open ports. The system will prompt the human operator for the scan profile. Input MUST be exactly an IP or Subnet (e.g. 192.168.1.0/24)."),
            Tool(name="ShodanIntel", func=tool_shodan_lookup, description="Lookup open ports and CVEs for an IP without scanning it actively. Input MUST be an IP."),
            Tool(name="SubdomainRecon", func=tool_subdomain_recon, description="Find subdomains for a target domain. Input MUST be exactly a domain name (e.g. example.com)."),
            Tool(name="DNSRecon", func=tool_dns_recon, description="Resolve a domain name to an IP address using DNS. Input MUST be exactly a domain name."),
            Tool(name="WebHeaderGrabber", func=tool_web_headers, description="Grab HTTP headers from a web server. Input MUST be exactly a URL."),
            Tool(name="RunMetasploit", func=tool_run_metasploit, description="Execute Metasploit exploits. The system will prompt the human operator for authorization before executing. Input MUST be exact MSF commands separated by semicolons.")
        ]
        
        system_instruction = (
            "You are DAVOID CORTEX, an elite autonomous Red Team AI agent. "
            f"Your current Operator IP is {self.operator_ip} and the Gateway is {self.gateway_ip}. "
            "You have tools to Ping, Nmap scan, Shodan lookup, find Subdomains, do DNS recon, grab Web Headers, query databases, and FIRE EXPLOITS via Metasploit. "
            "You MUST use your tools to complete the operator's requests. "
            "If a tool (like Metasploit) returns an error, state that the specific exploit failed or module was not found. DO NOT claim the tool itself is missing. "
            "\n\n======================================================\n"
            "CRITICAL OUTPUT FORMATTING (YOU MUST OBEY THESE RULES):\n"
            "======================================================\n"
            "1. You MUST ALWAYS start your final response with exactly: 'Final Answer: '\n"
            "2. NEVER summarize open ports into a paragraph. If you use Nmap or Shodan, you MUST output a strict Markdown table with columns: | Port | State | Service | Version |\n"
            "3. If you use Metasploit, output an 'Action Report' block detailing what was executed and the result.\n"
            "4. ALWAYS conclude your response with a '**Tactical Analysis:**' section suggesting the next attack vector.\n"
            "Failure to follow this exact formatting will compromise the mission."
        )

        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            self.agent = initialize_agent(
                tools=self.tools,
                llm=self.llm,
                agent=AgentType.CHAT_ZERO_SHOT_REACT_DESCRIPTION,
                verbose=False,
                handle_parsing_errors="Check your output and make sure it conforms to the Action/Action Input format!",
                max_iterations=7, 
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

    def chat(self, user_input: str, override_prompt: str = None):
        console.print(f"\n[bold cyan]Cortex ({self.model_name}) thinking and deploying tools...[/bold cyan]")
        try:
            if override_prompt:
                with warnings.catch_warnings():
                    warnings.simplefilter("ignore")
                    agent_override = initialize_agent(
                        tools=self.tools,
                        llm=self.llm,
                        agent=AgentType.CHAT_ZERO_SHOT_REACT_DESCRIPTION,
                        verbose=False,
                        handle_parsing_errors=True,
                        max_iterations=7,
                        early_stopping_method="generate",
                        agent_kwargs={"system_message_prefix": override_prompt}
                    )
                    result = agent_override.invoke({"input": user_input})
            else:
                with warnings.catch_warnings():
                    warnings.simplefilter("ignore")
                    result = self.agent.invoke({"input": user_input})
            
            response = result.get("output", str(result))
            console.print("\n[bold green]Cortex:[/bold green]")
            console.print(response + "\n")
            
        except Exception as e:
            error_str = str(e)
            # If the LLM did the work but forgot "Final Answer: ", we catch it and print the output perfectly anyway.
            if "Could not parse LLM output:" in error_str:
                raw_output = error_str.split("Could not parse LLM output:")[1].strip()
                
                # Clean up any trailing backticks or LangChain troubleshooting links
                raw_output = raw_output.replace("`", "")
                if "For troubleshooting, visit:" in raw_output:
                    raw_output = raw_output.split("For troubleshooting, visit:")[0].strip()
                
                console.print("\n[bold green]Cortex:[/bold green]")
                console.print(raw_output + "\n")
            else:
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
            " - [dim]'Can you find subdomains for example.com, scan the first one with Nmap, and check Shodan?'[/dim]\n"
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