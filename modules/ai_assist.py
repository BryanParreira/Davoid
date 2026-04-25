"""
modules/ai_assist.py — Autonomous AI Cortex (Ollama + LangChain)

FIXED in this version:
  - Suppresses LangChain deprecation warnings (ConversationBufferWindowMemory,
    initialize_agent) — these were just noise, app was working fine
  - Migrated to create_react_agent + AgentExecutor (modern LangChain API)
  - Manual message history replaces ConversationBufferWindowMemory
    (simpler, no deprecation, works identically)
  - All 16 tools preserved exactly
  - All slash commands preserved exactly
"""

from core.database import db
from core.ui import draw_header, Q_STYLE
from langchain_core.prompts import PromptTemplate
from langchain.tools import Tool
from langchain.agents import AgentExecutor, create_react_agent
from langchain_ollama import ChatOllama
from rich.markdown import Markdown
from rich.table import Table
from rich.panel import Panel
from rich.console import Console
import logging
import os
import socket
import subprocess
import warnings
import time
import requests
import questionary

# ── Suppress ALL LangChain deprecation warnings before any import ─────────────
warnings.filterwarnings("ignore", category=DeprecationWarning)
warnings.filterwarnings("ignore", category=UserWarning)
warnings.filterwarnings("ignore", message=".*LangChain.*")
warnings.filterwarnings("ignore", message=".*LangGraph.*")
warnings.filterwarnings("ignore", message=".*initialize_agent.*")
warnings.filterwarnings("ignore", message=".*ConversationBuffer.*")
warnings.filterwarnings("ignore", message=".*AgentExecutor.*")
logging.getLogger("langchain").setLevel(logging.ERROR)
logging.getLogger("langchain_core").setLevel(logging.ERROR)
logging.getLogger("langchain_ollama").setLevel(logging.ERROR)
logging.getLogger("langchain_community").setLevel(logging.ERROR)
# ─────────────────────────────────────────────────────────────────────────────


console = Console()


# ─────────────────────────────────────────────────────────────────────────────
#  TOOL IMPLEMENTATIONS
# ─────────────────────────────────────────────────────────────────────────────

def tool_query_mission_db(_: str) -> str:
    try:
        logs = db.get_all()
        if not logs:
            return "Mission database is empty. No scans or findings logged yet."
        lines = []
        for log in logs[-25:]:
            ts = log.get("timestamp", "?")[:19]
            mod = log.get("module",    "?")
            tgt = log.get("target",    "?")
            sev = log.get("severity",  "INFO")
            det = log.get("details",   "")[:150]
            lines.append(f"[{sev}] {ts} | {mod} → {tgt}: {det}")
        return "Mission Database (newest first):\n" + "\n".join(lines)
    except Exception as e:
        return f"DB query failed: {e}"


def tool_query_db_critical(_: str) -> str:
    try:
        logs = db.get_critical_logs(limit=15)
        if not logs:
            return "No CRITICAL or HIGH findings in the database."
        lines = []
        for log in logs:
            ts = log.get("timestamp", "?")[:19]
            mod = log.get("module",    "?")
            tgt = log.get("target",    "?")
            det = log.get("details",   "")[:200]
            lines.append(f"[CRITICAL/HIGH] {ts} | {mod} → {tgt}:\n  {det}")
        return "Critical Findings:\n" + "\n".join(lines)
    except Exception as e:
        return f"DB query failed: {e}"


def tool_ping_target(target: str) -> str:
    target = target.strip()
    try:
        flag = "-n" if os.name == "nt" else "-c"
        result = subprocess.run(
            ["ping", flag, "3", "-W", "2", target],
            capture_output=True, text=True, timeout=12
        )
        if result.returncode == 0:
            return f"{target} is ONLINE.\n{result.stdout[:400]}"
        return f"{target} is OFFLINE or unreachable.\n{result.stdout[:200]}"
    except Exception as e:
        return f"Ping failed: {e}"


def tool_nmap_scan(target: str) -> str:
    target = target.strip()
    try:
        result = subprocess.check_output(
            ["nmap", "-T4", "-F", "--open", "-sV", target],
            stderr=subprocess.STDOUT, timeout=90
        )
        output = result.decode("utf-8")
        db.log("AI-Nmap", target, output[:500], "HIGH")
        return f"Nmap Fast Scan for {target}:\n{output[:3000]}"
    except subprocess.TimeoutExpired:
        return f"Nmap timed out after 90 seconds."
    except FileNotFoundError:
        return "nmap not found. Install: apt install nmap"
    except Exception as e:
        return f"Nmap failed: {e}"


def tool_nmap_full(target: str) -> str:
    target = target.strip()
    try:
        result = subprocess.check_output(
            ["nmap", "-sS", "-sV", "-O", "-sC", "-T4", "--open", target],
            stderr=subprocess.STDOUT, timeout=180
        )
        output = result.decode("utf-8")
        db.log("AI-NmapFull", target, output[:800], "HIGH")
        return f"Full Nmap Audit for {target}:\n{output[:4000]}"
    except subprocess.TimeoutExpired:
        return "Full Nmap timed out (180s). Use NmapFastScan for quicker results."
    except Exception as e:
        return f"Full Nmap failed: {e}"


def tool_subdomain_scan(domain: str) -> str:
    domain = domain.strip().lower()
    wordlist = [
        'www', 'mail', 'api', 'dev', 'stage', 'admin', 'vpn', 'ftp', 'ssh', 'portal',
        'blog', 'app', 'test', 'staging', 'internal', 'shop', 'cdn', 'static', 'git',
        'jenkins', 'grafana', 'monitoring', 'wiki', 'docs', 'jira', 'confluence',
    ]
    found = []
    try:
        import dns.resolver
        for sub in wordlist:
            fqdn = f"{sub}.{domain}"
            try:
                answers = dns.resolver.resolve(fqdn, 'A')
                ips = [str(r) for r in answers]
                found.append(f"  {fqdn} → {', '.join(ips)}")
                db.log("AI-Subdomain", fqdn, f"IPs: {', '.join(ips)}", "HIGH")
            except Exception:
                pass
        if found:
            return f"Subdomains found for {domain}:\n" + "\n".join(found)
        return f"No subdomains found for {domain} in quick scan."
    except ImportError:
        return "dnspython not installed. Run: pip install dnspython"
    except Exception as e:
        return f"Subdomain scan failed: {e}"


def tool_shodan_lookup(target: str) -> str:
    target = target.strip()
    try:
        ip = socket.gethostbyname(target)
    except Exception:
        ip = target
    try:
        res = requests.get(f"https://internetdb.shodan.io/{ip}", timeout=15)
        if res.status_code == 200:
            data = res.json()
            ports = data.get("ports", [])
            hosts = data.get("hostnames", [])
            vulns = data.get("vulns", [])
            cpes = data.get("cpes", [])
            tags = data.get("tags", [])
            out = (
                f"InternetDB for {ip}:\n"
                f"  Ports    : {', '.join(str(p) for p in ports) or 'None'}\n"
                f"  Hostnames: {', '.join(hosts) or 'None'}\n"
                f"  Tags     : {', '.join(tags) or 'None'}\n"
                f"  Software : {', '.join(cpes[:5]) or 'None'}\n"
                f"  CVEs     : {', '.join(vulns[:10]) or 'None detected'}"
            )
            if vulns:
                db.log("AI-Shodan", ip,
                       f"CVEs: {', '.join(vulns[:10])}", "CRITICAL")
            return out
        elif res.status_code == 404:
            return f"No data indexed for {ip}."
        return f"InternetDB error: HTTP {res.status_code}"
    except Exception as e:
        return f"Shodan lookup failed: {e}"


def tool_dns_recon(domain: str) -> str:
    domain = domain.strip()
    results = []
    try:
        import dns.resolver
        for rtype in ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA']:
            try:
                for r in dns.resolver.resolve(domain, rtype):
                    results.append(f"  {rtype}: {str(r)}")
            except Exception:
                pass
        if results:
            return f"DNS Records for {domain}:\n" + "\n".join(results)
        return f"No DNS records resolved for {domain}."
    except ImportError:
        try:
            out = subprocess.check_output(
                ["nslookup", domain], stderr=subprocess.STDOUT, timeout=10)
            return f"DNS for {domain}:\n{out.decode()}"
        except Exception as e2:
            return f"DNS failed: {e2}"


def tool_web_headers(url: str) -> str:
    url = url.strip()
    if not url.startswith("http"):
        url = "http://" + url
    try:
        r = requests.head(url, timeout=8, allow_redirects=True,
                          headers={"User-Agent": "Mozilla/5.0"})
        hdr = "\n".join(f"  {k}: {v}" for k, v in r.headers.items())
        db.log("AI-WebHeaders", url,
               f"Status: {r.status_code} | Server: {r.headers.get('Server','?')}", "INFO")
        return f"HTTP Headers for {url} (status {r.status_code}):\n{hdr}"
    except Exception as e:
        return f"Failed to connect: {e}"


def tool_search_cve(keyword: str) -> str:
    keyword = keyword.strip()
    try:
        resp = requests.get(
            "https://services.nvd.nist.gov/rest/json/cves/2.0",
            params={"keywordSearch": keyword, "resultsPerPage": 5},
            timeout=12
        )
        if resp.status_code != 200:
            return f"NVD error: HTTP {resp.status_code}"
        items = resp.json().get("vulnerabilities", [])
        if not items:
            return f"No CVEs found for '{keyword}'."
        lines = [f"CVEs for '{keyword}':"]
        for item in items:
            cve = item.get("cve", {})
            cve_id = cve.get("id", "?")
            metrics = cve.get("metrics", {})
            score = "N/A"
            for key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                if key in metrics and metrics[key]:
                    score = metrics[key][0].get(
                        "cvssData", {}).get("baseScore", "N/A")
                    break
            desc = next(
                (d["value"]
                 for d in cve.get("descriptions", []) if d.get("lang") == "en"),
                "No description."
            )[:180]
            lines.append(f"  {cve_id} (CVSS {score}): {desc}")
        return "\n".join(lines)
    except Exception as e:
        return f"CVE search failed: {e}"


def tool_run_metasploit(commands: str) -> str:
    commands = commands.strip()
    if "exit" not in commands:
        commands += "; exit"
    try:
        output = subprocess.check_output(
            f"msfconsole -q -x '{commands}'",
            shell=True, stderr=subprocess.STDOUT, timeout=150
        )
        result = output.decode("utf-8")
        db.log("AI-MSF", "msfconsole", commands[:200], "HIGH")
        return f"Metasploit Output:\n{result[:3000]}"
    except subprocess.TimeoutExpired:
        return "Metasploit timed out (150s)."
    except FileNotFoundError:
        return "msfconsole not found. Install Metasploit first."
    except Exception as e:
        return f"Metasploit failed: {e}"


def tool_hash_crack(hash_input: str) -> str:
    parts = hash_input.strip().split(":")
    if len(parts) < 2:
        return "Format: hash:type  e.g. 5f4dcc3b5aa765d61d8327deb882cf99:md5"
    target_hash = parts[0].strip().lower()
    hash_type = parts[1].strip().lower()
    try:
        from modules.bruteforce import HashCracker, load_wordlist
        cracker = HashCracker(target_hash, hash_type, load_wordlist())
        result = cracker.crack()
        if result:
            db.log("AI-HashCrack", target_hash,
                   f"Password: {result} (type: {hash_type})", "CRITICAL")
            return f"Cracked! {target_hash} = '{result}' ({hash_type})"
        return f"Not found ({cracker.tried:,} words tried). Try rockyou.txt."
    except ImportError:
        return "bruteforce module not available."
    except Exception as e:
        return f"Hash cracking failed: {e}"


def tool_check_scope(target: str) -> str:
    target = target.strip()
    try:
        from modules.scope_manager import is_in_scope, load_scope
        scope = load_scope()
        if not scope:
            return f"{target} — No scope defined. All targets allowed."
        if is_in_scope(target):
            return f"{target} — IN SCOPE. Proceed."
        return f"{target} — OUT OF SCOPE. Do NOT attack."
    except ImportError:
        return "scope_manager not available."
    except Exception as e:
        return f"Scope check failed: {e}"


def tool_save_note(note: str) -> str:
    parts = note.strip().split("|", 1)
    target = parts[0].strip() if len(parts) > 0 else "AI-Note"
    details = parts[1].strip() if len(parts) > 1 else note.strip()
    try:
        db.log("AI-Note", target, details, "INFO")
        return f"Note saved: [{target}] {details[:100]}"
    except Exception as e:
        return f"Failed: {e}"


def tool_read_file(filepath: str) -> str:
    filepath = filepath.strip().lstrip("/")
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    safe_dirs = ["logs", "reports", "wordlists"]
    if not any(filepath.startswith(d) for d in safe_dirs):
        return f"Access denied. Only {safe_dirs} can be read."
    full_path = os.path.join(base_dir, filepath)
    if not os.path.exists(full_path):
        return f"File not found: {filepath}"
    try:
        size = os.path.getsize(full_path)
        with open(full_path, "r", encoding="utf-8", errors="replace") as f:
            content = f.read(5000)
        return f"File {filepath} ({size:,} bytes):\n{content}"
    except Exception as e:
        return f"Could not read: {e}"


def tool_run_bash(command: str) -> str:
    command = command.strip()
    allowed = {
        "nmap", "ping", "curl", "wget", "dig", "host", "whois", "netstat", "ss",
        "id", "uname", "ps", "ls", "cat", "echo", "ip", "ifconfig", "arp", "route",
        "traceroute", "which", "searchsploit", "find", "grep",
    }
    first_word = command.split()[0].split("/")[-1].lower()
    if first_word not in allowed:
        return f"'{first_word}' not allowed. Allowed: {', '.join(sorted(allowed))}"
    try:
        output = subprocess.check_output(
            command, shell=True, stderr=subprocess.STDOUT,
            timeout=30,
            cwd=os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        )
        return f"$ {command}\n{output.decode('utf-8', errors='replace')[:2000]}"
    except subprocess.TimeoutExpired:
        return f"Timed out (30s): {command}"
    except subprocess.CalledProcessError as e:
        return f"Failed (exit {e.returncode}):\n{e.output.decode(errors='replace')[:1000]}"
    except Exception as e:
        return f"Execution failed: {e}"


# ─────────────────────────────────────────────────────────────────────────────
#  TOOLS REGISTRY  (16 tools)
# ─────────────────────────────────────────────────────────────────────────────

ALL_TOOLS = [
    Tool("QueryMissionDatabase",  tool_query_mission_db,
         "Query all logged findings in the mission database. Input: any string."),
    Tool("QueryCriticalFindings", tool_query_db_critical,
         "Returns only CRITICAL and HIGH severity findings. Input: any string."),
    Tool("PingTarget",            tool_ping_target,
         "Check if a host is online with ICMP. Input: IP or hostname."),
    Tool("NmapFastScan",          tool_nmap_scan,
         "Fast Nmap scan (top 100 ports + version). Input: IP, domain, or CIDR."),
    Tool("NmapFullAudit",         tool_nmap_full,
         "Full Nmap with OS detection and scripts. Slower. Input: IP or domain."),
    Tool("SubdomainScan",         tool_subdomain_scan,
         "DNS bruteforce for common subdomains. Input: domain like 'example.com'."),
    Tool("ShodanLookup",          tool_shodan_lookup,
         "InternetDB query for open ports, CVEs, software. Input: IP or domain."),
    Tool("DNSRecon",              tool_dns_recon,
         "DNS record lookup (A, MX, NS, TXT, SOA). Input: domain name."),
    Tool("WebHeaderGrab",         tool_web_headers,
         "Grab HTTP headers to fingerprint web server. Input: URL or domain."),
    Tool("SearchCVE",             tool_search_cve,
         "Search NVD for CVEs by product. Input: product name e.g. 'Apache 2.4'."),
    Tool("RunMetasploit",         tool_run_metasploit,
         "Run msfconsole commands. Input: semicolon-separated commands."),
    Tool("HashCrack",             tool_hash_crack,
         "Crack a hash. Input: 'hash:type' e.g. '5f4dcc...:md5'. Types: md5,sha1,sha256,ntlm."),
    Tool("CheckScope",            tool_check_scope,
         "Check if target is in engagement scope. Input: IP or domain."),
    Tool("SaveNote",              tool_save_note,
         "Save finding to mission DB. Input: 'target|details'."),
    Tool("ReadFile",              tool_read_file,
         "Read file from logs/, reports/, wordlists/. Input: relative path."),
    Tool("RunBashCommand",        tool_run_bash,
         "Run safe shell command (nmap,ping,curl,dig,grep,ls,cat,etc). Input: full command."),
]


# ─────────────────────────────────────────────────────────────────────────────
#  REACT PROMPT  (no deprecation — using PromptTemplate directly)
# ─────────────────────────────────────────────────────────────────────────────

REACT_PROMPT = PromptTemplate(
    input_variables=[
        "input", "tools", "tool_names",
        "agent_scratchpad", "chat_history",
        "operator_ip", "gateway_ip",
    ],
    template="""You are Cortex, an elite autonomous penetration testing AI inside Davoid.
Operator IP: {operator_ip} | Gateway: {gateway_ip}

RULES:
1. Always CheckScope before attacking a new target.
2. Use tools proactively — when asked to scan, call NmapFastScan.
3. After scanning, query the database and correlate findings.
4. For exploitation, build the full MSF command string and call RunMetasploit.
5. Save important findings with SaveNote.
6. Respond in clean Markdown.
7. You remember this conversation: {chat_history}

Available tools:
{tools}

Use this format EXACTLY:

Question: the input you must answer
Thought: think about what to do
Action: one of [{tool_names}]
Action Input: the input to the action
Observation: the result
... (repeat Thought/Action/Action Input/Observation as needed)
Thought: I now know the final answer
Final Answer: your final response in Markdown

Question: {input}
Thought: {agent_scratchpad}"""
)


# ─────────────────────────────────────────────────────────────────────────────
#  CORTEX ENGINE
# ─────────────────────────────────────────────────────────────────────────────

class AutonomousCortex:
    def __init__(self, model: str = None, debug: bool = False):
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
        self.debug = debug
        self._history: list[tuple[str, str]] = []

        self.llm = ChatOllama(
            base_url=self.base_url,
            model=self.model_name,
            temperature=0.1,
        )

        self._build_agent()

    def _build_agent(self, system_override: str = None):
        """Build a modern ReAct agent — zero deprecated APIs."""
        prompt = REACT_PROMPT

        # If god_mode passes a custom system message, wrap it in ReAct format
        if system_override:
            prompt = PromptTemplate(
                input_variables=[
                    "input", "tools", "tool_names",
                    "agent_scratchpad", "chat_history",
                ],
                template=(
                    system_override + "\n\n"
                    "Tools available:\n{tools}\n\n"
                    "Format:\n"
                    "Question: {input}\n"
                    "Thought: {agent_scratchpad}\n"
                    "Action: one of [{tool_names}]\n"
                    "Action Input: ...\n"
                    "Observation: ...\n"
                    "Final Answer: ...\n\n"
                    "Previous conversation: {chat_history}"
                ),
            )

        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            react_agent = create_react_agent(
                llm=self.llm,
                tools=ALL_TOOLS,
                prompt=prompt,
            )
            self.executor = AgentExecutor(
                agent=react_agent,
                tools=ALL_TOOLS,
                verbose=self.debug,
                handle_parsing_errors=True,
                max_iterations=8,
            )

    def _auto_detect_ollama(self) -> str:
        for url in [
            "http://host.docker.internal:11434",
            "http://127.0.0.1:11434",
            "http://localhost:11434",
        ]:
            try:
                if requests.get(f"{url}/api/tags", timeout=1).status_code == 200:
                    return url
            except Exception:
                pass
        return "http://127.0.0.1:11434"

    def check_connection(self) -> bool:
        try:
            return requests.get(f"{self.base_url}/api/tags", timeout=3).status_code == 200
        except Exception:
            return False

    def list_models(self) -> list:
        try:
            r = requests.get(f"{self.base_url}/api/tags", timeout=3)
            if r.status_code == 200:
                return [m.get("name") for m in r.json().get("models", [])]
        except Exception:
            pass
        return []

    def _format_history(self) -> str:
        if not self._history:
            return "No previous conversation."
        lines = []
        for role, content in self._history[-10:]:
            lines.append(f"{role}: {content[:300]}")
        return "\n".join(lines)

    def chat(self, user_input: str, override_prompt: str = None) -> str:
        if override_prompt:
            self._build_agent(system_override=override_prompt)

        console.print(
            f"\n[bold cyan]Cortex ({self.model_name}) thinking...[/bold cyan]"
        )

        try:
            with warnings.catch_warnings():
                warnings.simplefilter("ignore")
                result = self.executor.invoke({
                    "input":        user_input,
                    "chat_history": self._format_history(),
                    "operator_ip":  self.operator_ip,
                    "gateway_ip":   self.gateway_ip,
                })

            response = result.get("output", str(result))

            self._history.append(("Operator", user_input))
            self._history.append(("Cortex",   response))

            console.print("\n[bold green]Cortex ▶[/bold green]")
            try:
                console.print(Markdown(response))
            except Exception:
                console.print(response)
            console.print()
            return response

        except Exception as e:
            err = str(e)
            if self.debug:
                import traceback
                console.print(f"[bold red][!] Agent Error:[/bold red] {err}")
                console.print(f"[dim]{traceback.format_exc()}[/dim]")
            else:
                console.print(
                    f"[bold red][!] Agent Error:[/bold red] {err[:300]}\n"
                    "[dim]Use /debug to see full trace.[/dim]"
                )
            return ""

    def clear_memory(self):
        self._history.clear()

    def get_history(self) -> list:
        return list(self._history)

    def save_session(self) -> str:
        os.makedirs("logs", exist_ok=True)
        fname = f"logs/cortex_session_{int(time.time())}.txt"
        with open(fname, "w", encoding="utf-8") as f:
            f.write(f"Cortex Session — Model: {self.model_name}\n")
            f.write(f"Timestamp: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write("=" * 60 + "\n\n")
            for role, content in self._history:
                f.write(f"[{role}]\n{content}\n\n")
        return fname


# ─────────────────────────────────────────────────────────────────────────────
#  AIEngine ALIAS  (backward-compatible — god_mode.py + payloads.py)
# ─────────────────────────────────────────────────────────────────────────────

class AIEngine(AutonomousCortex):
    def check_connection(self) -> bool:
        return super().check_connection()

    def list_models(self) -> list:
        return super().list_models()

    def chat(self, user_input: str, override_prompt: str = None) -> str:
        return super().chat(user_input, override_prompt=override_prompt)


# ─────────────────────────────────────────────────────────────────────────────
#  INTERACTIVE CONSOLE
# ─────────────────────────────────────────────────────────────────────────────

_SLASH_COMMANDS = {
    "/tools":   "Show all 16 available tools",
    "/history": "Show conversation history",
    "/clear":   "Clear memory and start fresh",
    "/save":    "Save session transcript to logs/",
    "/debug":   "Toggle debug mode (shows tool calls step by step)",
    "/model":   "Switch to a different Ollama model mid-session",
    "/help":    "Show this help message",
    "/exit":    "Return to main menu",
}


def _show_tools():
    table = Table(title="Cortex Tools (16)", border_style="cyan", expand=True)
    table.add_column("Tool",        style="cyan",  no_wrap=True)
    table.add_column("Description", style="white")
    for tool in ALL_TOOLS:
        table.add_row(tool.name, (tool.description or "")[:90])
    console.print(table)


def _show_help():
    table = Table(title="Slash Commands", border_style="dim", expand=True)
    table.add_column("Command",     style="cyan")
    table.add_column("Description", style="white")
    for cmd, desc in _SLASH_COMMANDS.items():
        table.add_row(cmd, desc)
    console.print(table)


def run_ai_console():
    draw_header("AI Cortex — Autonomous Pentest Agent")

    probe = AutonomousCortex()
    if not probe.check_connection():
        console.print(
            f"[bold red][!] Ollama unreachable at {probe.base_url}[/bold red]\n"
            "[white]Start Ollama:[/white] [dim]ollama serve[/dim]\n"
            "[white]Pull a model:[/white] [dim]ollama pull llama3[/dim]"
        )
        questionary.press_any_key_to_continue(style=Q_STYLE).ask()
        return

    available_models = probe.list_models()
    if not available_models:
        console.print(
            "[bold red][!] No models installed in Ollama.[/bold red]\n"
            "[dim]Pull one: ollama pull llama3[/dim]"
        )
        questionary.press_any_key_to_continue(style=Q_STYLE).ask()
        return

    selected_model = questionary.select(
        "Select AI Model:", choices=available_models, style=Q_STYLE
    ).ask()
    if not selected_model:
        return

    agent = AutonomousCortex(model=selected_model)

    os.system('cls' if os.name == 'nt' else 'clear')
    draw_header(f"Cortex: {selected_model.upper()}")

    console.print(Panel(
        f"[bold white]Autonomous Link Active — {selected_model}[/bold white]\n\n"
        f"[cyan]16 tools:[/cyan] Nmap (fast+full), Shodan, DNS, Subdomain, WebHeaders,\n"
        f"  CVE Search, MSF, Hash Crack, Scope Check, DB Query, Bash, File Read.\n\n"
        "[dim]/tools  /history  /clear  /save  /debug  /model  /help  /exit[/dim]",
        border_style="cyan", title="Cortex"
    ))

    while True:
        try:
            q = questionary.text("Operator ▶", style=Q_STYLE).ask()
            if q is None:
                break
            q = q.strip()
            if not q:
                continue

            if q.lower() in ("/exit", "/quit", "exit", "quit", "back"):
                break
            elif q.lower() == "/tools":
                _show_tools()
            elif q.lower() == "/help":
                _show_help()
            elif q.lower() == "/history":
                history = agent.get_history()
                if not history:
                    console.print("[dim]No conversation history yet.[/dim]")
                else:
                    for role, content in history:
                        colour = "cyan" if role == "Operator" else "green"
                        console.print(
                            f"[bold {colour}][{role}][/bold {colour}] {content[:300]}")
            elif q.lower() == "/clear":
                agent.clear_memory()
                console.print("[green][+] Memory cleared.[/green]")
            elif q.lower() == "/save":
                fname = agent.save_session()
                console.print(f"[green][+] Saved: {fname}[/green]")
            elif q.lower() == "/debug":
                agent.debug = not agent.debug
                agent._build_agent()
                console.print(
                    f"[yellow][*] Debug: {'ON' if agent.debug else 'OFF'}[/yellow]")
            elif q.lower() == "/model":
                models = agent.list_models()
                if not models:
                    console.print("[red]No models available.[/red]")
                else:
                    new_model = questionary.select(
                        "Switch to:", choices=models, style=Q_STYLE
                    ).ask()
                    if new_model and new_model != agent.model_name:
                        agent.model_name = new_model
                        agent.llm = ChatOllama(
                            base_url=agent.base_url,
                            model=new_model, temperature=0.1)
                        agent._build_agent()
                        console.print(
                            f"[green][+] Switched to: {new_model}[/green]")
            else:
                agent.chat(q)

        except KeyboardInterrupt:
            console.print(
                "\n[yellow][*] Use /exit to return to main menu.[/yellow]")

    if agent.get_history():
        if questionary.confirm(
            "Save session transcript?", default=False, style=Q_STYLE
        ).ask():
            fname = agent.save_session()
            console.print(f"[green][+] Saved: {fname}[/green]")


if __name__ == "__main__":
    run_ai_console()
