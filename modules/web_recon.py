import requests
import urllib3
import re
import threading
import time
import random
from bs4 import BeautifulSoup
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich.prompt import Confirm
from concurrent.futures import ThreadPoolExecutor, as_completed
from core.ui import draw_header

# Disable SSL warnings for testing environments
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
console = Console()

# Enhanced dictionary of sensitive paths and files
SENSITIVE_PATHS = [
    "/.env", "/.git/config", "/.docker-compose.yml", "/.htaccess", 
    "/backup.sql", "/db.sql", "/config.php", "/config.php.bak",
    "/phpinfo.php", "/admin/", "/login.php", "/wp-admin/", "/.ssh/id_rsa",
    "/server-status", "/robots.txt", "/sitemap.xml", "/api/v1/", "/debug"
]

# Security Headers targeted for compliance audit
SECURITY_HEADERS = {
    "Content-Security-Policy": "Prevents XSS/Injection",
    "Strict-Transport-Security": "Enforces HTTPS (HSTS)",
    "X-Frame-Options": "Prevents Clickjacking",
    "X-Content-Type-Options": "Prevents MIME-sniffing",
    "Referrer-Policy": "Controls Metadata Leakage"
}

# [STEALTH] List of Rotating User-Agents to mimic legitimate traffic
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Mobile/15E148 Safari/604.1"
]

class WebGhost:
    def __init__(self, target, use_tor=True):
        self.target = target.rstrip("/")
        self.session = requests.Session()
        self.session.verify = False
        self.proxies_enabled = False
        
        # [STEALTH] PROXY SUPPORT: Route traffic through Tor (default port 9050)
        if use_tor:
            self.session.proxies = {
                'http': 'socks5h://127.0.0.1:9050',
                'https': 'socks5h://127.0.0.1:9050'
            }
            self.proxies_enabled = True
        
        # [STEALTH] Randomize the initial header
        self.session.headers = {
            "User-Agent": random.choice(USER_AGENTS)
        }

    def audit_headers(self, headers):
        """Analyzes response headers for security gaps."""
        table = Table(title="Security Header Compliance", border_style="bold red", expand=True)
        table.add_column("Header", style="cyan")
        table.add_column("Status", style="white")
        table.add_column("Risk/Purpose", style="dim")

        for header, description in SECURITY_HEADERS.items():
            if header in headers:
                status = "[bold green]PASS[/bold green]"
            else:
                status = "[bold red]MISSING[/bold red]"
            table.add_row(header, status, description)
        return table

    def extract_intel(self, html):
        """Scans HTML source for leaked information (emails, API keys, etc)."""
        intel = []
        # Regex for Emails
        emails = re.findall(r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+', html)
        if emails:
            intel.append(f"[cyan]Emails Found:[/cyan] {', '.join(set(emails[:3]))}")

        # Regex for potential API Keys/Secrets
        api_patterns = [r'(?i)api_key["\']?\s?[:=]\s?["\']?([a-zA-Z0-9_-]{20,})["\']?']
        for p in api_patterns:
            keys = re.findall(p, html)
            if keys:
                intel.append(f"[bold red]Potential API Key Detected![/bold red]")
        
        return intel

    def check_path(self, path):
        """Worker function for concurrent path discovery with Stealth."""
        url = f"{self.target}{path}"
        
        # [STEALTH] Rotate User-Agent for this specific request
        self.session.headers.update({"User-Agent": random.choice(USER_AGENTS)})

        try:
            # [STEALTH] Add jitter delay to break traffic patterns if using proxy
            if self.proxies_enabled:
                time.sleep(random.uniform(0.5, 1.5))
            
            # Increased timeout slightly for Tor latency
            res = self.session.get(url, timeout=10, allow_redirects=False)
            
            if res.status_code == 200:
                return (path, "[bold green]200 OK[/bold green]")
            elif res.status_code == 403:
                return (path, "[yellow]403 Forbidden[/yellow]")
            elif res.status_code == 301 or res.status_code == 302:
                return (path, f"[blue]Redirect ({res.status_code})[/blue]")
        except:
            pass
        return None

    def run(self):
        draw_header("Web Ghost Elite: Professional Auditor")
        
        if self.proxies_enabled:
            console.print("[*] Stealth Mode: [bold green]ON[/bold green] (Attempting Tor Connection...)\n")
            
        console.print(f"[*] Analyzing target: [bold yellow]{self.target}[/bold yellow]\n")
        
        try:
            r = self.session.get(self.target, timeout=10)
        except requests.exceptions.ConnectionError as e:
            # Handle the specific SOCKS connection error
            if "SOCKS" in str(e) or "Connection refused" in str(e):
                console.print("\n[bold red][!] ERROR: Tor Proxy Unreachable (127.0.0.1:9050)[/bold red]")
                console.print("[yellow]It appears Tor is not running. Your connection was refused.[/yellow]")
                
                if Confirm.ask("[bold white]Disable Proxy (Stealth OFF) and continue?[/bold white]"):
                    console.print("\n[red][!] SWITCHING TO CLEARNET. STEALTH DISABLED.[/red]")
                    self.session.proxies = {}
                    self.proxies_enabled = False
                    try:
                        r = self.session.get(self.target, timeout=10)
                    except Exception as e2:
                         console.print(f"[bold red][!] Connection failed even without proxy: {e2}[/bold red]")
                         return
                else:
                    console.print("[dim]Aborting scan...[/dim]")
                    return
            else:
                console.print(f"[bold red][!] Target Connectivity Error: {e}[/bold red]")
                return
        except Exception as e:
            console.print(f"[bold red][!] Unexpected Error: {e}[/bold red]")
            return

        try:
            # 1. Header Audit
            console.print(self.audit_headers(r.headers))

            # 2. Fingerprinting & Intelligence
            soup = BeautifulSoup(r.text, 'html.parser')
            server = r.headers.get("Server", "Undisclosed")
            powered_by = r.headers.get("X-Powered-By", "Unknown")
            title = soup.title.string.strip() if soup.title else "None"
            
            intel_findings = self.extract_intel(r.text)

            intel_panel = Panel(
                f"[white]Title:[/white] {title}\n"
                f"[white]Server:[/white] {server}\n"
                f"[white]Tech:[/white] {powered_by}\n"
                f"[white]Leaks:[/white] {' | '.join(intel_findings) if intel_findings else 'None Detected'}",
                title="Infrastructure Fingerprint",
                border_style="green"
            )
            console.print(intel_panel)

            # 3. Parallel Path Discovery
            discovery_table = Table(title="Sensitive Directory Discovery", border_style="bold green", expand=True)
            discovery_table.add_column("Path", style="cyan")
            discovery_table.add_column("Status", style="white")

            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                console=console
            ) as progress:
                task = progress.add_task("[green]Fuzzing paths...", total=len(SENSITIVE_PATHS))
                
                with ThreadPoolExecutor(max_workers=10) as executor:
                    futures = [executor.submit(self.check_path, p) for p in SENSITIVE_PATHS]
                    for f in as_completed(futures):
                        res = f.result()
                        if res:
                            discovery_table.add_row(res[0], res[1])
                        progress.update(task, advance=1)

            console.print(discovery_table)

        except Exception as e:
            console.print(f"[bold red][!] Audit Error: {e}[/bold red]")
        
        input("\nAudit Complete. Press Enter...")

def web_ghost():
    target = console.input("[bold yellow]Enter Target URL (e.g., https://example.com): [/bold yellow]").strip()
    if target.startswith("http"):
        # Initializing with Stealth enabled by default
        scanner = WebGhost(target, use_tor=True)
        scanner.run()
    else:
        console.print("[red][!] Invalid URL format.[/red]")

if __name__ == "__main__":
    web_ghost()