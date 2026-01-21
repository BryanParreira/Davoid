import requests
import urllib3
import re
import threading
from bs4 import BeautifulSoup
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
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

class WebGhost:
    def __init__(self, target):
        self.target = target.rstrip("/")
        self.session = requests.Session()
        self.session.verify = False
        self.session.headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Davoid-WebAudit/2.0"
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
        """Worker function for concurrent path discovery."""
        url = f"{self.target}{path}"
        try:
            res = self.session.get(url, timeout=3, allow_redirects=False)
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
        
        try:
            console.print(f"[*] Analyzing target: [bold yellow]{self.target}[/bold yellow]\n")
            r = self.session.get(self.target, timeout=5)
            
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

        except requests.exceptions.RequestException as e:
            console.print(f"[bold red][!] Target Connectivity Error: {e}[/bold red]")
        except Exception as e:
            console.print(f"[bold red][!] Audit Error: {e}[/bold red]")
        
        input("\nAudit Complete. Press Enter...")

def web_ghost():
    target = console.input("[bold yellow]Enter Target URL (e.g., https://example.com): [/bold yellow]").strip()
    if target.startswith("http"):
        scanner = WebGhost(target)
        scanner.run()
    else:
        console.print("[red][!] Invalid URL format.[/red]")

if __name__ == "__main__":
    web_ghost()