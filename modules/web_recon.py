import requests
import urllib3
import re
import time
import random
import questionary
from bs4 import BeautifulSoup
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from concurrent.futures import ThreadPoolExecutor, as_completed
from core.ui import draw_header, Q_STYLE
from core.database import db

# Only disable warnings if verify_ssl is intentionally turned off
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
console = Console()

# Extremely targeted list of high-impact infrastructure leaks
CRITICAL_PATHS = [
    "/.env", "/.env.backup", "/.env.dev", "/.git/config", 
    "/.docker-compose.yml", "/docker-compose.yml", "/Dockerfile",
    "/.aws/credentials", "/.ssh/id_rsa", "/.ssh/authorized_keys",
    "/config.php", "/wp-config.php.bak", "/database.yml", 
    "/server-status", "/phpinfo.php", "/api/v1/swagger.json",
    "/actuator/env", "/actuator/health", "/backup.sql"
]

SECURITY_HEADERS = {
    "Content-Security-Policy": "Prevents XSS/Injection",
    "Strict-Transport-Security": "Enforces HTTPS (HSTS)",
    "X-Frame-Options": "Prevents Clickjacking",
    "X-Content-Type-Options": "Prevents MIME-sniffing"
}

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0"
]

class WebGhost:
    def __init__(self, target, use_tor=True, verify_ssl=True):
        self.target = target.rstrip("/")
        self.session = requests.Session()
        self.session.verify = verify_ssl
        self.proxies_enabled = False

        if use_tor:
            self.session.proxies = {
                'http': 'socks5h://127.0.0.1:9050',
                'https': 'socks5h://127.0.0.1:9050'
            }
            self.proxies_enabled = True

        self.session.headers = {"User-Agent": random.choice(USER_AGENTS)}

    def audit_headers(self, headers):
        table = Table(title="Security Header Compliance", border_style="bold red", expand=True)
        table.add_column("Header", style="cyan")
        table.add_column("Status", style="white")
        table.add_column("Risk/Purpose", style="dim")

        for header, description in SECURITY_HEADERS.items():
            if header in headers:
                status = "[bold green]PASS[/bold green]"
            else:
                status = "[bold red]MISSING[/bold red]"
                db.log("Web-Ghost", self.target, f"Missing Security Header: {header}", "INFO")
            table.add_row(header, status, description)
        return table

    def check_path(self, path):
        url = f"{self.target}{path}"
        self.session.headers.update({"User-Agent": random.choice(USER_AGENTS)})

        try:
            if self.proxies_enabled:
                time.sleep(random.uniform(0.5, 1.2))

            res = self.session.get(url, timeout=10, allow_redirects=False)

            if res.status_code == 200:
                # Basic check to avoid false positive 200s (e.g. custom 404 pages)
                if "404" not in res.text and "not found" not in res.text.lower():
                    db.log("Web-Ghost", url, f"Exposed Infrastructure File Found: {path}", "CRITICAL")
                    return (path, "[bold green]200 OK (EXPOSED)[/bold green]")
            elif res.status_code == 403:
                return (path, "[yellow]403 Forbidden (Exists)[/yellow]")
        except:
            pass
        return None

    def run(self):
        draw_header("Web Ghost: Infrastructure Leak Hunter")

        if self.proxies_enabled:
            console.print("[*] Stealth Mode: [bold green]ON[/bold green] (Routing through Tor...)\n")

        console.print(f"[*] Analyzing target: [bold yellow]{self.target}[/bold yellow]\n")

        try:
            r = self.session.get(self.target, timeout=10)
        except requests.exceptions.SSLError:
            console.print("\n[bold red][!] ERROR: SSL Certificate Verification Failed.[/bold red]")
            console.print("[yellow]If you trust this target, restart Web Ghost and select 'No' to Verify SSL.[/yellow]")
            return
        except requests.exceptions.ConnectionError as e:
            if "SOCKS" in str(e) or "Connection refused" in str(e):
                console.print("\n[bold red][!] ERROR: Tor Proxy Unreachable (127.0.0.1:9050)[/bold red]")
                if questionary.confirm("Disable Proxy (Stealth OFF) and continue on Clearnet?", default=True, style=Q_STYLE).ask():
                    self.session.proxies = {}
                    self.proxies_enabled = False
                    try:
                        r = self.session.get(self.target, timeout=10)
                    except Exception as e2:
                        console.print(f"[bold red][!] Connection failed: {e2}[/bold red]")
                        return
                else:
                    return
            else:
                console.print(f"[bold red][!] Target Connectivity Error: {e}[/bold red]")
                return
        except Exception as e:
            console.print(f"[bold red][!] Unexpected Error: {e}[/bold red]")
            return

        try:
            console.print(self.audit_headers(r.headers))

            server = r.headers.get("Server", "Undisclosed")
            powered_by = r.headers.get("X-Powered-By", "Unknown")
            console.print(Panel(
                f"[white]Server:[/white] {server}\n"
                f"[white]Tech:[/white] {powered_by}",
                title="Infrastructure Fingerprint", border_style="green"
            ))

            discovery_table = Table(title="Critical Infrastructure Discovery", border_style="bold green", expand=True)
            discovery_table.add_column("Path", style="cyan")
            discovery_table.add_column("Status", style="white")

            with Progress(SpinnerColumn(), TextColumn("{task.description}"), BarColumn(), console=console) as progress:
                task = progress.add_task("[green]Hunting for exposed configs...", total=len(CRITICAL_PATHS))

                with ThreadPoolExecutor(max_workers=10) as executor:
                    futures = [executor.submit(self.check_path, p) for p in CRITICAL_PATHS]
                    for f in as_completed(futures):
                        res = f.result()
                        if res:
                            discovery_table.add_row(res[0], res[1])
                        progress.update(task, advance=1)

            console.print(discovery_table)

        except Exception as e:
            console.print(f"[bold red][!] Audit Error: {e}[/bold red]")

        questionary.press_any_key_to_continue(style=Q_STYLE).ask()

def web_ghost():
    target = questionary.text("Target URL (e.g., https://example.com):", style=Q_STYLE).ask()
    if target and target.startswith("http"):
        verify_cert = questionary.confirm("Verify SSL Certificates?", default=True, style=Q_STYLE).ask()
        scanner = WebGhost(target, use_tor=True, verify_ssl=verify_cert)
        scanner.run()
    else:
        console.print("[red][!] Invalid URL format. Must include http/https.[/red]")

if __name__ == "__main__":
    web_ghost()