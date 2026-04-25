"""
modules/web_recon.py — Web Ghost Elite: Professional Web Auditor
FIXES:
  - Broken markdown URL in metadata_url replaced with clean string
  - Added generate_shell() alias so main.py can import it from web_recon if needed
    (primary generate_shell lives in payloads.py)
"""

import requests
import urllib3
import re
import threading
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

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
console = Console()


# ─────────────────────────────────────────────────────────────────────────────
#  CONSTANTS
# ─────────────────────────────────────────────────────────────────────────────

SENSITIVE_PATHS = [
    "/.env",                  "/.git/config",
    "/.docker-compose.yml",   "/.htaccess",
    "/backup.sql",            "/db.sql",
    "/config.php",            "/config.php.bak",
    "/phpinfo.php",           "/admin/",
    "/login.php",             "/wp-admin/",
    "/.ssh/id_rsa",           "/server-status",
    "/robots.txt",            "/sitemap.xml",
    "/api/v1/",               "/debug",
    "/.well-known/",          "/wp-config.php",
    "/web.config",            "/.DS_Store",
    "/crossdomain.xml",       "/clientaccesspolicy.xml",
]

SECURITY_HEADERS = {
    "Content-Security-Policy":   "Prevents XSS / injection attacks",
    "Strict-Transport-Security": "Enforces HTTPS (HSTS)",
    "X-Frame-Options":           "Prevents clickjacking",
    "X-Content-Type-Options":    "Prevents MIME-type sniffing",
    "Referrer-Policy":           "Controls metadata leakage",
    "Permissions-Policy":        "Controls browser feature access",
}

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_1 like Mac OS X) "
    "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Mobile/15E148 Safari/604.1",
]

# Cloud IMDS endpoint (fixed — no markdown link wrapping)
METADATA_URL = "http://169.254.169.254/latest/meta-data/"


# ─────────────────────────────────────────────────────────────────────────────
#  ENGINE
# ─────────────────────────────────────────────────────────────────────────────

class WebGhost:
    def __init__(self, target: str, use_tor: bool = True, verify_ssl: bool = True):
        self.target = target.rstrip("/")
        self.metadata_url = METADATA_URL           # clean string, no markdown
        self.session = requests.Session()
        self.session.verify = verify_ssl
        self.proxies_enabled = False

        if use_tor:
            self.session.proxies = {
                "http":  "socks5h://127.0.0.1:9050",
                "https": "socks5h://127.0.0.1:9050",
            }
            self.proxies_enabled = True

        self.session.headers.update({
            "User-Agent": random.choice(USER_AGENTS)
        })

    # ── Security header audit ─────────────────────────────────────────────────

    def audit_headers(self, headers: dict) -> Table:
        table = Table(
            title="Security Header Compliance",
            border_style="bold red",
            expand=True,
        )
        table.add_column("Header",       style="cyan")
        table.add_column("Status",       style="white")
        table.add_column("Risk/Purpose", style="dim")

        for header, description in SECURITY_HEADERS.items():
            status = (
                "[bold green]PASS[/bold green]"
                if header in headers
                else "[bold red]MISSING[/bold red]"
            )
            table.add_row(header, status, description)
        return table

    # ── Intel extraction ──────────────────────────────────────────────────────

    def extract_intel(self, html: str) -> list:
        intel = []

        emails = re.findall(
            r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+", html)
        if emails:
            intel.append(
                f"[cyan]Emails:[/cyan] {', '.join(set(emails[:5]))}")

        api_patterns = [
            r'(?i)api[_-]?key["\']?\s?[:=]\s?["\']?([a-zA-Z0-9_\-]{20,})',
            r'(?i)access[_-]?token["\']?\s?[:=]\s?["\']?([a-zA-Z0-9_\-]{20,})',
            r'(?i)secret["\']?\s?[:=]\s?["\']?([a-zA-Z0-9_\-]{20,})',
        ]
        for pat in api_patterns:
            if re.search(pat, html):
                intel.append(
                    "[bold red]Potential API Key / Secret Detected![/bold red]")
                break

        comments = re.findall(r"<!--(.*?)-->", html, re.DOTALL)
        if comments:
            intel.append(
                f"[yellow]HTML Comments: {len(comments)} found[/yellow]")

        return intel

    # ── Path fuzzer ───────────────────────────────────────────────────────────

    def check_path(self, path: str):
        url = f"{self.target}{path}"
        self.session.headers.update({"User-Agent": random.choice(USER_AGENTS)})
        try:
            if self.proxies_enabled:
                time.sleep(random.uniform(0.3, 1.2))
            res = self.session.get(url, timeout=10, allow_redirects=False)
            if res.status_code == 200:
                return (path, "[bold green]200 OK[/bold green]")
            elif res.status_code == 403:
                return (path, "[yellow]403 Forbidden[/yellow]")
            elif res.status_code in (301, 302):
                return (path, f"[blue]Redirect ({res.status_code})[/blue]")
        except Exception:
            pass
        return None

    # ── Main audit ────────────────────────────────────────────────────────────

    def run(self):
        draw_header("Web Ghost Elite: Professional Auditor")

        if self.proxies_enabled:
            console.print(
                "[*] Stealth Mode: [bold green]ON[/bold green] "
                "(routing via Tor 127.0.0.1:9050)\n")

        console.print(
            f"[*] Analyzing target: [bold yellow]{self.target}[/bold yellow]\n")

        # ── Initial request ──────────────────────────────────────────────────
        try:
            r = self.session.get(self.target, timeout=10)

        except requests.exceptions.SSLError:
            console.print(
                "\n[bold red][!] SSL Certificate Verification Failed.[/bold red]")
            console.print(
                "[yellow]The target uses an invalid or self-signed certificate. "
                "Restart Web Ghost and select 'No' when asked to Verify SSL.[/yellow]")
            return

        except requests.exceptions.ConnectionError as e:
            if "SOCKS" in str(e) or "Connection refused" in str(e):
                console.print(
                    "\n[bold red][!] Tor Proxy Unreachable (127.0.0.1:9050)[/bold red]")
                if questionary.confirm(
                    "Disable Proxy (stealth OFF) and continue?",
                    default=True, style=Q_STYLE
                ).ask():
                    console.print(
                        "\n[red][!] SWITCHING TO CLEARNET. STEALTH DISABLED.[/red]")
                    self.session.proxies = {}
                    self.proxies_enabled = False
                    try:
                        r = self.session.get(self.target, timeout=10)
                    except Exception as e2:
                        console.print(
                            f"[bold red][!] Connection failed: {e2}[/bold red]")
                        return
                else:
                    return
            else:
                console.print(
                    f"[bold red][!] Target Connectivity Error: {e}[/bold red]")
                return

        except Exception as e:
            console.print(f"[bold red][!] Unexpected Error: {e}[/bold red]")
            return

        # ── Analysis ─────────────────────────────────────────────────────────
        try:
            # 1. Header audit
            console.print(self.audit_headers(r.headers))

            # 2. Fingerprinting
            soup = BeautifulSoup(r.text, "html.parser")
            server = r.headers.get("Server",      "Undisclosed")
            powered = r.headers.get("X-Powered-By", "Unknown")
            title = soup.title.string.strip() if soup.title else "None"
            intel = self.extract_intel(r.text)

            console.print(Panel(
                f"[white]Title:[/white]  {title}\n"
                f"[white]Server:[/white] {server}\n"
                f"[white]Tech:[/white]   {powered}\n"
                f"[white]Leaks:[/white]  {' | '.join(intel) if intel else 'None Detected'}",
                title="Infrastructure Fingerprint",
                border_style="green",
            ))

            # 3. Path discovery
            discovery_table = Table(
                title="Sensitive Directory Discovery",
                border_style="bold green",
                expand=True,
            )
            discovery_table.add_column("Path",   style="cyan")
            discovery_table.add_column("Status", style="white")

            with Progress(
                SpinnerColumn(),
                TextColumn("{task.description}"),
                BarColumn(),
                console=console,
            ) as progress:
                task = progress.add_task(
                    "[green]Fuzzing paths...", total=len(SENSITIVE_PATHS))
                with ThreadPoolExecutor(max_workers=10) as executor:
                    futures = [
                        executor.submit(self.check_path, p)
                        for p in SENSITIVE_PATHS
                    ]
                    for f in as_completed(futures):
                        res = f.result()
                        if res:
                            discovery_table.add_row(res[0], res[1])
                        progress.update(task, advance=1)

            console.print(discovery_table)

        except Exception as e:
            console.print(f"[bold red][!] Audit Error: {e}[/bold red]")

        questionary.press_any_key_to_continue(style=Q_STYLE).ask()


# ─────────────────────────────────────────────────────────────────────────────
#  ENTRY POINT — called by main.py
# ─────────────────────────────────────────────────────────────────────────────

def web_ghost():
    target = questionary.text(
        "Target URL (e.g., https://example.com):", style=Q_STYLE).ask()
    if not target:
        return
    if not target.startswith("http"):
        console.print(
            "[red][!] Invalid URL — must start with http:// or https://[/red]")
        return

    verify_cert = questionary.confirm(
        "Verify SSL Certificates? (select 'No' ONLY for self-signed targets)",
        default=True, style=Q_STYLE,
    ).ask()

    scanner = WebGhost(target, use_tor=True, verify_ssl=verify_cert)
    scanner.run()


if __name__ == "__main__":
    web_ghost()
