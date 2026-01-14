import requests
import urllib3
from bs4 import BeautifulSoup
from rich.console import Console
from rich.table import Table
from core.ui import draw_header

urllib3.disable_warnings()
console = Console()

PATHS = ["/.env", "/.git/config", "/backup.sql",
         "/config.php", "/phpinfo.php", "/admin/", "/login"]
HEADERS = ["Content-Security-Policy",
           "Strict-Transport-Security", "X-Frame-Options"]


def web_ghost():
    draw_header("Web Ghost Elite: Audit & Intel")
    target = console.input(
        "[bold yellow]URL (http://example.com): [/bold yellow]").strip()
    if not target.startswith("http"):
        return

    try:
        r = requests.get(target, timeout=5, verify=False)

        # 1. Security Audit
        audit = Table(title="Security Configuration Audit",
                      border_style="bold red")
        audit.add_column("Security Header", style="cyan")
        audit.add_column("Status", style="white")
        for h in HEADERS:
            status = "[green]Present[/green]" if h in r.headers else "[bold red]MISSING[/bold red]"
            audit.add_row(h, status)
        console.print(audit)

        # 2. Tech Fingerprint
        server = r.headers.get("Server", "Unknown")
        soup = BeautifulSoup(r.text, 'html.parser')
        title = soup.title.string if soup.title else "No Title"
        console.print(
            f"\n[green][+][/green] Server: {server} | Title: {title}")

        # 3. Path Discovery
        fuzz = Table(title="Sensitive Path Discovery", border_style="green")
        fuzz.add_column("Path", style="cyan")
        fuzz.add_column("Status", style="white")
        for path in PATHS:
            try:
                res = requests.get(target.rstrip(
                    "/") + path, timeout=2, verify=False, allow_redirects=False)
                if res.status_code == 200:
                    fuzz.add_row(path, "[bold green]200 OK[/bold green]")
                elif res.status_code == 403:
                    fuzz.add_row(path, "[yellow]403 Forbidden[/yellow]")
            except:
                pass
        console.print(fuzz)

    except:
        console.print("[red][!] Target offline.[/red]")
    input("\nPress Enter...")
