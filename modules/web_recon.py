import requests
import urllib3
from bs4 import BeautifulSoup
from rich.console import Console
from rich.table import Table
from core.ui import draw_header

urllib3.disable_warnings()
console = Console()

SENSITIVE_PATHS = ["/.env", "/.git/config", "/backup.sql",
                   "/config.php", "/phpinfo.php", "/admin/"]


def web_ghost():
    draw_header("Web Ghost Intelligence")
    target = console.input(
        "[bold yellow]Target URL (http://1.2.3.4): [/bold yellow]").strip()
    if not target.startswith("http"):
        return

    # 1. Technology Fingerprinting
    try:
        r = requests.get(target, timeout=5, verify=False)
        server = r.headers.get("Server", "Unknown")
        powered_by = r.headers.get("X-Powered-By", "Unknown")

        soup = BeautifulSoup(r.text, 'html.parser')
        title = soup.title.string if soup.title else "No Title"

        intel_table = Table(title="Target Fingerprint", border_style="blue")
        intel_table.add_row("Server", server)
        intel_table.add_row("Tech Stack", powered_by)
        intel_table.add_row("Page Title", title)
        console.print(intel_table)

        # 2. WAF Detection (Basic)
        waf_headers = ["X-CDN", "X-WAF-Event", "cf-ray", "x-amz-cf-id"]
        if any(h in r.headers for h in waf_headers):
            console.print(
                "[bold red][!] WAF/CDN Detected! Fuzzing may be blocked.[/bold red]")

    except:
        console.print("[red][!] Target unreachable.[/red]")
        return

    # 3. Path Fuzzing
    fuzz_table = Table(title="Path Discovery Results", border_style="green")
    fuzz_table.add_column("Path", style="cyan")
    fuzz_table.add_column("Status", justify="center")
    fuzz_table.add_column("Size", style="dim")

    console.print("[*] Fuzzing high-value paths...")
    for path in SENSITIVE_PATHS:
        try:
            url = target.rstrip("/") + path
            res = requests.get(url, timeout=3, verify=False,
                               allow_redirects=False)
            if res.status_code == 200:
                fuzz_table.add_row(
                    path, "[bold green]200 OK[/bold green]", f"{len(res.content)} bytes")
            elif res.status_code == 403:
                fuzz_table.add_row(path, "[yellow]403 Forbidden[/yellow]", "-")
        except:
            pass

    console.print(fuzz_table)
    input("\nPress Enter...")
