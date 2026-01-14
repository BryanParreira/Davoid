import requests
import urllib3
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, BarColumn, TextColumn, SpinnerColumn
from concurrent.futures import ThreadPoolExecutor, as_completed
from core.ui import draw_header

# Suppress insecure request warnings for cleaner output
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

console = Console()

# Expanded dictionary for high-impact discovery
SENSITIVE_PATHS = {
    "Config/Env": [
        "/.env", "/.env.local", "/.env.production", "/config.php", "/web.config",
        "/settings.py", "/.flaskenv", "/.dockerenv", "/docker-compose.yml"
    ],
    "Version Control": [
        "/.git/config", "/.git/HEAD", "/.git/index", "/.gitignore",
        "/.svn/entries", "/.hg/", "/.bzr/"
    ],
    "Backups/DB": [
        "/backup.zip", "/backup.sql", "/db.sql", "/dump.sql", "/archive.tar.gz",
        "/config.bak", "/old.zip", "/site.bak", "/www.zip", "/data.zip"
    ],
    "Admin/Dev": [
        "/phpinfo.php", "/info.php", "/admin/", "/wp-admin/", "/dashboard/",
        "/_debugbar/", "/telescope/", "/elmah.axd", "/server-status"
    ],
    "Secrets": [
        "/.ssh/id_rsa", "/.ssh/id_dsa", "/.ssh/authorized_keys",
        "/.aws/credentials", "/.npmrc", "/.bash_history"
    ],
    "API/JSON": [
        "/swagger.json", "/api/v1/users", "/graphql", "/actuator/env",
        "/actuator/health", "/package.json", "/composer.json"
    ]
}

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Davoid/2.0 WebGhost/1.1"
}


def check_path(target, path):
    """Worker function to check a single path."""
    url = f"{target.rstrip('/')}{path}"
    try:
        # We use allow_redirects=False to find the exact file, not the login page
        r = requests.get(url, headers=HEADERS, timeout=5,
                         verify=False, allow_redirects=False)

        # Intelligence: Look for content markers in 200 OK responses
        info = ""
        if r.status_code == 200:
            if "DB_PASSWORD" in r.text or "AWS_ACCESS_KEY" in r.text:
                info = "[BOLD RED]LEAK DETECTED[/BOLD RED]"
            elif "[repository]" in r.text:
                info = "Git Repo"
            else:
                info = f"{len(r.content)} bytes"

        return path, r.status_code, info
    except requests.exceptions.RequestException:
        return path, None, "Error"


def web_ghost():
    draw_header("Web Ghost Pro")

    target = console.input(
        "[bold yellow]Target (e.g., http://10.10.10.1): [/bold yellow]").strip()
    if not target.startswith("http"):
        console.print("[red][!] Include http:// or https://[/red]")
        return

    # Flatten the list for processing
    all_paths = [path for category in SENSITIVE_PATHS.values()
                 for path in category]

    # Results Table
    table = Table(title=f"Intel Report: {target}",
                  border_style="bold green", expand=True)
    table.add_column("Path", style="cyan", no_wrap=True)
    table.add_column("Status", justify="center")
    table.add_column("Info/Size", style="magenta")

    found_count = 0

    # Multi-threaded scanning engine
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        console=console
    ) as progress:

        task = progress.add_task(
            "[green]Fuzzing sensitive paths...", total=len(all_paths))

        with ThreadPoolExecutor(max_workers=15) as executor:
            futures = {executor.submit(
                check_path, target, p): p for p in all_paths}

            for future in as_completed(futures):
                path, status, info = future.result()

                if status:
                    # Highlight interesting status codes
                    status_str = str(status)
                    if status == 200:
                        status_str = f"[bold green]{status}[/bold green]"
                        table.add_row(path, status_str, info)
                        found_count += 1
                    elif status == 403:
                        status_str = f"[bold yellow]{status}[/bold yellow]"
                        table.add_row(path, status_str, "Forbidden")
                    elif status == 401:
                        status_str = f"[bold red]{status}[/bold red]"
                        table.add_row(path, status_str, "Auth Required")

                progress.update(task, advance=1)

    # Output Results
    console.print("\n")
    if found_count > 0:
        console.print(table)
        console.print(
            f"[bold green][+] Scan complete. {found_count} potential vulnerabilities discovered.[/bold green]")
    else:
        console.print(
            "[bold red][!] No sensitive files found with the current wordlist.[/bold red]")

    input("\nPress Enter to return to menu...")
