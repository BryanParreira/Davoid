import requests
from rich.console import Console
from rich.table import Table
from core.ui import draw_header

console = Console()

def web_ghost():
    draw_header("Web Ghost")
    target = console.input("[bold yellow]Target (e.g., http://10.10.10.1): [/bold yellow]").strip()
    if not target.startswith("http"):
        console.print("[red][!] Include http:// or https://[/red]")
        return

    paths = ["/.env", "/.git/config", "/robots.txt", "/phpinfo.php", "/.ssh/id_rsa", "/backup.zip"]
    table = Table(title="Web Intel", border_style="bold green")
    table.add_column("Path", style="cyan")
    table.add_column("Status", style="bold white")

    with console.status("[bold green]Fuzzing..."):
        for path in paths:
            try:
                r = requests.get(f"{target}{path}", timeout=3, verify=False)
                if r.status_code == 200:
                    table.add_row(path, "FOUND (200)")
                elif r.status_code == 403:
                    table.add_row(path, "FORBIDDEN (403)")
            except:
                continue
    
    console.print(table)
    input("\nPress Enter...")