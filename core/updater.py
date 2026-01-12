import requests
from rich.console import Console
from rich.panel import Panel

console = Console()

# Current version of the user's local code
VERSION = "2.6"
# Your GitHub raw link for the version file
RAW_VERSION_URL = "https://raw.githubusercontent.com/BryanParreira/Davoid/main/version.txt"


def check_version():
    try:
        response = requests.get(RAW_VERSION_URL, timeout=2)
        if response.status_code == 200:
            latest = response.text.strip()
            if latest != VERSION:
                console.print(Panel(
                    f"[bold yellow]UPDATE FOUND:[/bold yellow] Davoid v{latest} is available!\n"
                    f"[white]Run [bold red]davoid --update[/bold red] to pull the latest tools.[/white]",
                    border_style="yellow",
                    expand=False
                ))
    except:
        pass  # Fail silently if no internet
