import sys
from rich.console import Console
from rich.prompt import Prompt
from core.ui import draw_header
from core.updater import check_version
from modules.scanner import network_discovery
from modules.sniff import start_sniffing

console = Console()


def main():
    while True:
        draw_header("Main Control")

        # Check for updates every time the main menu loads
        check_version()

        console.print("[bold red]>[/bold red] [1] Net-Mapper")
        console.print("[bold red]>[/bold red] [2] Live Interceptor")
        console.print("[bold red]>[/bold red] [Q] Vanish")

        choice = Prompt.ask(
            "\n[bold red]davoid[/bold red]@[root]", choices=["1", "2", "q", "Q"])

        if choice == "1":
            network_discovery()
        elif choice == "2":
            start_sniffing()
        elif choice.lower() == "q":
            sys.exit()


if __name__ == "__main__":
    main()
