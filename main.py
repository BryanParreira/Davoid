import sys
import time
from rich.console import Console
from rich.prompt import Prompt
from core.ui import draw_header
from modules.scanner import network_discovery
from modules.sniff import start_sniffing

console = Console()


def main():
    while True:
        draw_header("Main Control")

        console.print("[bold red]>[/bold red] [1] Net-Mapper")
        console.print("[bold red]>[/bold red] [2] Live Interceptor")
        console.print("[bold red]>[/bold red] [3] Payload Forge")
        console.print("[bold red]>[/bold red] [Q] Vanish")

        choice = Prompt.ask(
            "\n[bold red]davoid[/bold red]@[root]", choices=["1", "2", "3", "q", "Q"])

        if choice == "1":
            console.print(
                "[italic white][*] Grabbing server fingerprints...[/italic white]")
            time.sleep(1.5)  # The "Venom" aesthetic delay
            network_discovery()
        elif choice == "2":
            start_sniffing()
        elif choice.lower() == "q":
            sys.exit()


if __name__ == "__main__":
    main()
