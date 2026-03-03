# plugins/hello_plugin.py
import time
from core.plugin import DavoidPlugin
from rich.console import Console

console = Console()


class HelloPlugin(DavoidPlugin):
    @property
    def name(self) -> str:
        return "Community Beacon Tool"

    @property
    def description(self) -> str:
        return "An example plugin to test the Davoid Scripting Engine."

    @property
    def author(self) -> str:
        return "Davoid Community"

    def run(self) -> None:
        console.print(
            "\n[bold green]>>> Plugin Execution Started <<<[/bold green]")
        console.print("[*] Initializing custom community module...")
        time.sleep(1)
        console.print("[+] Target acquired via plugin interface.")
        console.print("[+] Execution complete.\n")
