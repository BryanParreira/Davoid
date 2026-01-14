import shutil
import subprocess
from rich.console import Console
from rich.table import Table
from core.ui import draw_header

console = Console()


class DavoidAuditor:
    def check_and_fix(self, dep):
        if not shutil.which(dep):
            console.print(f"[bold red][!] Missing: {dep}[/bold red]")
            # Remediation logic
            if shutil.which("apt"):
                console.print(f"    [dim]Remedy: sudo apt install {dep}[/dim]")
            elif shutil.which("brew"):
                console.print(f"    [dim]Remedy: brew install {dep}[/dim]")
        else:
            console.print(f"[bold green][+] {dep} found.[/bold green]")

    def run(self):
        draw_header("Davoid Advanced Auditor")
        deps = ["tcpdump", "nmap", "iw", "airmon-ng"]

        for d in deps:
            self.check_and_fix(d)

        # Auto-Switch to Monitor Mode (if interface provided)
        iface = console.input(
            "\n[bold yellow]Interface to audit for Monitor Mode? (Enter to skip): [/bold yellow]")
        if iface:
            subprocess.run(["sudo", "airmon-ng", "start",
                           iface], capture_output=True)
            console.print(
                f"[bold green][+] {iface} set to Monitor Mode.[/bold green]")


def run_auditor():
    auditor = DavoidAuditor()
    auditor.run()
