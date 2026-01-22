import shutil
import subprocess
import platform
import os
from rich.console import Console
from core.ui import draw_header

console = Console()


class DavoidAuditor:
    def check_and_fix(self, dep):
        """Detects missing dependencies and provides OS-specific remediation."""
        if not shutil.which(dep):
            # Special case for macOS 'airport'
            if dep == "airport" and platform.system() == "Darwin":
                airport_path = "/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport"
                if os.path.exists(airport_path):
                    console.print(
                        f"[bold green][+] {dep} found (System Resource).[/bold green]")
                    return

            console.print(f"[bold red][!] Missing: {dep}[/bold red]")

            # Smart Remediation logic
            if platform.system() == "Darwin":
                if dep == "airmon-ng":
                    console.print(
                        "    [dim]Remedy: brew install aircrack-ng[/dim]")
                elif dep == "iw":
                    console.print(
                        "    [dim]Note: 'iw' is Linux-only. Use 'airport' on Mac.[/dim]")
                else:
                    console.print(f"    [dim]Remedy: brew install {dep}[/dim]")
            else:
                console.print(f"    [dim]Remedy: sudo apt install {dep}[/dim]")
        else:
            console.print(f"[bold green][+] {dep} found.[/bold green]")

    def run(self):
        draw_header("Davoid Advanced Auditor")

        # Base requirements
        deps = ["tcpdump", "nmap", "airmon-ng"]

        # OS-Specific Wireless Logic
        if platform.system() == "Darwin":
            deps.append("airport")
        else:
            deps.append("iw")

        for d in deps:
            self.check_and_fix(d)

        # REMOVED: Monitor Mode Activation input loop to prevent double Enter prompt


def run_auditor():
    auditor = DavoidAuditor()
    auditor.run()
