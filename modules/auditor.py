import shutil
import subprocess
import platform
from rich.console import Console
from rich.table import Table
from core.ui import draw_header

console = Console()


class DavoidAuditor:
    def check_and_fix(self, dep):
        """Detects missing dependencies and provides OS-specific remediation."""
        if not shutil.which(dep):
            # Special case for macOS 'airport' which is often not in the PATH
            if dep == "airport" and platform.system() == "Darwin":
                airport_path = "/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport"
                if shutil.os.path.exists(airport_path):
                    console.print(
                        f"[bold green][+] {dep} found (System Resource).[/bold green]")
                    return

            console.print(f"[bold red][!] Missing: {dep}[/bold red]")

            # Smart Remediation logic based on OS
            if platform.system() == "Darwin":  # macOS
                if dep == "airmon-ng":
                    console.print(
                        "    [dim]Remedy: brew install aircrack-ng[/dim]")
                elif dep == "iw":
                    console.print(
                        "    [dim]Note: 'iw' is Linux-only. Use 'airport' on Mac.[/dim]")
                else:
                    console.print(f"    [dim]Remedy: brew install {dep}[/dim]")
            else:  # Linux
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

        # Monitor Mode Activation Logic
        iface = console.input(
            "\n[bold yellow]Interface to audit for Monitor Mode? (Enter to skip): [/bold yellow]")

        if iface:
            try:
                if platform.system() == "Darwin":
                    # macOS specific monitor mode command
                    subprocess.run(["sudo", "airport", iface,
                                   "disassociate"], capture_output=True)
                    console.print(
                        f"[bold green][+] {iface} disassociated for sniffing.[/bold green]")
                else:
                    # Standard Linux airmon-ng command
                    subprocess.run(
                        ["sudo", "airmon-ng", "start", iface], capture_output=True)
                    console.print(
                        f"[bold green][+] {iface} set to Monitor Mode.[/bold green]")
            except Exception as e:
                console.print(
                    f"[bold red][!] Could not set Monitor Mode: {e}[/bold red]")


def run_auditor():
    auditor = DavoidAuditor()
    auditor.run()
