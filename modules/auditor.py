import shutil
import subprocess
import platform
import os
import socket
import questionary
from rich.console import Console
from rich.table import Table
from core.ui import draw_header, Q_STYLE

console = Console()


class DavoidAuditor:
    def __init__(self):
        self.os = platform.system()

    def check_dependency(self, dep):
        if not shutil.which(dep):
            # macOS specific check for 'airport'
            if dep == "airport" and self.os == "Darwin":
                if os.path.exists("/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport"):
                    return True
            return False
        return True

    def run_posture_audit(self):
        """Advanced Check for local system security misconfigurations."""
        table = Table(title="System Posture Audit",
                      border_style="bold magenta")
        table.add_column("Security Check", style="cyan")
        table.add_column("Status", style="white")

        # 1. Root Check
        is_root = os.getuid() == 0
        table.add_row(
            "Root Privileges", "[green]YES[/green]" if is_root else "[red]NO (Limited)[/red]")

        # 2. Firewall Check (Linux Example)
        if self.os == "Linux":
            try:
                fw = subprocess.check_output(
                    ["ufw", "status"], stderr=subprocess.STDOUT).decode()
                status = "[green]Enabled[/green]" if "active" in fw else "[yellow]Inactive[/yellow]"
            except:
                status = "[red]Not Found[/red]"
            table.add_row("UFW Firewall Status", status)

        # 3. Open Listening Ports (Local)
        ports = []
        for port in [22, 80, 443, 445, 3389]:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(0.1)
                if s.connect_ex(('127.0.0.1', port)) == 0:
                    ports.append(str(port))

        table.add_row("Local Listening Ports", ", ".join(ports)
                      if ports else "[green]None Exposed[/green]")

        # 4. Sensitive File Permissions (Linux/macOS)
        if self.os != "Windows":
            shadow = os.access("/etc/shadow", os.R_OK)
            table.add_row("Shadow File Readable",
                          "[red]VULNERABLE[/red]" if shadow else "[green]Secure[/green]")

        console.print(table)

    def run(self):
        draw_header("Davoid Advanced Auditor & Posture Scout")

        # Dependency Report
        dep_table = Table(title="Core Dependency Report", border_style="cyan")
        dep_table.add_column("Tool", style="yellow")
        dep_table.add_column("Status", style="bold")

        deps = ["tcpdump", "nmap", "airmon-ng", "git", "python3"]
        if self.os == "Darwin":
            deps.append("airport")
        else:
            deps.append("iw")

        for d in deps:
            status = "[bold green]FOUND[/bold green]" if self.check_dependency(
                d) else "[bold red]MISSING[/bold red]"
            dep_table.add_row(d, status)

        console.print(dep_table)
        console.print("\n")

        # Security Posture Audit
        self.run_posture_audit()

        questionary.press_any_key_to_continue(style=Q_STYLE).ask()


def run_auditor():
    auditor = DavoidAuditor()
    auditor.run()


if __name__ == "__main__":
    run_auditor()
