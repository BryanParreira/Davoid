import os
import shutil
import subprocess
import json
import questionary
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from core.ui import draw_header, Q_STYLE
from core.database import db

try:
    import nmap
except ImportError:
    pass

console = Console()


class NmapEngine:
    def __init__(self):
        self.nm = None
        self.has_searchsploit = False

    def check_dependencies(self):
        try:
            import nmap
            self.nm = nmap.PortScanner()
        except ImportError:
            console.print(
                "[bold red][!] Critical Dependency Missing: 'python-nmap'[/bold red]")
            console.print(
                "[white]Please run: /opt/davoid/venv/bin/pip install python-nmap[/white]")
            return False
        except nmap.PortScannerError:
            console.print(
                "[bold red][!] Nmap executable not found on the system.[/bold red]")
            console.print(
                "[white]Please ensure Nmap is installed (e.g., 'brew install nmap' or 'apt install nmap').[/white]")
            return False

        # Check for ExploitDB Integration
        if shutil.which('searchsploit'):
            self.has_searchsploit = True
        else:
            console.print(
                "[dim][!] 'searchsploit' not found. Exploit mapping disabled. (Run 'brew install exploitdb' to enable)[/dim]")

        return True

    def query_searchsploit(self, product, version):
        """Silently queries the Exploit Database for known vulnerabilities."""
        if not product or not self.has_searchsploit:
            return ""

        # Clean the query to prevent overly complex Nmap strings from breaking the search
        query = f"{product} {version}".strip()
        # Keep it to the first two words (e.g., "Apache httpd")
        query = " ".join(query.split()[:2])

        try:
            # Query SearchSploit and request JSON output
            result = subprocess.run(
                ['searchsploit', query, '--json'], capture_output=True, text=True, timeout=5)
            if result.returncode == 0 and result.stdout:
                data = json.loads(result.stdout)
                results = data.get('RESULTS_EXPLOIT', [])

                if results:
                    count = len(results)
                    exploit_str = f"\n  └── [bold red][!] {count} Exploits Found in ExploitDB![/bold red]"

                    # Show the top 2 exploits to keep the terminal UI clean
                    for exp in results[:2]:
                        title = exp.get('Title', 'Unknown')
                        path = exp.get('Path', 'Unknown')

                        # Highlight Metasploit modules
                        if "metasploit" in path.lower() or "msf" in title.lower():
                            exploit_str += f"\n      - [bold red]MSF Module:[/bold red] {title[:50]}..."
                        else:
                            exploit_str += f"\n      - {title[:60]}..."

                    if count > 2:
                        exploit_str += f"\n      - [dim]...and {count - 2} more (Run 'searchsploit {query}' to view all)[/dim]"

                    return exploit_str
        except Exception:
            pass  # Fail silently if the query breaks so the scan doesn't crash

        return ""

    def run_scan(self):
        target = questionary.text(
            "Target (IP or Subnet, e.g., 192.168.1.0/24):", default="192.168.1.1", style=Q_STYLE).ask()
        if not target:
            return

        # Offer professional Nmap scan profiles
        scan_profile = questionary.select(
            "Select Nmap Scan Profile:",
            choices=[
                "1. Quick Scan (Ping sweep + Top 100 ports)",
                "2. Stealth SYN Scan (-sS, requires sudo)",
                "3. Comprehensive Audit (-sS -sV -O -sC, requires sudo)",
                "4. UDP Discovery (-sU, requires sudo)",
                "Back"
            ],
            style=Q_STYLE
        ).ask()

        if not scan_profile or scan_profile == "Back":
            return

        # Map profiles to Nmap arguments
        nmap_args = ""
        if "Quick" in scan_profile:
            nmap_args = "-T4 -F"
        elif "Stealth" in scan_profile:
            if os.getuid() != 0:
                return console.print("[red][!] Stealth SYN scans require root privileges. Run Davoid with sudo.[/red]")
            nmap_args = "-sS -T4"
        elif "Comprehensive" in scan_profile:
            if os.getuid() != 0:
                return console.print("[red][!] Comprehensive audits require root privileges. Run Davoid with sudo.[/red]")
            nmap_args = "-sS -sV -O -sC -T4"
        elif "UDP" in scan_profile:
            if os.getuid() != 0:
                return console.print("[red][!] UDP scans require root privileges. Run Davoid with sudo.[/red]")
            nmap_args = "-sU -T4 --top-ports 20"

        console.print(
            f"[*] Initiating Nmap Engine against {target} with args: '{nmap_args}'...")

        try:
            # Run Nmap with a spinner
            with console.status("[bold cyan]Nmap Engine running... (This may take a while depending on the profile)[/bold cyan]", spinner="bouncingBar"):
                self.nm.scan(hosts=target, arguments=nmap_args)
        except Exception as e:
            console.print(f"[bold red][!] Nmap scan failed:[/bold red] {e}")
            return

        # Process and display the results
        if not self.nm.all_hosts():
            console.print(
                "[yellow][!] No active hosts discovered or all ports are filtered.[/yellow]")
            questionary.press_any_key_to_continue(style=Q_STYLE).ask()
            return

        for host in self.nm.all_hosts():
            state = self.nm[host].state()
            mac = self.nm[host]['addresses'].get('mac', 'Unknown')
            vendor = self.nm[host]['vendor'].get(
                mac, 'Unknown') if mac != 'Unknown' else 'Unknown'

            # Extract OS matches if available
            os_match = "Unknown"
            if 'osmatch' in self.nm[host] and len(self.nm[host]['osmatch']) > 0:
                os_match = self.nm[host]['osmatch'][0]['name']

            console.print(f"\n[bold green]Host:[/bold green] {host} ({state})")
            console.print(
                f"[bold white]MAC:[/bold white] {mac} [dim]({vendor})[/dim] | [bold white]OS:[/bold white] {os_match}")

            # Draw a table for the ports
            table = Table(border_style="cyan")
            table.add_column("Port", style="yellow", justify="right")
            table.add_column("State", style="magenta")
            table.add_column("Service", style="cyan")
            table.add_column("Version / Info", style="white")

            db_services = []

            for proto in self.nm[host].all_protocols():
                ports = self.nm[host][proto].keys()
                for port in sorted(ports):
                    port_data = self.nm[host][proto][port]
                    state = port_data['state']
                    name = port_data['name']
                    product = port_data.get('product', '')
                    version = port_data.get('version', '')
                    extrainfo = port_data.get('extrainfo', '')

                    # Compile version info cleanly
                    info = f"{product} {version} {extrainfo}".strip()
                    if not info:
                        info = "N/A"

                    # 1. Check for ExploitDB Vulnerabilities natively!
                    if product:
                        exploit_data = self.query_searchsploit(
                            product, version)
                        info += exploit_data

                    # 2. Append Nmap Scripting Engine (NSE) output if it ran
                    script_output = ""
                    if 'script' in port_data:
                        for script_name, script_res in port_data['script'].items():
                            script_output += f"\n  └── [bold red]{script_name}:[/bold red] {script_res.splitlines()[0]}"

                    info += script_output
                    table.add_row(f"{port}/{proto}", state, name, info)

                    if state == "open":
                        db_services.append(f"{port}/{proto} ({name}): {info}")

            if db_services:
                console.print(table)
                # Log to the mission database
                svc_log = "\n".join(db_services)
                # Strip rich formatting tags before saving to DB
                clean_log = svc_log.replace("[bold red]", "").replace(
                    "[/bold red]", "").replace("[dim]", "").replace("[/dim]", "").replace("[!]", "")
                db.log("Nmap-Engine", host,
                       f"OS: {os_match}\nServices:\n{clean_log}", "HIGH")
            else:
                console.print(
                    "[dim]No open ports discovered on this host.[/dim]")

        console.print(
            f"\n[bold green][+] Nmap Discovery Complete. Results logged to Mission Database.[/bold green]")
        questionary.press_any_key_to_continue(style=Q_STYLE).ask()

    def network_discovery(self):
        draw_header("Nmap Tactical Orchestrator & Exploit Mapper")
        if not self.check_dependencies():
            questionary.press_any_key_to_continue(style=Q_STYLE).ask()
            return

        self.run_scan()


def network_discovery():
    engine = NmapEngine()
    engine.network_discovery()


if __name__ == "__main__":
    network_discovery()
