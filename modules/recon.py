import dns.resolver
import threading
import requests
import json
import socket
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.panel import Panel
from core.ui import draw_header

# Suppress noisy logging from third-party libs
logging.getLogger("urllib3").setLevel(logging.CRITICAL)

console = Console()

# Expanded Professional Subdomain Dictionary
SUB_DICT = [
    'www', 'mail', 'remote', 'vpn', 'dev', 'stage', 'api', 'git', 'ssh', 
    'webmail', 'portal', 'admin', 'test', 'support', 'cloud', 'autodiscover', 
    'sip', 'm', 'blog', 'shop', 'beta', 'app', 'jenkins', 'proxy', 'secure', 
    'status', 'wiki', 'docs', 'internal', 'staging', 'demo', 'mysql', 'db'
]

class DNSReconEngine:
    def __init__(self, domain):
        self.domain = domain
        self.found_assets = {}  # Format: {subdomain: ip}
        self.lock = threading.Lock()
        self.wildcard_ip = None

    def detect_wildcard(self):
        """Checks if the domain uses a wildcard DNS record to avoid false positives."""
        random_sub = f"detect-wildcard-{socket.gethostname()}.{self.domain}"
        try:
            ans = dns.resolver.resolve(random_sub, 'A')
            self.wildcard_ip = str(ans[0])
            console.print(f"[yellow][!] Wildcard DNS detected: {self.wildcard_ip}. Filtering results...[/yellow]")
            return True
        except:
            return False

    def get_passive_creds(self):
        """OSINT: Queries Certificate Transparency (CT) logs via CRT.sh."""
        try:
            url = f"https://crt.sh/?q=%.{self.domain}&output=json"
            res = requests.get(url, timeout=15)
            if res.status_code == 200:
                data = res.json()
                # Use a set to handle duplicates from CT logs
                raw_subs = set()
                for entry in data:
                    name = entry['name_value']
                    for sub in name.split('\n'):
                        if not sub.startswith('*') and self.domain in sub:
                            raw_subs.add(sub.strip().lower())
                return list(raw_subs)
        except Exception as e:
            console.print(f"[dim red][!] Passive discovery failed (CRT.sh): {e}[/dim red]")
        return []

    def resolve_target(self, target):
        """Resolves a subdomain to its IP address."""
        try:
            # Enforce short timeout for brute forcing
            resolver = dns.resolver.Resolver()
            resolver.timeout = 2
            resolver.lifetime = 2
            ans = resolver.resolve(target, 'A')
            ip = str(ans[0])
            
            # Filter wildcard false positives
            if ip == self.wildcard_ip:
                return None
                
            return ip
        except:
            return None

    def brute_worker(self, sub):
        """Active Discovery logic for thread pool."""
        target = f"{sub}.{self.domain}".lower()
        ip = self.resolve_target(target)
        if ip:
            with self.lock:
                self.found_assets[target] = ip

    def run(self):
        draw_header("Elite DNS Infrastructure Recon")
        console.print(Panel(f"Targeting Domain: [bold cyan]{self.domain}[/bold cyan]", border_style="magenta"))

        # 1. Standard Infrastructure Records
        record_table = Table(title="Core Infrastructure Records", border_style="magenta", expand=True)
        record_table.add_column("Record Type", style="cyan")
        record_table.add_column("Value / Data", style="white")

        for rtype in ['A', 'MX', 'NS', 'TXT', 'SOA']:
            try:
                ans = dns.resolver.resolve(self.domain, rtype)
                for a in ans:
                    record_table.add_row(rtype, str(a))
            except:
                continue
        console.print(record_table)

        # 2. Wildcard Detection
        self.detect_wildcard()

        # 3. Passive & Active Hybrid Discovery
        with Progress(SpinnerColumn(), TextColumn("{task.description}"), console=console) as progress:
            # Passive Stage
            task_passive = progress.add_task("[yellow]Collecting Passive OSINT (CT Logs)...", total=None)
            passive_subs = self.get_passive_creds()
            progress.update(task_passive, description="[green]Passive OSINT Collection Complete.")

            # Active Brute Force Stage
            task_active = progress.add_task("[cyan]Active Brute-Force Discovery...", total=len(SUB_DICT))
            with ThreadPoolExecutor(max_workers=10) as executor:
                futures = [executor.submit(self.brute_worker, s) for s in SUB_DICT]
                for _ in as_completed(futures):
                    progress.update(task_active, advance=1)

            # Verification Stage (Passive to Active)
            task_verify = progress.add_task("[magenta]Verifying Passive Results...", total=len(passive_subs))
            with ThreadPoolExecutor(max_workers=10) as executor:
                for sub in passive_subs:
                    ip = self.resolve_target(sub)
                    if ip:
                        with self.lock:
                            self.found_assets[sub] = ip
                    progress.update(task_verify, advance=1)

        # 4. Final Report
        if self.found_assets:
            sub_table = Table(title=f"Infrastructure Map: {len(self.found_assets)} Assets Found", border_style="green", expand=True)
            sub_table.add_column("Subdomain / Host", style="bold yellow")
            sub_table.add_column("IP Address", style="bold white")
            sub_table.add_column("Reverse DNS / PTR", style="dim")

            for sub, ip in sorted(self.found_assets.items()):
                # Attempt to get PTR record (Reverse DNS)
                try:
                    ptr = socket.gethostbyaddr(ip)[0]
                except:
                    ptr = "N/A"
                sub_table.add_row(sub, ip, ptr)
            
            console.print("\n", sub_table)
            
            # Export Option
            if console.input("\n[bold cyan]Export to JSON? (y/N): [/bold cyan]").lower() == 'y':
                output = {"domain": self.domain, "assets": self.found_assets}
                filename = f"logs/recon_{self.domain.replace('.', '_')}.json"
                with open(filename, 'w') as f:
                    json.dump(output, f, indent=4)
                console.print(f"[green][+] Report saved to {filename}[/green]")
        else:
            console.print("[red][!] No subdomains discovered.[/red]")

        input("\nPress Enter to return...")

def dns_recon():
    domain = console.input("[bold yellow]Target Domain (e.g., example.com): [/bold yellow]").strip()
    if domain:
        engine = DNSReconEngine(domain)
        engine.run()

if __name__ == "__main__":
    dns_recon()