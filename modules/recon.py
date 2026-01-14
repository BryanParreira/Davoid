import dns.resolver
import threading
import requests
import json
from rich.console import Console
from rich.table import Table
from core.ui import draw_header

console = Console()

# Professional Subdomain Dictionary
SUB_DICT = ['www', 'mail', 'remote', 'vpn', 'dev', 'stage',
            'api', 'git', 'ssh', 'webmail', 'portal', 'admin', 'test']


class DNSReconEngine:
    def __init__(self, domain):
        self.domain = domain
        self.found_subs = []
        self.lock = threading.Lock()

    def get_passive(self):
        """OSINT: Queries Certificate Transparency logs for hidden subdomains."""
        try:
            url = f"https://crt.sh/?q=%.{self.domain}&output=json"
            res = requests.get(url, timeout=10)
            if res.status_code == 200:
                for entry in res.json():
                    name = entry['name_value']
                    for sub in name.split('\n'):
                        if not sub.startswith('*') and sub.strip() not in self.found_subs:
                            self.found_subs.append(sub.strip())
        except:
            pass

    def brute_worker(self, sub):
        """Active Discovery: Brute forces common subdomains."""
        target = f"{sub}.{self.domain}"
        try:
            dns.resolver.resolve(target, 'A')
            with self.lock:
                if target not in self.found_subs:
                    self.found_subs.append(target)
        except:
            pass

    def run(self):
        draw_header("Elite DNS Infrastructure Recon")
        console.print(
            f"[*] Analyzing [bold cyan]{self.domain}[/bold cyan]...\n")

        # 1. Standard Infrastructure Records
        table = Table(
            title=f"Core DNS Records: {self.domain}", border_style="magenta")
        table.add_column("Type", style="cyan")
        table.add_column("Value", style="white")

        for rtype in ['A', 'MX', 'NS', 'TXT', 'SOA']:
            try:
                ans = dns.resolver.resolve(self.domain, rtype)
                for a in ans:
                    table.add_row(rtype, str(a))
            except:
                pass
        console.print(table)

        # 2. Passive & Active Discovery
        console.print("\n[*] Launching OSINT and Brute-Force discovery...")
        self.get_passive()

        threads = []
        for s in SUB_DICT:
            t = threading.Thread(target=self.brute_worker, args=(s,))
            t.start()
            threads.append(t)
        for t in threads:
            t.join()

        if self.found_subs:
            sub_table = Table(
                title="Discovered Attack Surface (Subdomains)", border_style="green")
            sub_table.add_column("Subdomain", style="bold yellow")
            sub_table.add_column("Status", style="white")
            for sub in sorted(list(set(self.found_subs))):
                sub_table.add_row(sub, "Active")
            console.print(sub_table)

        input("\nPress Enter...")


def dns_recon():
    domain = console.input(
        "[bold yellow]Target Domain (e.g., target.com): [/bold yellow]").strip()
    if domain:
        engine = DNSReconEngine(domain)
        engine.run()
