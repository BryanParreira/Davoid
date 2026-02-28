"""
recon.py — DNS & Subdomain Recon Engine
FIX: Added missing 'import os' (was crashing on export).
"""

import os                        # ← CRITICAL FIX: was missing
import dns.resolver
import threading
import requests
import json
import socket
import logging
import questionary
from concurrent.futures import ThreadPoolExecutor, as_completed
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.panel import Panel
from core.ui import draw_header, Q_STYLE

logging.getLogger("urllib3").setLevel(logging.CRITICAL)
console = Console()

SUB_DICT = [
    'www', 'mail', 'remote', 'vpn', 'dev', 'stage', 'api', 'git', 'ssh',
    'webmail', 'portal', 'admin', 'test', 'support', 'cloud', 'autodiscover',
    'sip', 'm', 'blog', 'shop', 'beta', 'app', 'jenkins', 'proxy', 'secure',
    'status', 'wiki', 'docs', 'internal', 'staging', 'demo', 'mysql', 'db',
    'ftp', 'ns1', 'ns2', 'smtp', 'pop', 'imap', 'exchange', 'owa', 'rdp',
    'citrix', 'jira', 'confluence', 'gitlab', 'github', 'grafana', 'kibana',
]


class DNSReconEngine:
    def __init__(self, domain):
        self.domain = domain
        self.found_assets = {}
        self.lock = threading.Lock()
        self.wildcard_ip = None

    def detect_wildcard(self):
        random_sub = f"nonexistent-wildcard-probe-{socket.gethostname()}.{self.domain}"
        try:
            ans = dns.resolver.resolve(random_sub, 'A')
            self.wildcard_ip = str(ans[0])
            console.print(
                f"[yellow][!] Wildcard DNS detected ({self.wildcard_ip}). "
                f"False positives will be filtered.[/yellow]")
            return True
        except Exception:
            return False

    def get_passive_creds(self):
        """Query Certificate Transparency logs (crt.sh) for passive subdomain discovery."""
        try:
            url = f"https://crt.sh/?q=%.{self.domain}&output=json"
            res = requests.get(url, timeout=15)
            if res.status_code == 200:
                raw = set()
                for entry in res.json():
                    for sub in entry.get('name_value', '').split('\n'):
                        sub = sub.strip().lower()
                        if not sub.startswith('*') and self.domain in sub:
                            raw.add(sub)
                return list(raw)
        except Exception as e:
            console.print(
                f"[dim red][!] Passive discovery error (crt.sh): {e}[/dim red]")
        return []

    def resolve_target(self, target):
        try:
            resolver = dns.resolver.Resolver()
            resolver.timeout = 2
            resolver.lifetime = 2
            ans = resolver.resolve(target, 'A')
            ip = str(ans[0])
            if ip == self.wildcard_ip:
                return None
            return ip
        except Exception:
            return None

    def brute_worker(self, sub):
        target = f"{sub}.{self.domain}".lower()
        ip = self.resolve_target(target)
        if ip:
            with self.lock:
                self.found_assets[target] = ip

    def run(self):
        draw_header("Elite DNS Infrastructure Recon")
        console.print(Panel(
            f"Target: [bold cyan]{self.domain}[/bold cyan]",
            border_style="magenta"))

        # ── Core DNS records ──────────────────────────────────────
        rec_table = Table(title="Core Infrastructure Records",
                          border_style="magenta", expand=True)
        rec_table.add_column("Type",  style="cyan")
        rec_table.add_column("Value", style="white")

        for rtype in ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA', 'CNAME']:
            try:
                for a in dns.resolver.resolve(self.domain, rtype):
                    rec_table.add_row(rtype, str(a))
            except Exception:
                continue
        console.print(rec_table)

        # ── Wildcard detection ────────────────────────────────────
        self.detect_wildcard()

        # ── Hybrid passive + active discovery ─────────────────────
        with Progress(SpinnerColumn(), TextColumn("{task.description}"),
                      console=console) as progress:

            t1 = progress.add_task(
                "[yellow]Collecting CT log data (passive)...", total=None)
            passive_subs = self.get_passive_creds()
            progress.update(
                t1, description="[green]Passive collection complete.")

            t2 = progress.add_task(
                "[cyan]Active brute-force...", total=len(SUB_DICT))
            with ThreadPoolExecutor(max_workers=15) as ex:
                for _ in as_completed([ex.submit(self.brute_worker, s) for s in SUB_DICT]):
                    progress.update(t2, advance=1)

            t3 = progress.add_task(
                "[magenta]Verifying passive results...", total=len(passive_subs))
            with ThreadPoolExecutor(max_workers=15) as ex:
                def verify(sub):
                    ip = self.resolve_target(sub)
                    if ip:
                        with self.lock:
                            self.found_assets[sub] = ip
                    progress.update(t3, advance=1)
                list(ex.map(verify, passive_subs))

        # ── Results table ─────────────────────────────────────────
        if self.found_assets:
            sub_table = Table(
                title=f"Infrastructure Map — {len(self.found_assets)} assets",
                border_style="green", expand=True)
            sub_table.add_column("Subdomain / Host", style="bold yellow")
            sub_table.add_column("IP Address",       style="bold white")
            sub_table.add_column("PTR (rDNS)",       style="dim")

            for sub, ip in sorted(self.found_assets.items()):
                try:
                    ptr = socket.gethostbyaddr(ip)[0]
                except Exception:
                    ptr = "N/A"
                sub_table.add_row(sub, ip, ptr)

            console.print("\n", sub_table)

            # Export option — os.makedirs was crashing without 'import os'
            if questionary.confirm(
                    "Export results to JSON?", default=False, style=Q_STYLE).ask():
                output = {"domain": self.domain, "assets": self.found_assets}
                os.makedirs("logs", exist_ok=True)           # ← uses import os
                filename = f"logs/recon_{self.domain.replace('.', '_')}.json"
                with open(filename, 'w') as f:
                    json.dump(output, f, indent=4)
                console.print(f"[green][+] Report saved: {filename}[/green]")
        else:
            console.print("[red][!] No subdomains discovered.[/red]")

        questionary.press_any_key_to_continue(style=Q_STYLE).ask()


def dns_recon():
    domain = questionary.text(
        "Target Domain (e.g., example.com):", style=Q_STYLE).ask()
    if domain:
        DNSReconEngine(domain).run()


if __name__ == "__main__":
    dns_recon()
