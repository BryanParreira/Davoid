import dns.resolver
import threading
from rich.console import Console
from rich.table import Table
from core.ui import draw_header

console = Console()

SUBDOMAINS = ['www', 'mail', 'remote', 'vpn', 'dev',
              'stage', 'api', 'git', 'ssh', 'webmail', 'portal']


def resolve_sub(domain, sub, results):
    target = f"{sub}.{domain}"
    try:
        answers = dns.resolver.resolve(target, 'A')
        for rdata in answers:
            results.append((target, str(rdata)))
    except:
        pass


def dns_recon():
    draw_header("Advanced Infrastructure Recon")
    domain = console.input(
        "[bold yellow]Target Domain (example.com): [/bold yellow]").strip()
    if not domain:
        return

    console.print(
        f"[*] Analyzing [bold cyan]{domain}[/bold cyan] and hunting subdomains...")

    # Standard Records
    results_table = Table(
        title=f"Core DNS Records: {domain}", border_style="magenta")
    results_table.add_column("Type", style="cyan")
    results_table.add_column("Data", style="white")

    for r_type in ['A', 'MX', 'NS', 'TXT']:
        try:
            answers = dns.resolver.resolve(domain, r_type)
            for rdata in answers:
                results_table.add_row(r_type, str(rdata))
        except:
            pass

    console.print(results_table)

    # Subdomain Brute Force
    sub_results = []
    threads = []
    for s in SUBDOMAINS:
        t = threading.Thread(target=resolve_sub, args=(domain, s, sub_results))
        t.start()
        threads.append(t)

    for t in threads:
        t.join()

    if sub_results:
        sub_table = Table(title="Discovered Subdomains", border_style="green")
        sub_table.add_column("Subdomain", style="bold yellow")
        sub_table.add_column("IP Address", style="white")
        for host, ip in sub_results:
            sub_table.add_row(host, ip)
        console.print(sub_table)
    else:
        console.print("[dim][-] No common subdomains found.[/dim]")

    input("\nPress Enter...")
