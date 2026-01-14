import socket
import dns.resolver
import dns.zone
import dns.query
import whois
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from core.ui import draw_header

console = Console()


def get_dns_records(domain, record_type):
    """Helper to fetch DNS records safely."""
    try:
        answers = dns.resolver.resolve(domain, record_type)
        return [str(rdata) for rdata in answers]
    except Exception:
        return []


def check_axfr(domain, nameservers):
    """Attempts a DNS Zone Transfer (AXFR) - A high-value vulnerability."""
    vulnerable = []
    for ns in nameservers:
        try:
            # Resolve NS to IP
            ns_ip = socket.gethostbyname(ns)
            zone = dns.zone.from_xfr(dns.query.xfr(ns_ip, domain))
            if zone:
                vulnerable.append(ns)
        except Exception:
            continue
    return vulnerable


def dns_recon():
    draw_header("Advanced DNS Infrastructure Recon")
    domain = console.input(
        "[bold yellow]Enter Target Domain (e.g., example.com): [/bold yellow]").strip()

    if not domain:
        return

    console.print(
        f"[*] Starting deep analysis of [bold cyan]{domain}[/bold cyan]...\n")

    # 1. Main Infrastructure Table
    table = Table(
        title=f"Infrastructure Report: {domain}", border_style="bold magenta", expand=True)
    table.add_column("Query Type", style="cyan", no_wrap=True)
    table.add_column("Result / Value", style="white")

    try:
        # A & AAAA Records
        ips = get_dns_records(domain, 'A')
        ipv6 = get_dns_records(domain, 'AAAA')
        for ip in ips:
            table.add_row("IPv4 Address (A)", ip)
        for ip in ipv6:
            table.add_row("IPv6 Address (AAAA)", ip)

        # Reverse DNS for the first IP
        if ips:
            try:
                ptr = socket.gethostbyaddr(ips[0])[0]
                table.add_row("PTR (Reverse DNS)", ptr)
            except:
                table.add_row("PTR (Reverse DNS)", "No Record Found")

        # MX Records (Mail)
        mx_records = get_dns_records(domain, 'MX')
        for mx in mx_records:
            table.add_row("Mail Server (MX)", mx)

        # NS Records (Nameservers)
        ns_records = get_dns_records(domain, 'NS')
        for ns in ns_records:
            table.add_row("Nameserver (NS)", ns)

        # TXT Records (SPF, DMARC, Verification)
        txt_records = get_dns_records(domain, 'TXT')
        for txt in txt_records:
            table.add_row(
                "TXT Record", txt[:100] + "..." if len(txt) > 100 else txt)

        console.print(table)

        # 2. Security Analysis Panel
        console.print(
            "\n[bold yellow][!] Running Security Checks...[/bold yellow]")

        # Check for Zone Transfer Vulnerability
        vuln_ns = check_axfr(domain, ns_records)
        if vuln_ns:
            console.print(Panel(
                f"[bold red][CRITICAL] Zone Transfer (AXFR) Successful on: {', '.join(vuln_ns)}[/bold red]\nThis domain is leaking its entire internal DNS structure!", title="Vulnerability Found"))
        else:
            console.print("[green][+] Zone Transfer: Secure (Failed)[/green]")

        # WHOIS Information
        try:
            w = whois.whois(domain)
            whois_table = Table(
                title="Ownership & Registration", border_style="green")
            whois_table.add_column("Field", style="dim")
            whois_table.add_column("Data")
            whois_table.add_row("Registrar", str(w.registrar))
            whois_table.add_row("Creation Date", str(w.creation_date))
            whois_table.add_row("Expiration", str(w.expiration_date))
            whois_table.add_row("Org", str(w.org))
            console.print(whois_table)
        except:
            console.print("[red][!] WHOIS lookup failed.[/red]")

    except Exception as e:
        console.print(f"[bold red][!] Recon Failed:[/bold red] {e}")

    console.print(
        f"\n[bold green][+] Reconnaissance for {domain} complete.[/bold green]")
    input("\nPress Enter to return to main menu...")
