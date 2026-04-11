"""
recon.py — Unified Recon & OSINT Engine
Consolidates: DNS recon, subdomain brute-force, CT logs, Shodan/InternetDB,
Wayback mining, Google Dork generation, Username tracking, Phone intel,
Geo-IP tracking — all in one module.
"""

import os
import re
import dns.resolver
import threading
import requests
import json
import socket
import logging
import concurrent.futures
import questionary
import urllib3
import phonenumbers
from phonenumbers import carrier, geocoder, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich.panel import Panel
from core.ui import draw_header, Q_STYLE

try:
    from core.config import load_config
except ImportError:
    def load_config(): return None

logging.getLogger("urllib3").setLevel(logging.CRITICAL)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
console = Console()

# ── Subdomain wordlist ────────────────────────────────────────────────────────
SUB_DICT = [
    'www', 'mail', 'remote', 'vpn', 'dev', 'stage', 'api', 'git', 'ssh',
    'webmail', 'portal', 'admin', 'test', 'support', 'cloud', 'autodiscover',
    'sip', 'm', 'blog', 'shop', 'beta', 'app', 'jenkins', 'proxy', 'secure',
    'status', 'wiki', 'docs', 'internal', 'staging', 'demo', 'mysql', 'db',
    'ftp', 'ns1', 'ns2', 'smtp', 'pop', 'imap', 'exchange', 'owa', 'rdp',
    'citrix', 'jira', 'confluence', 'gitlab', 'github', 'grafana', 'kibana',
]

# ── Social platforms for username tracking ────────────────────────────────────
SOCIAL_SITES = {
    "GitHub":     "https://github.com/{}",
    "Twitter":    "https://twitter.com/{}",
    "Instagram":  "https://www.instagram.com/{}/",
    "Reddit":     "https://www.reddit.com/user/{}",
    "Pinterest":  "https://www.pinterest.com/{}/",
    "Medium":     "https://medium.com/@{}",
    "SoundCloud": "https://soundcloud.com/{}",
    "Tumblr":     "https://{}.tumblr.com",
    "Steam":      "https://steamcommunity.com/id/{}",
    "Vimeo":      "https://vimeo.com/{}",
    "Snapchat":   "https://www.snapchat.com/add/{}",
    "TikTok":     "https://www.tiktok.com/@{}",
    "Spotify":    "https://open.spotify.com/user/{}",
    "Twitch":     "https://www.twitch.tv/{}",
}


# ══════════════════════════════════════════════════════════════════════════════
#  DNS & SUBDOMAIN ENGINE
# ══════════════════════════════════════════════════════════════════════════════

class DNSReconEngine:
    def __init__(self, domain):
        self.domain       = domain
        self.found_assets = {}
        self.lock         = threading.Lock()
        self.wildcard_ip  = None

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
            console.print(f"[dim red][!] Passive discovery error (crt.sh): {e}[/dim red]")
        return []

    def resolve_target(self, target):
        try:
            resolver          = dns.resolver.Resolver()
            resolver.timeout  = 2
            resolver.lifetime = 2
            ans = resolver.resolve(target, 'A')
            ip  = str(ans[0])
            if ip == self.wildcard_ip:
                return None
            return ip
        except Exception:
            return None

    def brute_worker(self, sub):
        target = f"{sub}.{self.domain}".lower()
        ip     = self.resolve_target(target)
        if ip:
            with self.lock:
                self.found_assets[target] = ip

    def run(self):
        draw_header("Infrastructure & DNS Recon")
        console.print(Panel(
            f"Target: [bold cyan]{self.domain}[/bold cyan]",
            border_style="magenta"))

        # ── Core DNS records ──────────────────────────────────────────────────
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

        # ── Wildcard detection ────────────────────────────────────────────────
        self.detect_wildcard()

        # ── Hybrid passive + active discovery ─────────────────────────────────
        with Progress(SpinnerColumn(), TextColumn("{task.description}"),
                      console=console) as progress:

            t1 = progress.add_task(
                "[yellow]Collecting CT log data (passive)...", total=None)
            passive_subs = self.get_passive_creds()
            progress.update(t1, description="[green]Passive collection complete.")

            t2 = progress.add_task(
                "[cyan]Active brute-force...", total=len(SUB_DICT))
            with ThreadPoolExecutor(max_workers=15) as ex:
                for _ in as_completed(
                        [ex.submit(self.brute_worker, s) for s in SUB_DICT]):
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

        # ── Results ───────────────────────────────────────────────────────────
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

            if questionary.confirm(
                    "Export results to JSON?", default=False, style=Q_STYLE).ask():
                output   = {"domain": self.domain, "assets": self.found_assets}
                os.makedirs("logs", exist_ok=True)
                filename = f"logs/recon_{self.domain.replace('.', '_')}.json"
                with open(filename, 'w') as f:
                    json.dump(output, f, indent=4)
                console.print(f"[green][+] Report saved: {filename}[/green]")
        else:
            console.print("[red][!] No subdomains discovered.[/red]")

        questionary.press_any_key_to_continue(style=Q_STYLE).ask()


# ══════════════════════════════════════════════════════════════════════════════
#  SHODAN / INTERNETDB
# ══════════════════════════════════════════════════════════════════════════════

def shodan_intel():
    draw_header("InternetDB Attack Surface (No API Key Required)")
    console.print("[dim]Powered by InternetDB — free Shodan tier[/dim]\n")

    target = questionary.text("Target IP Address:", style=Q_STYLE).ask()
    if not target:
        return

    try:
        ip = socket.gethostbyname(target)
    except Exception:
        return console.print(f"[red][!] Failed to resolve: {target}[/red]")

    console.print(f"[*] Querying InternetDB for {ip}...")
    try:
        res = requests.get(f"https://internetdb.shodan.io/{ip}", timeout=15)
        if res.status_code == 200:
            data  = res.json()
            table = Table(title=f"Attack Surface: {ip}",
                          border_style="bold red", expand=True)
            table.add_column("Property", style="cyan")
            table.add_column("Details",  style="white")

            hostnames = data.get("hostnames", [])
            table.add_row("Hostnames",
                          ", ".join(hostnames) if hostnames else "None")

            ports = [str(p) for p in data.get("ports", [])]
            table.add_row("Open Ports",
                          ", ".join(ports) if ports else "None")

            tags = data.get("tags", [])
            table.add_row("Tags",
                          ", ".join(tags) if tags else "None")

            cpes = data.get("cpes", [])
            if cpes:
                cpe_str = "\n".join(cpes[:10])
                if len(cpes) > 10:
                    cpe_str += f"\n[dim]...and {len(cpes)-10} more[/dim]"
                table.add_row("Software (CPEs)", cpe_str)

            vulns = data.get("vulns", [])
            if vulns:
                vuln_str = "\n".join(vulns[:15])
                if len(vulns) > 15:
                    vuln_str += f"\n[dim]...and {len(vulns)-15} more[/dim]"
                table.add_row("CVEs",
                              f"[bold red]{vuln_str}[/bold red]")
            else:
                table.add_row("CVEs", "[bold green]None Detected[/bold green]")

            console.print(table)

        elif res.status_code == 404:
            console.print("[yellow][+] No data indexed for this IP.[/yellow]")
        else:
            console.print(f"[red][!] API Error: {res.status_code}[/red]")

    except Exception as e:
        console.print(f"[red][!] Error: {e}[/red]")

    questionary.press_any_key_to_continue(style=Q_STYLE).ask()


# ══════════════════════════════════════════════════════════════════════════════
#  WAYBACK + DORK (combined submenu)
# ══════════════════════════════════════════════════════════════════════════════

def wayback_intel():
    draw_header("Wayback Machine — Deep Archive Mining")
    domain = questionary.text(
        "Target Domain (e.g., example.com):", style=Q_STYLE).ask()
    if not domain:
        return

    console.print(f"[*] Mining Wayback CDX API for {domain}...")
    url = (f"http://web.archive.org/cdx/search/cdx"
           f"?url=*.{domain}/*&output=json&collapse=urlkey&limit=1000")

    try:
        with console.status(
                "[bold cyan]Retrieving historical URL records...[/bold cyan]",
                spinner="bouncingBar"):
            res = requests.get(url, timeout=20)

        if res.status_code == 200:
            data = res.json()
            if len(data) <= 1:
                console.print("[yellow][!] No archived endpoints found.[/yellow]")
                return questionary.press_any_key_to_continue(style=Q_STYLE).ask()

            endpoints   = [row[2] for row in data[1:]]
            interesting = [
                ep for ep in endpoints
                if any(ext in ep.lower()
                       for ext in ['.php', '.api', '.env', '.sql', '.bak',
                                   '/admin', '/login', 'token=', 'key='])
            ]

            if interesting:
                console.print(Panel(
                    "\n".join(interesting[:40]),
                    title=f"High-Value Endpoints ({len(interesting)} total)",
                    border_style="red"))
                if len(interesting) > 40:
                    console.print(
                        f"[dim]... and {len(interesting)-40} more.[/dim]")
            else:
                console.print(Panel(
                    "\n".join(endpoints[:40]),
                    title=f"Endpoints Found ({len(endpoints)-1} total)",
                    border_style="cyan"))
        else:
            console.print("[red][!] Wayback API Error.[/red]")
    except Exception as e:
        console.print(f"[red][!] Error: {e}[/red]")

    questionary.press_any_key_to_continue(style=Q_STYLE).ask()


def dork_generator():
    draw_header("Google Dork Generator")
    domain = questionary.text("Target Domain:", style=Q_STYLE).ask()
    if not domain:
        return

    dorks = {
        "Config Files":    (f"site:{domain} ext:xml | ext:conf | ext:cnf | "
                            f"ext:reg | ext:inf | ext:rdp | ext:cfg | ext:txt | ext:ini"),
        "Database Dumps":  f"site:{domain} ext:sql | ext:dbf | ext:mdb",
        "Log Files":       f"site:{domain} ext:log",
        "Exposed Docs":    (f"site:{domain} ext:doc | ext:docx | ext:odt | "
                            f"ext:pdf | ext:rtf | ext:ppt | ext:pptx | ext:csv"),
        "Directory Listing": f"site:{domain} intitle:index.of",
    }

    table = Table(title="Google Dork Payloads", border_style="magenta")
    table.add_column("Type",                    style="cyan")
    table.add_column("Query (paste in Google)", style="white")
    for k, v in dorks.items():
        table.add_row(k, v)
    console.print(table)
    questionary.press_any_key_to_continue(style=Q_STYLE).ask()


def passive_intel_menu():
    """Combined Wayback + Dork submenu."""
    while True:
        choice = questionary.select(
            "Passive Archive Intel:",
            choices=[
                "1. Wayback Machine (Hidden Endpoints)",
                "2. Google Dork Generator",
                "Back",
            ],
            style=Q_STYLE,
        ).ask()
        if not choice or choice == "Back":
            break
        if "Wayback" in choice:
            wayback_intel()
        elif "Dork" in choice:
            dork_generator()


# ══════════════════════════════════════════════════════════════════════════════
#  PERSON OSINT (Username + Phone + Geo combined)
# ══════════════════════════════════════════════════════════════════════════════

def _check_username_platform(platform, url_fmt, username):
    url     = url_fmt.format(username)
    headers = {
        'User-Agent': (
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
            'AppleWebKit/537.36 (KHTML, like Gecko) '
            'Chrome/120.0.0.0 Safari/537.36'),
        'Accept-Language': 'en-US,en;q=0.9',
    }
    try:
        res = requests.get(url, headers=headers, timeout=6, allow_redirects=True)
        if res.status_code == 200 and username.lower() in res.text.lower():
            return platform, "[bold green]LIVE[/bold green]", url
    except Exception:
        pass
    return None


def username_tracker():
    draw_header("Identity Profiler — Username Tracker")
    username = questionary.text("Enter Username to Trace:", style=Q_STYLE).ask()
    if not username:
        return

    table = Table(
        title=f"Digital Footprint: {username}",
        border_style="bold green", expand=True)
    table.add_column("Platform", style="cyan")
    table.add_column("Status",   style="white")
    table.add_column("Link",     style="blue")

    with Progress(SpinnerColumn(), TextColumn("{task.description}"),
                  BarColumn(), console=console) as progress:
        task = progress.add_task(
            "[cyan]Crawling Platforms...", total=len(SOCIAL_SITES))
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            futures = [
                executor.submit(_check_username_platform, p, u, username)
                for p, u in SOCIAL_SITES.items()
            ]
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result:
                    table.add_row(*result)
                progress.update(task, advance=1)

    console.print(table)
    questionary.press_any_key_to_continue(style=Q_STYLE).ask()


def phone_intel():
    draw_header("Global Phone Tracer")
    num_str = questionary.text(
        "Target Phone (e.g. +14155552671):", style=Q_STYLE).ask()
    if not num_str:
        return

    try:
        parsed = phonenumbers.parse(num_str)
        if not phonenumbers.is_valid_number(parsed):
            console.print("[red]Invalid number.[/red]")
            return

        table = Table(title="Carrier & Geo Intel", border_style="bold magenta")
        table.add_column("Field", style="cyan")
        table.add_column("Value", style="white")
        table.add_row("Carrier",  carrier.name_for_number(parsed, "en") or "N/A")
        table.add_row("Region",   geocoder.description_for_number(parsed, "en") or "Unknown")
        table.add_row("Timezone", ", ".join(timezone.time_zones_for_number(parsed)))
        console.print(table)

    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")

    questionary.press_any_key_to_continue(style=Q_STYLE).ask()


def geolocate():
    draw_header("Geospatial IP Tracker")
    target = questionary.text("Target IP or Domain:", style=Q_STYLE).ask()
    if not target:
        return
    try:
        if not re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", target):
            target = socket.gethostbyname(target)
        res = requests.get(f"http://ip-api.com/json/{target}", timeout=10).json()

        table = Table(title=f"Geo-Intel: {target}", border_style="bold blue")
        table.add_column("Metric", style="cyan")
        table.add_column("Value",  style="white")
        table.add_row("Location",    f"{res.get('city')}, {res.get('country')}")
        table.add_row("Coordinates", f"{res.get('lat')}, {res.get('lon')}")
        table.add_row("ISP",         res.get('isp', 'N/A'))
        console.print(table)

    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")

    questionary.press_any_key_to_continue(style=Q_STYLE).ask()


def person_osint_menu():
    """Combined Username + Phone + Geo submenu."""
    while True:
        choice = questionary.select(
            "Person OSINT:",
            choices=[
                "1. Username Tracker (14 platforms)",
                "2. Phone Number Intel",
                "3. Geo-IP Tracker",
                "Back",
            ],
            style=Q_STYLE,
        ).ask()
        if not choice or choice == "Back":
            break
        if "Username" in choice:
            username_tracker()
        elif "Phone" in choice:
            phone_intel()
        elif "Geo" in choice:
            geolocate()


# ══════════════════════════════════════════════════════════════════════════════
#  ENTRY POINTS (called from main.py)
# ══════════════════════════════════════════════════════════════════════════════

def dns_recon():
    domain = questionary.text(
        "Target Domain (e.g., example.com):", style=Q_STYLE).ask()
    if domain:
        DNSReconEngine(domain).run()


# Legacy aliases so main.py imports still resolve without changes
username_tracker  = username_tracker
phone_intel       = phone_intel
geolocate         = geolocate
dork_generator    = dork_generator
wayback_intel     = wayback_intel
shodan_intel      = shodan_intel
dns_intel         = dns_recon     # dns_intel now just calls dns_recon


if __name__ == "__main__":
    dns_recon()