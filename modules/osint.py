"""
modules/osint.py — Unified OSINT & Reconnaissance Engine
Covers: DNS recon, subdomain bruteforce, CT logs, Shodan/InternetDB,
Wayback Machine mining, Google Dork generation, Username tracking (14 platforms),
Phone number intelligence, Geo-IP tracking.
All findings saved to mission database.
"""

import os
import re
import json
import socket
import threading
import logging
import concurrent.futures
import questionary
import requests
import urllib3
import dns.resolver
import phonenumbers
from phonenumbers import carrier, geocoder, timezone as pn_timezone
from concurrent.futures import ThreadPoolExecutor, as_completed
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from core.ui import draw_header, Q_STYLE
from core.database import db

logging.getLogger("urllib3").setLevel(logging.CRITICAL)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
console = Console()

# ─────────────────────────────────────────────────────────────────────────────
#  CONSTANTS
# ─────────────────────────────────────────────────────────────────────────────

SUB_DICT = [
    'www', 'mail', 'remote', 'vpn', 'dev', 'stage', 'api', 'git', 'ssh', 'webmail',
    'portal', 'admin', 'test', 'support', 'cloud', 'autodiscover', 'sip', 'm', 'blog',
    'shop', 'beta', 'app', 'jenkins', 'proxy', 'secure', 'status', 'wiki', 'docs',
    'internal', 'staging', 'demo', 'mysql', 'db', 'ftp', 'ns1', 'ns2', 'smtp', 'pop',
    'imap', 'exchange', 'owa', 'rdp', 'citrix', 'jira', 'confluence', 'gitlab',
    'github', 'grafana', 'kibana', 'monitoring', 'cdn', 'assets', 'static', 'images',
    'media', 'download', 'upload', 'backup', 'archive', 'legacy', 'old', 'new',
]

SOCIAL_SITES = {
    "GitHub":      "https://github.com/{}",
    "Twitter":     "https://twitter.com/{}",
    "Instagram":   "https://www.instagram.com/{}/",
    "Reddit":      "https://www.reddit.com/user/{}",
    "Pinterest":   "https://www.pinterest.com/{}/",
    "Medium":      "https://medium.com/@{}",
    "SoundCloud":  "https://soundcloud.com/{}",
    "Tumblr":      "https://{}.tumblr.com",
    "Steam":       "https://steamcommunity.com/id/{}",
    "Vimeo":       "https://vimeo.com/{}",
    "Snapchat":    "https://www.snapchat.com/add/{}",
    "TikTok":      "https://www.tiktok.com/@{}",
    "Spotify":     "https://open.spotify.com/user/{}",
    "Twitch":      "https://www.twitch.tv/{}",
}

HEADERS = {
    'User-Agent': (
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
        'AppleWebKit/537.36 (KHTML, like Gecko) '
        'Chrome/120.0.0.0 Safari/537.36'
    ),
    'Accept-Language': 'en-US,en;q=0.9',
}


# ─────────────────────────────────────────────────────────────────────────────
#  DNS & SUBDOMAIN ENGINE
# ─────────────────────────────────────────────────────────────────────────────

class DNSReconEngine:
    def __init__(self, domain: str):
        self.domain = domain
        self.found_assets = {}
        self.lock = threading.Lock()
        self.wildcard_ip = None

    def detect_wildcard(self):
        try:
            ans = dns.resolver.resolve(f"xyznonexistent987.{self.domain}", 'A')
            self.wildcard_ip = str(ans[0])
            console.print(
                f"[yellow][!] Wildcard DNS detected: {self.wildcard_ip} — filtering results.[/yellow]")
        except Exception:
            pass

    def _resolve_sub(self, sub: str):
        fqdn = f"{sub}.{self.domain}"
        try:
            ans = dns.resolver.resolve(fqdn, 'A')
            ips = [str(r) for r in ans]
            if self.wildcard_ip and self.wildcard_ip in ips:
                return
            with self.lock:
                self.found_assets[fqdn] = ips
        except Exception:
            pass

    def enum_records(self):
        table = Table(
            title=f"DNS Records: {self.domain}", border_style="cyan", expand=True)
        table.add_column("Type",   style="yellow")
        table.add_column("Value",  style="white")

        for rtype in ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA', 'CNAME']:
            try:
                answers = dns.resolver.resolve(self.domain, rtype)
                for r in answers:
                    val = str(r)
                    table.add_row(rtype, val)
                    db.log("DNS-Recon", self.domain, f"{rtype}: {val}", "INFO")
            except Exception:
                pass

        console.print(table)

    def brute_subdomains(self):
        self.detect_wildcard()
        console.print(
            f"[*] Bruteforcing {len(SUB_DICT)} subdomains on [cyan]{self.domain}[/cyan]...")

        with Progress(SpinnerColumn(), TextColumn("{task.description}"), BarColumn(), console=console) as prog:
            task = prog.add_task(
                "[cyan]Resolving subdomains...", total=len(SUB_DICT))
            with ThreadPoolExecutor(max_workers=30) as ex:
                futures = {ex.submit(self._resolve_sub, s): s for s in SUB_DICT}
                for f in as_completed(futures):
                    prog.update(task, advance=1)

        if self.found_assets:
            t = Table(
                title=f"Subdomains Discovered ({len(self.found_assets)})", border_style="green", expand=True)
            t.add_column("Subdomain", style="cyan")
            t.add_column("IPs",       style="white")
            for fqdn, ips in sorted(self.found_assets.items()):
                ip_str = ", ".join(ips)
                t.add_row(fqdn, ip_str)
                db.log("DNS-Subdomain", fqdn, f"IPs: {ip_str}", "HIGH")
            console.print(t)
        else:
            console.print("[yellow][-] No subdomains found.[/yellow]")

    def run(self):
        draw_header(f"DNS Recon: {self.domain}")
        self.enum_records()
        console.print()
        self.brute_subdomains()
        questionary.press_any_key_to_continue(style=Q_STYLE).ask()


def dns_recon():
    domain = questionary.text(
        "Target Domain (e.g., example.com):", style=Q_STYLE).ask()
    if domain:
        DNSReconEngine(domain.strip()).run()


# ─────────────────────────────────────────────────────────────────────────────
#  SHODAN / INTERNETDB
# ─────────────────────────────────────────────────────────────────────────────

def shodan_intel():
    draw_header("Attack Surface — Shodan / InternetDB")
    target = questionary.text("Target IP or Domain:", style=Q_STYLE).ask()
    if not target:
        return

    target = target.strip()
    try:
        ip = socket.gethostbyname(target)
    except Exception:
        console.print(f"[red][!] Could not resolve: {target}[/red]")
        questionary.press_any_key_to_continue(style=Q_STYLE).ask()
        return

    console.print(f"[*] Querying InternetDB for [cyan]{ip}[/cyan]...")

    try:
        res = requests.get(f"https://internetdb.shodan.io/{ip}", timeout=15)
        if res.status_code == 200:
            data = res.json()
            table = Table(
                title=f"Attack Surface: {ip}", border_style="bold red", expand=True)
            table.add_column("Property", style="cyan")
            table.add_column("Details",  style="white")

            hostnames = data.get("hostnames", [])
            ports = [str(p) for p in data.get("ports", [])]
            tags = data.get("tags", [])
            cpes = data.get("cpes", [])
            vulns = data.get("vulns", [])

            table.add_row("Hostnames", ", ".join(
                hostnames) if hostnames else "None")
            table.add_row("Open Ports", ", ".join(ports) if ports else "None")
            table.add_row("Tags", ", ".join(tags) if tags else "None")

            if cpes:
                table.add_row("Software (CPEs)", "\n".join(cpes[:10]))
            if vulns:
                vuln_str = "\n".join(vulns[:15])
                table.add_row("CVEs", f"[bold red]{vuln_str}[/bold red]")
                db.log("Shodan-Intel", ip,
                       f"CVEs found: {', '.join(vulns[:15])}", "CRITICAL")
            else:
                table.add_row("CVEs", "[bold green]None Detected[/bold green]")

            db.log("Shodan-Intel", ip,
                   f"Ports: {', '.join(ports)} | Hostnames: {', '.join(hostnames)}", "HIGH")
            console.print(table)

        elif res.status_code == 404:
            console.print("[yellow][+] No data indexed for this IP.[/yellow]")
        else:
            console.print(f"[red][!] API Error: {res.status_code}[/red]")

    except Exception as e:
        console.print(f"[red][!] Error: {e}[/red]")

    questionary.press_any_key_to_continue(style=Q_STYLE).ask()


# ─────────────────────────────────────────────────────────────────────────────
#  WAYBACK MACHINE
# ─────────────────────────────────────────────────────────────────────────────

def wayback_intel():
    draw_header("Wayback Machine — Deep Archive Mining")
    domain = questionary.text(
        "Target Domain (e.g., example.com):", style=Q_STYLE).ask()
    if not domain:
        return

    domain = domain.strip()
    console.print(f"[*] Mining Wayback CDX API for [cyan]{domain}[/cyan]...")

    url = (f"http://web.archive.org/cdx/search/cdx"
           f"?url=*.{domain}/*&output=json&collapse=urlkey&limit=2000")

    try:
        with console.status("[bold cyan]Retrieving historical URL records...[/bold cyan]",
                            spinner="bouncingBar"):
            res = requests.get(url, timeout=25)

        if res.status_code == 200:
            data = res.json()
            if len(data) <= 1:
                console.print(
                    "[yellow][!] No archived endpoints found.[/yellow]")
                questionary.press_any_key_to_continue(style=Q_STYLE).ask()
                return

            endpoints = [row[2] for row in data[1:]]
            interesting = [
                ep for ep in endpoints
                if any(ext in ep.lower() for ext in [
                    '.php', '.asp', '.aspx', '.api', '.env', '.sql', '.bak', '.conf',
                    '.json', '.xml', '/admin', '/login', 'token=', 'key=', 'secret=',
                    '/api/', '/.git', 'backup', 'password', 'config'
                ])
            ]

            display = interesting if interesting else endpoints
            console.print(Panel(
                "\n".join(display[:50]),
                title=f"{'High-Value' if interesting else 'All'} Endpoints ({len(display)} shown / {len(endpoints)} total)",
                border_style="red" if interesting else "cyan"
            ))
            if len(display) > 50:
                console.print(f"[dim]... and {len(display)-50} more.[/dim]")

            db.log("Wayback-Intel", domain,
                   f"Archived endpoints: {len(endpoints)} total, {len(interesting)} high-value",
                   "HIGH" if interesting else "INFO")
        else:
            console.print("[red][!] Wayback API Error.[/red]")

    except Exception as e:
        console.print(f"[red][!] Error: {e}[/red]")

    questionary.press_any_key_to_continue(style=Q_STYLE).ask()


# ─────────────────────────────────────────────────────────────────────────────
#  GOOGLE DORK GENERATOR
# ─────────────────────────────────────────────────────────────────────────────

def dork_generator():
    draw_header("Google Dork Generator")
    domain = questionary.text("Target Domain:", style=Q_STYLE).ask()
    if not domain:
        return

    domain = domain.strip()
    dorks = {
        "Config & Env Files":   f"site:{domain} ext:xml | ext:conf | ext:cnf | ext:reg | ext:ini | ext:env | ext:cfg",
        "Database Dumps":       f"site:{domain} ext:sql | ext:dbf | ext:mdb | ext:db",
        "Log Files":            f"site:{domain} ext:log",
        "Exposed Documents":    f"site:{domain} ext:doc | ext:docx | ext:odt | ext:pdf | ext:xls | ext:xlsx | ext:csv",
        "Directory Listings":   f"site:{domain} intitle:index.of",
        "Login Pages":          f"site:{domain} inurl:login | inurl:admin | inurl:signin | inurl:dashboard",
        "API Keys Leaked":      f"site:{domain} \"api_key\" | \"api_secret\" | \"apikey\" | \"client_secret\"",
        "Git Exposed":          f"site:{domain} inurl:.git",
        "Backup Files":         f"site:{domain} ext:bak | ext:old | ext:backup | ext:orig",
        "PHP Info":             f"site:{domain} inurl:phpinfo.php | inurl:info.php",
    }

    table = Table(
        title=f"Google Dork Payloads — {domain}", border_style="magenta", expand=True)
    table.add_column("Category", style="cyan",  no_wrap=True)
    table.add_column("Query (paste into Google)", style="white")

    for category, query in dorks.items():
        table.add_row(category, query)

    console.print(table)
    db.log("Dork-Generator", domain,
           f"Generated {len(dorks)} dork queries", "INFO")
    questionary.press_any_key_to_continue(style=Q_STYLE).ask()


# ─────────────────────────────────────────────────────────────────────────────
#  USERNAME TRACKER
# ─────────────────────────────────────────────────────────────────────────────

def _check_username_platform(platform: str, url_fmt: str, username: str):
    url = url_fmt.format(username)
    try:
        res = requests.get(url, headers=HEADERS,
                           timeout=8, allow_redirects=True)
        if res.status_code == 200 and username.lower() in res.text.lower():
            return platform, "[bold green]LIVE[/bold green]", url
    except Exception:
        pass
    return None


def username_tracker():
    draw_header("Identity Profiler — Username Tracker")
    username = questionary.text(
        "Enter Username to Trace:", style=Q_STYLE).ask()
    if not username:
        return

    username = username.strip()
    table = Table(
        title=f"Digital Footprint: {username}", border_style="bold green", expand=True)
    table.add_column("Platform", style="cyan")
    table.add_column("Status",   style="white")
    table.add_column("Link",     style="blue")

    results = []
    with Progress(SpinnerColumn(), TextColumn("{task.description}"),
                  BarColumn(), console=console) as progress:
        task = progress.add_task(
            "[cyan]Scanning platforms...", total=len(SOCIAL_SITES))
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = {
                executor.submit(_check_username_platform, p, u, username): p
                for p, u in SOCIAL_SITES.items()
            }
            for future in as_completed(futures):
                result = future.result()
                if result:
                    results.append(result)
                    table.add_row(*result)
                progress.update(task, advance=1)

    console.print(table)
    console.print(
        f"[bold green][+] Found {len(results)} active profiles.[/bold green]")
    if results:
        db.log("Username-Tracker", username,
               f"Active profiles: {', '.join(r[0] for r in results)}", "HIGH")
    questionary.press_any_key_to_continue(style=Q_STYLE).ask()


# ─────────────────────────────────────────────────────────────────────────────
#  PHONE NUMBER INTEL
# ─────────────────────────────────────────────────────────────────────────────

def phone_intel():
    draw_header("Global Phone Tracer")
    num_str = questionary.text(
        "Target Phone (e.g. +14155552671):", style=Q_STYLE).ask()
    if not num_str:
        return

    num_str = num_str.strip()
    try:
        parsed = phonenumbers.parse(num_str)
        if not phonenumbers.is_valid_number(parsed):
            console.print("[red][!] Invalid number.[/red]")
            questionary.press_any_key_to_continue(style=Q_STYLE).ask()
            return

        carrier_name = carrier.name_for_number(parsed, "en")
        geo_info = geocoder.description_for_number(parsed, "en")
        timezones = pn_timezone.time_zones_for_number(parsed)
        number_type = phonenumbers.number_type(parsed)
        is_mobile = number_type == phonenumbers.PhoneNumberType.MOBILE
        formatted_int = phonenumbers.format_number(
            parsed, phonenumbers.PhoneNumberFormat.INTERNATIONAL)
        formatted_e164 = phonenumbers.format_number(
            parsed, phonenumbers.PhoneNumberFormat.E164)

        table = Table(
            title=f"Phone Intelligence: {num_str}", border_style="cyan", expand=True)
        table.add_column("Property",  style="cyan")
        table.add_column("Value",     style="white")
        table.add_row("International", formatted_int)
        table.add_row("E.164 Format",  formatted_e164)
        table.add_row("Carrier",       carrier_name or "Unknown")
        table.add_row("Region",        geo_info or "Unknown")
        table.add_row(
            "Type",          "Mobile" if is_mobile else "Fixed/Other")
        table.add_row("Timezones",     ", ".join(
            timezones) if timezones else "Unknown")
        table.add_row("Country Code",  f"+{parsed.country_code}")

        console.print(table)
        db.log("Phone-Intel", num_str,
               f"Carrier: {carrier_name} | Region: {geo_info} | Mobile: {is_mobile}", "INFO")

    except Exception as e:
        console.print(f"[red][!] Error: {e}[/red]")

    questionary.press_any_key_to_continue(style=Q_STYLE).ask()


# ─────────────────────────────────────────────────────────────────────────────
#  GEO-IP TRACKER
# ─────────────────────────────────────────────────────────────────────────────

def geolocate():
    draw_header("Geo-IP Tracker")
    target = questionary.text("Target IP or Domain:", style=Q_STYLE).ask()
    if not target:
        return

    target = target.strip()
    try:
        ip = socket.gethostbyname(target)
    except Exception:
        ip = target

    try:
        res = requests.get(
            f"https://ipapi.co/{ip}/json/", timeout=10, headers=HEADERS)
        data = res.json()

        if data.get("error"):
            console.print(
                f"[red][!] API Error: {data.get('reason', 'unknown')}[/red]")
            questionary.press_any_key_to_continue(style=Q_STYLE).ask()
            return

        table = Table(title=f"Geo-IP: {ip}", border_style="cyan", expand=True)
        table.add_column("Property", style="cyan")
        table.add_column("Value",    style="white")

        fields = [
            ("IP",           data.get("ip")),
            ("City",         data.get("city")),
            ("Region",       data.get("region")),
            ("Country",      data.get("country_name")),
            ("Postal Code",  data.get("postal")),
            ("Latitude",     str(data.get("latitude"))),
            ("Longitude",    str(data.get("longitude"))),
            ("Timezone",     data.get("timezone")),
            ("ISP / Org",    data.get("org")),
            ("ASN",          data.get("asn")),
        ]
        for label, value in fields:
            if value:
                table.add_row(label, value)

        console.print(table)

        lat = data.get("latitude", 0)
        lon = data.get("longitude", 0)
        console.print(
            f"\n[dim]Google Maps: https://maps.google.com/?q={lat},{lon}[/dim]")

        db.log("Geo-IP", ip,
               f"City: {data.get('city')} | Country: {data.get('country_name')} | "
               f"ISP: {data.get('org')} | Coords: {lat},{lon}", "INFO")

    except Exception as e:
        console.print(f"[red][!] Error: {e}[/red]")

    questionary.press_any_key_to_continue(style=Q_STYLE).ask()


# ─────────────────────────────────────────────────────────────────────────────
#  MAIN OSINT MENU
# ─────────────────────────────────────────────────────────────────────────────

def run_osint():
    while True:
        os.system('cls' if os.name == 'nt' else 'clear')
        draw_header("OSINT Suite — Open Source Intelligence")

        choice = questionary.select(
            "Select OSINT Module:",
            choices=[
                Separator("─── NETWORK & DOMAIN OSINT ───────────────────"),
                questionary.Choice(
                    "DNS Recon & Subdomain Bruteforce",     value="dns"),
                questionary.Choice(
                    "Attack Surface  (Shodan / InternetDB)", value="shodan"),
                questionary.Choice(
                    "Wayback Machine  (Archive Mining)",     value="wayback"),
                questionary.Choice("Google Dork Generator",
                                   value="dork"),
                Separator("─── PERSON & IDENTITY OSINT ──────────────────"),
                questionary.Choice(
                    "Username Tracker  (14 Platforms)",      value="username"),
                questionary.Choice(
                    "Phone Number Intelligence",             value="phone"),
                questionary.Choice("Geo-IP Tracker",
                                   value="geo"),
                Separator("─── NAVIGATION ────────────────────────────────"),
                questionary.Choice("Return to Main Menu",
                                   value="back"),
            ],
            style=Q_STYLE
        ).ask()

        if not choice or choice == "back":
            break

        actions = {
            "dns":      dns_recon,
            "shodan":   shodan_intel,
            "wayback":  wayback_intel,
            "dork":     dork_generator,
            "username": username_tracker,
            "phone":    phone_intel,
            "geo":      geolocate,
        }
        if choice in actions:
            try:
                actions[choice]()
            except KeyboardInterrupt:
                console.print("\n[yellow][*] Interrupted.[/yellow]")
            except Exception as e:
                console.print(f"[red][!] Error: {e}[/red]")
                questionary.press_any_key_to_continue(style=Q_STYLE).ask()


if __name__ == "__main__":
    run_osint()
