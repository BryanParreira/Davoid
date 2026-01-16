import requests
import phonenumbers
import urllib3
import dns.resolver
import re
import json
from phonenumbers import carrier, geocoder, timezone
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from core.ui import draw_header

urllib3.disable_warnings()
console = Console()

# --- 1. USERNAME TRACKER (Elite Expanded) ---
SOCIAL_SITES = {
    "GitHub": "https://github.com/{}",
    "Twitter": "https://twitter.com/{}",
    "Instagram": "https://www.instagram.com/{}/",
    "Reddit": "https://www.reddit.com/user/{}",
    "Pinterest": "https://www.pinterest.com/{}/",
    "Medium": "https://medium.com/@{}",
    "SoundCloud": "https://soundcloud.com/{}",
    "Tumblr": "https://{}.tumblr.com",
    "Steam": "https://steamcommunity.com/id/{}",
    "Vimeo": "https://vimeo.com/{}",
    "Snapchat": "https://www.snapchat.com/add/{}",
    "TikTok": "https://www.tiktok.com/@{}"
}


def username_tracker():
    draw_header("Holmes Intel: Username Profiler")
    username = console.input(
        "[bold yellow]Enter Username to Trace: [/bold yellow]").strip()
    if not username:
        return

    table = Table(
        title=f"Digital Footprint: {username}", border_style="bold green", expand=True)
    table.add_column("Platform", style="cyan")
    table.add_column("Status", style="white")
    table.add_column("Direct Intelligence Link", style="blue")

    with Progress(SpinnerColumn(), TextColumn("{task.description}"), BarColumn(), console=console) as progress:
        task = progress.add_task(
            "[cyan]Crawling Global Platforms...", total=len(SOCIAL_SITES))
        for platform, url_fmt in SOCIAL_SITES.items():
            url = url_fmt.format(username)
            try:
                headers = {'User-Agent': 'Mozilla/5.0'}
                res = requests.get(url, headers=headers,
                                   timeout=5, allow_redirects=True)
                if res.status_code == 200 and username.lower() in res.text.lower():
                    table.add_row(
                        platform, "[bold green]LIVE[/bold green]", url)
            except:
                pass
            progress.update(task, advance=1)

    console.print(table)
    input("\nPress Enter to return...")

# --- 2. GLOBAL PHONE INTELLIGENCE ---


def phone_intel():
    draw_header("Holmes Intel: Global Phone Tracer")
    num_str = console.input(
        "[bold yellow]Enter Target Phone (e.g., +14155552671): [/bold yellow]").strip()
    if not num_str:
        return

    try:
        parsed_num = phonenumbers.parse(num_str)
        if not phonenumbers.is_valid_number(parsed_num):
            console.print(
                "[red][!] Invalid number format. Use E.164 (e.g., +1...)[/red]")
            return

        table = Table(
            title=f"Carrier & Geo Intel: {num_str}", border_style="bold magenta")
        table.add_column("Field", style="cyan")
        table.add_column("Value", style="white")

        table.add_row("Line Provider (Carrier)",
                      carrier.name_for_number(parsed_num, "en") or "Unknown")
        table.add_row("Geographic Region", geocoder.description_for_number(
            parsed_num, "en") or "Unknown")
        table.add_row("Timezone Assignments", ", ".join(
            timezone.time_zones_for_number(parsed_num)))
        table.add_row("Formatting Verification",
                      "Valid E.164 International Format")

        console.print(table)
    except Exception as e:
        console.print(f"[red][!] Processing Error: {e}[/red]")
    input("\nPress Enter...")

# --- 3. GEOSPATIAL & INFRASTRUCTURE (FIXED) ---


def geolocate():
    """Fixed: Corrected malformed Map Evidence URL."""
    draw_header("Holmes Intel: Geospatial Tracker")
    target = console.input(
        "[bold yellow]Enter Target IP or Domain: [/bold yellow]").strip()
    if not target:
        return

    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
    }

    try:
        fields = "status,message,country,countryCode,regionName,city,zip,lat,lon,timezone,isp,org,as,query"
        url = f"http://ip-api.com/json/{target}?fields={fields}"

        response = requests.get(url, headers=headers, timeout=10)
        res = response.json()

        if res.get('status') == 'fail':
            console.print(
                f"[red][!] API Error: {res.get('message', 'Unknown failure')}[/red]")
            return

        table = Table(
            title=f"Infrastructural Context: {target}", border_style="bold blue")
        table.add_column("Intelligence Metric", style="cyan")
        table.add_column("Value", style="white")

        table.add_row(
            "Location", f"{res.get('city')}, {res.get('regionName')}, {res.get('country')}")
        table.add_row("Coordinates", f"{res.get('lat')}, {res.get('lon')}")
        table.add_row("ISP / Organization",
                      f"{res.get('isp')} / {res.get('org')}")
        table.add_row("ASN", res.get('as'))
        table.add_row("Timezone", res.get('timezone'))

        console.print(table)

        # Fixed Map URL logic
        lat = res.get('lat')
        lon = res.get('lon')
        maps_url = f"https://www.google.com/maps?q={lat},{lon}"
        console.print(f"\n[dim][*] Evidence Map: {maps_url}[/dim]")

    except requests.exceptions.Timeout:
        console.print(
            "[red][!] Error: Connection to Geolocator API timed out.[/red]")
    except Exception as e:
        console.print(f"[red][!] Connectivity Error: {e}[/red]")

    input("\nPress Enter to return...")

# --- 4. ROBOTS & HIDDEN PATH SCRAPER ---


def robots_scraper():
    draw_header("Holmes Intel: Asset Discovery")
    domain = console.input(
        "[bold yellow]Enter Domain (e.g., target.com): [/bold yellow]").strip()
    if not domain:
        return

    url = f"http://{domain}/robots.txt"
    try:
        r = requests.get(url, timeout=5)
        if r.status_code == 200:
            console.print(
                f"\n[bold green][+] Robots.txt Found for {domain}:[/bold green]")

            disallowed = [line for line in r.text.splitlines()
                          if line.startswith("Disallow")]
            if disallowed:
                table = Table(title="Discovered Hidden Directories",
                              border_style="yellow")
                table.add_column("Sensitive Path", style="dim white")
                for path in disallowed[:20]:
                    table.add_row(path.split(": ")[
                                  1] if ": " in path else path)
                console.print(table)
            else:
                console.print(
                    "[yellow][!] Robots.txt present but no Disallow paths found.[/yellow]")
        else:
            console.print(
                "[red][!] No robots.txt available for this domain.[/red]")
    except:
        console.print(
            "[red][!] Connection failed during asset discovery.[/red]")
    input("\nPress Enter...")

# --- 5. DOMAIN REPUTATION & THREAT INTEL ---


def reputation_check():
    draw_header("Holmes Intel: Reputation Audit")
    domain = console.input(
        "[bold yellow]Enter Domain to Verify: [/bold yellow]").strip()
    if not domain:
        return

    try:
        url = f"https://www.google.com/transparencyreport/safebrowsing/diagnostic/index.html?site={domain}"
        res = requests.get(url, timeout=5)

        if "No unsafe content found" in res.text:
            console.print(
                f"[bold green][+] {domain}[/bold green] is verified CLEAN by global indicators.")
        elif "Unsafe" in res.text:
            console.print(
                f"[bold red][!] ALERT: {domain}[/bold red] has been flagged for malicious activity!")
        else:
            console.print(
                f"[yellow][!] Status for {domain} is currently ambiguous/unknown.[/yellow]")

    except:
        console.print("[red][!] Reputation Audit timed out.[/red]")
    input("\nPress Enter...")

# --- 6. TACTICAL DNS & PASSIVE SUBDOMAINS ---


def dns_intel():
    draw_header("Holmes Intel: DNS Infrastructure")
    domain = console.input(
        "[bold yellow]Enter Target Domain: [/bold yellow]").strip()
    if not domain:
        return

    subdomains = set()
    try:
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        res = requests.get(url, timeout=15)

        if res.status_code == 200:
            try:
                data = res.json()
                for entry in data:
                    name = entry['name_value']
                    for sub in name.split('\n'):
                        if not sub.startswith('*') and domain in sub:
                            subdomains.add(sub.strip())
            except json.JSONDecodeError:
                console.print("[red][!] Error parsing passive DNS data.[/red]")
                return

        if subdomains:
            table = Table(
                title=f"Passive Subdomain Discovery: {domain}", border_style="cyan")
            table.add_column("Subdomain", style="white")

            for s in sorted(list(subdomains))[:25]:
                table.add_row(s)

            console.print(table)
            console.print(
                f"\n[dim][*] Total passive assets identified: {len(subdomains)}[/dim]")
        else:
            console.print(
                "[yellow][!] No passive subdomains found in CT logs.[/yellow]")

    except requests.exceptions.Timeout:
        console.print("[red][!] Passive DNS service timed out.[/red]")
    except Exception as e:
        console.print(f"[red][!] Passive DNS lookup failed: {e}[/red]")

    input("\nPress Enter to return...")

# --- 7. TACTICAL GOOGLE DORK ENGINE ---


def dork_generator():
    draw_header("Holmes Intel: Google Dorking")
    domain = console.input(
        "[bold yellow]Target Domain for Dorking: [/bold yellow]").strip()
    if not domain:
        return

    dorks = {
        "Directory Listing": f"site:{domain} intitle:index.of",
        "Configuration Leaks": f"site:{domain} ext:env OR ext:conf OR ext:ini",
        "Public Backups": f"site:{domain} ext:bak OR ext:old OR ext:backup OR ext:sql",
        "Sensitive Docs": f"site:{domain} ext:pdf OR ext:doc OR ext:docx OR ext:xls",
        "Admin Logins": f"site:{domain} inurl:admin OR inurl:login OR inurl:dashboard"
    }

    table = Table(
        title=f"Tactical Dorks: {domain}", border_style="bold yellow", expand=True)
    table.add_column("Intelligence Goal", style="cyan")
    table.add_column("Dork Query (Copy/Paste to Google)", style="white")

    for goal, query in dorks.items():
        table.add_row(goal, query)

    console.print(table)
    input("\nPress Enter to return...")