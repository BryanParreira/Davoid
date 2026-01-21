import requests
import phonenumbers
import urllib3
import dns.resolver
import re
import json
import socket
import concurrent.futures
from phonenumbers import carrier, geocoder, timezone
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
from core.ui import draw_header

# Suppress SSL warnings and Scapy metadata
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
console = Console()

# --- 1. USERNAME TRACKER (Elite Expanded & Parallelized) ---
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
    "TikTok": "https://www.tiktok.com/@{}",
    "Spotify": "https://open.spotify.com/user/{}",
    "Twitch": "https://www.twitch.org/{}"
}

def check_username_platform(platform, url_fmt, username):
    """Worker function for parallel username crawling."""
    url = url_fmt.format(username)
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Accept-Language': 'en-US,en;q=0.9'
    }
    try:
        res = requests.get(url, headers=headers, timeout=6, allow_redirects=True)
        # Verify 200 OK and ensure the username actually appears in the body (prevents false positives)
        if res.status_code == 200 and username.lower() in res.text.lower():
            return platform, "[bold green]LIVE[/bold green]", url
    except:
        pass
    return None

def username_tracker():
    draw_header("Holmes Intel: Username Profiler")
    username = console.input("[bold yellow]Enter Username to Trace: [/bold yellow]").strip()
    if not username:
        return

    table = Table(title=f"Digital Footprint: {username}", border_style="bold green", expand=True)
    table.add_column("Platform", style="cyan")
    table.add_column("Status", style="white")
    table.add_column("Intelligence Link", style="blue")

    with Progress(
        SpinnerColumn(), 
        TextColumn("[progress.description]{task.description}"), 
        BarColumn(), 
        TimeElapsedColumn(), 
        console=console
    ) as progress:
        task = progress.add_task("[cyan]Crawling Global Platforms...", total=len(SOCIAL_SITES))
        
        # Parallel Execution for Speed
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(check_username_platform, p, u, username) for p, u in SOCIAL_SITES.items()]
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result:
                    table.add_row(*result)
                progress.update(task, advance=1)

    console.print(table)
    input("\nPress Enter to return...")


# --- 2. GLOBAL PHONE INTELLIGENCE ---
def phone_intel():
    draw_header("Holmes Intel: Global Phone Tracer")
    num_str = console.input("[bold yellow]Enter Target Phone (e.g., +14155552671): [/bold yellow]").strip()
    if not num_str:
        return

    try:
        parsed_num = phonenumbers.parse(num_str)
        if not phonenumbers.is_valid_number(parsed_num):
            console.print("[red][!] Invalid number format. Ensure Country Code is included (e.g. +1).[/red]")
            return

        table = Table(title=f"Carrier & Geo Intel: {num_str}", border_style="bold magenta")
        table.add_column("Field", style="cyan")
        table.add_column("Value", style="white")

        # Extracting Detailed Metrics
        carrier_info = carrier.name_for_number(parsed_num, "en") or "N/A / VOIP"
        region_info = geocoder.description_for_number(parsed_num, "en") or "International / Unknown"
        tz_info = ", ".join(timezone.time_zones_for_number(parsed_num))
        validity = "Verified [green]Valid[/green] E.164"

        table.add_row("Line Provider (Carrier)", carrier_info)
        table.add_row("Geographic Region", region_info)
        table.add_row("Timezone Assignments", tz_info)
        table.add_row("Formatting Status", validity)
        table.add_row("National Format", phonenumbers.format_number(parsed_num, phonenumbers.PhoneNumberFormat.NATIONAL))

        console.print(table)
    except Exception as e:
        console.print(f"[red][!] Processing Error: {e}[/red]")
    input("\nPress Enter...")


# --- 3. GEOSPATIAL & INFRASTRUCTURE ---
def geolocate():
    """High-precision IP/Domain Geospatial Profiler."""
    draw_header("Holmes Intel: Geospatial Tracker")
    target = console.input("[bold yellow]Enter Target IP or Domain: [/bold yellow]").strip()
    if not target:
        return

    headers = {'User-Agent': 'Mozilla/5.0'}
    try:
        # Resolve domain to IP if necessary
        ip_addr = target
        if not re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", target):
            ip_addr = socket.gethostbyname(target)

        fields = "status,message,country,countryCode,regionName,city,zip,lat,lon,timezone,isp,org,as,query"
        url = f"http://ip-api.com/json/{ip_addr}?fields={fields}"
        res = requests.get(url, headers=headers, timeout=10).json()

        if res.get('status') == 'fail':
            console.print(f"[red][!] API Error: {res.get('message', 'Target unreachable')}[/red]")
            return

        table = Table(title=f"Infrastructural Context: {target}", border_style="bold blue", expand=True)
        table.add_column("Metric", style="cyan")
        table.add_column("Intelligence Value", style="white")

        table.add_row("Physical Location", f"{res.get('city')}, {res.get('regionName')}, {res.get('country')} ({res.get('countryCode')})")
        table.add_row("GPS Coordinates", f"{res.get('lat')}, {res.get('lon')}")
        table.add_row("ISP / ASN", f"{res.get('isp')} | {res.get('as')}")
        table.add_row("Organization", res.get('org', 'N/A'))
        table.add_row("Postal / Timezone", f"{res.get('zip')} | {res.get('timezone')}")

        console.print(table)

        # Precise Map Evidence
        maps_url = f"https://www.google.com/maps?q={res.get('lat')},{res.get('lon')}"
        console.print(Panel(f"[dim]Evidence Map:[/dim] [link={maps_url}]{maps_url}[/link]", border_style="dim"))

    except Exception as e:
        console.print(f"[red][!] Connectivity Error: {e}[/red]")
    input("\nPress Enter to return...")


# --- 4. ROBOTS & HIDDEN PATH SCRAPER ---
def robots_scraper():
    draw_header("Holmes Intel: Asset Discovery")
    domain = console.input("[bold yellow]Enter Domain (e.g., target.com): [/bold yellow]").strip()
    if not domain:
        return

    # Normalize URL
    target_url = f"http://{domain}/robots.txt" if not domain.startswith("http") else f"{domain}/robots.txt"
    
    try:
        r = requests.get(target_url, timeout=7, headers={'User-Agent': 'Mozilla/5.0'})
        if r.status_code == 200:
            console.print(f"\n[bold green][+] Robots.txt Identified for {domain}[/bold green]")
            
            # Parsing disallowed paths while filtering duplicates
            disallowed = sorted(list(set([line.split(": ")[1].strip() for line in r.text.splitlines() if line.lower().startswith("disallow")])))
            
            if disallowed:
                table = Table(title="Sensitive Discovered Paths", border_style="yellow")
                table.add_column("Path", style="dim white")
                for path in disallowed[:30]: # Limit display to top 30
                    table.add_row(path)
                console.print(table)
            else:
                console.print("[yellow][!] Robots.txt present but no Disallow directives found.[/yellow]")
        else:
            console.print(f"[red][!] Robots.txt not found (Status: {r.status_code}).[/red]")
    except Exception as e:
        console.print(f"[red][!] Discovery failed: {e}[/red]")
    input("\nPress Enter...")


# --- 5. DOMAIN REPUTATION & THREAT INTEL ---
def reputation_check():
    draw_header("Holmes Intel: Reputation Audit")
    domain = console.input("[bold yellow]Enter Domain to Verify: [/bold yellow]").strip()
    if not domain:
        return

    # Google Safe Browsing and URLVoid style diagnostic
    diag_url = f"https://www.google.com/transparencyreport/safebrowsing/diagnostic/index.html?site={domain}"
    
    try:
        headers = {'User-Agent': 'Mozilla/5.0'}
        res = requests.get(diag_url, headers=headers, timeout=8)
        
        # Checking for Safety Indicators in raw response
        if "No unsafe content found" in res.text:
            console.print(Panel(f"[bold green][+] {domain}[/bold green]\nStatus: Verified CLEAN by Global Threat Indices.", border_style="green"))
        elif "Unsafe" in res.text or "Malicious" in res.text:
            console.print(Panel(f"[bold red][!] ALERT: {domain}[/bold red]\nStatus: FLAGGED for Phishing or Malware!", border_style="red"))
        else:
            console.print(f"[yellow][!] Reputation for {domain} is ambiguous or currently unindexed.[/yellow]")
            
    except Exception as e:
        console.print(f"[red][!] Reputation Audit failed: {e}[/red]")
    input("\nPress Enter...")


# --- 6. TACTICAL DNS & PASSIVE SUBDOMAINS ---
def dns_intel():
    draw_header("Holmes Intel: DNS Infrastructure")
    domain = console.input("[bold yellow]Enter Target Domain: [/bold yellow]").strip()
    if not domain:
        return

    subdomains = set()
    try:
        # Querying Certificate Transparency (CT) logs for subdomains
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        res = requests.get(url, timeout=15)

        if res.status_code == 200:
            data = res.json()
            for entry in data:
                # Entries can contain multiple subdomains split by newlines
                names = entry['name_value'].split('\n')
                for name in names:
                    if not name.startswith('*') and domain in name:
                        subdomains.add(name.strip().lower())

        if subdomains:
            table = Table(title=f"Passive Asset Discovery: {domain}", border_style="cyan")
            table.add_column("Identified Host", style="white")

            for s in sorted(list(subdomains))[:40]: # Show top 40 results
                table.add_row(s)

            console.print(table)
            console.print(f"\n[dim][*] Total Passive Assets Mapped: {len(subdomains)}[/dim]")
        else:
            console.print("[yellow][!] No passive subdomains discovered in CT logs.[/yellow]")

    except Exception as e:
        console.print(f"[red][!] Passive DNS lookup failed: {e}[/red]")
    input("\nPress Enter to return...")


# --- 7. TACTICAL GOOGLE DORK ENGINE ---
def dork_generator():
    draw_header("Holmes Intel: Tactical Dorking")
    domain = console.input("[bold yellow]Target Domain for Dorking: [/bold yellow]").strip()
    if not domain:
        return

    # Specialized dorks for configuration and sensitive file exposure
    dorks = {
        "Directory Listing": f"site:{domain} intitle:index.of",
        "Environment/Secrets": f"site:{domain} ext:env OR ext:conf OR ext:ini OR ext:yml",
        "Backup Exposure": f"site:{domain} ext:bak OR ext:old OR ext:backup OR ext:sql OR ext:zip",
        "Document Intel": f"site:{domain} ext:pdf OR ext:docx OR ext:xlsx OR ext:pptx",
        "Auth Portals": f"site:{domain} inurl:admin | inurl:login | inurl:dashboard | inurl:wp-login",
        "Public S3/Cloud": f"site:s3.amazonaws.com OR site:blob.core.windows.net \"{domain}\""
    }

    table = Table(title=f"Dork Query Intelligence: {domain}", border_style="bold yellow", expand=True)
    table.add_column("Goal", style="cyan", width=25)
    table.add_column("Query (Paste to Browser)", style="white")

    for goal, query in dorks.items():
        table.add_row(goal, query)

    console.print(table)
    console.print("[dim]\n[*] Tip: Run these in Incognito mode to avoid Captchas.[/dim]")
    input("\nPress Enter to return...")