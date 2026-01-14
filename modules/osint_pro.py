import requests
import phonenumbers
import urllib3
from phonenumbers import carrier, geocoder, timezone
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
from core.ui import draw_header

urllib3.disable_warnings()
console = Console()

# --- 1. USERNAME TRACKER ---
SOCIAL_SITES = {
    "GitHub": "https://github.com/{}",
    "Twitter": "https://twitter.com/{}",
    "Instagram": "https://www.instagram.com/{}/",
    "Reddit": "https://www.reddit.com/user/{}",
    "Pinterest": "https://www.pinterest.com/{}/",
    "Medium": "https://medium.com/@{}",
    "SoundCloud": "https://soundcloud.com/{}"
}


def username_tracker():
    draw_header("Username Profile Tracker")
    username = console.input(
        "[bold yellow]Enter Username: [/bold yellow]").strip()
    if not username:
        return

    table = Table(
        title=f"Social Footprint: {username}", border_style="bold green")
    table.add_column("Platform", style="cyan")
    table.add_column("Status", style="white")
    table.add_column("URL", style="blue")

    with Progress(SpinnerColumn(), TextColumn("{task.description}"), console=console) as progress:
        task = progress.add_task(
            "[cyan]Scanning platforms...", total=len(SOCIAL_SITES))
        for platform, url_fmt in SOCIAL_SITES.items():
            url = url_fmt.format(username)
            try:
                res = requests.get(url, timeout=5)
                if res.status_code == 200:
                    table.add_row(platform, "FOUND", url)
            except:
                pass
            progress.update(task, advance=1)
    console.print(table)
    input("\nPress Enter...")

# --- 2. PHONE INTELLIGENCE ---


def phone_intel():
    draw_header("Global Phone Tracer")
    num_str = console.input(
        "[bold yellow]Enter Phone (e.g. +14155552671): [/bold yellow]").strip()
    if not num_str:
        return
    try:
        parsed_num = phonenumbers.parse(num_str)
        table = Table(
            title=f"Tele-Intel: {num_str}", border_style="bold magenta")
        table.add_column("Metric", style="cyan")
        table.add_column("Value", style="white")
        table.add_row("Carrier", carrier.name_for_number(parsed_num, "en"))
        table.add_row(
            "Location", geocoder.description_for_number(parsed_num, "en"))
        table.add_row("Timezone", ", ".join(
            timezone.time_zones_for_number(parsed_num)))
        console.print(table)
    except:
        console.print("[red][!] Invalid format.[/red]")
    input("\nPress Enter...")

# --- 3. GEOLOCATION ---


def geolocate():
    draw_header("Geospatial Intel Tracker")
    target = console.input(
        "[bold yellow]Enter IP/Domain: [/bold yellow]").strip()
    if not target:
        return
    try:
        res = requests.get(
            f"http://ip-api.com/json/{target}", timeout=5).json()
        table = Table(title=f"Geo-Intel: {target}", border_style="bold blue")
        table.add_column("Metric", style="cyan")
        table.add_column("Value", style="white")
        table.add_row("Location", f"{res.get('city')}, {res.get('country')}")
        table.add_row("Lat/Lon", f"{res.get('lat')}, {res.get('lon')}")
        table.add_row("ISP", res.get('isp'))
        console.print(table)
    except:
        console.print("[red][!] API Error.[/red]")
    input("\nPress Enter...")

# --- 4. NEW: ROBOTS.TXT SCRAPER (From Mr. Holmes) ---


def robots_scraper():
    draw_header("Domain Robots.txt Scraper")
    domain = console.input(
        "[bold yellow]Domain (e.g. target.com): [/bold yellow]").strip()
    if not domain:
        return
    url = f"http://{domain}/robots.txt"
    try:
        r = requests.get(url, timeout=5)
        if r.status_code == 200:
            console.print(
                f"\n[bold green][+] Robots.txt Found for {domain}:[/bold green]")
            console.print(r.text[:500] + "...")  # Preview the first 500 chars
            disallowed = [line for line in r.text.splitlines()
                          if line.startswith("Disallow")]
            if disallowed:
                console.print(
                    f"\n[bold yellow][!] {len(disallowed)} Hidden paths discovered:[/bold yellow]")
                for path in disallowed[:10]:
                    console.print(f" [dim]- {path}[/dim]")
        else:
            console.print("[red][!] No robots.txt available.[/red]")
    except:
        console.print("[red][!] Connection failed.[/red]")
    input("\nPress Enter...")

# --- 5. NEW: DOMAIN REPUTATION (From Mr. Holmes) ---


def reputation_check():
    draw_header("Domain Reputation Audit")
    domain = console.input(
        "[bold yellow]Domain to Audit: [/bold yellow]").strip()
    if not domain:
        return
    # Mimics Holmes' reputation check using public API data
    try:
        # Check against Google Safe Browsing or similar public indicators
        res = requests.get(
            f"https://www.google.com/transparencyreport/safebrowsing/diagnostic/index.html?site={domain}", timeout=5)
        if "No unsafe content found" in res.text:
            console.print(
                f"[bold green][+] {domain} is currently marked as SAFE.[/bold green]")
        else:
            console.print(
                f"[bold red][!] {domain} may contain MALICIOUS content.[/bold red]")
    except:
        console.print("[red][!] Audit failed.[/red]")
    input("\nPress Enter...")

# --- 6. GOOGLE DORK AUTOMATOR ---


def dork_generator():
    draw_header("Tactical Google Dork Engine")
    domain = console.input(
        "[bold yellow]Target Domain: [/bold yellow]").strip()
    if not domain:
        return
    dorks = {
        "Config Leaks": f"site:{domain} ext:log OR ext:txt OR ext:conf",
        "Public Backups": f"site:{domain} ext:bak OR ext:sql OR ext:backup",
        "Admin Portals": f"site:{domain} inurl:admin OR inurl:login"
    }
    table = Table(title=f"Holmes Search: {domain}", border_style="bold yellow")
    table.add_column("Goal")
    table.add_column("Query")
    for k, v in dorks.items():
        table.add_row(k, v)
    console.print(table)
    input("\nPress Enter...")
