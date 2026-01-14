import requests
import phonenumbers
from phonenumbers import carrier, geocoder, timezone
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
from core.ui import draw_header

console = Console()

# --- 1. USERNAME TRACKER (Elite Version) ---
SOCIAL_SITES = {
    "GitHub": "https://github.com/{}",
    "Twitter": "https://twitter.com/{}",
    "Instagram": "https://www.instagram.com/{}/",
    "Reddit": "https://www.reddit.com/user/{}",
    "Pinterest": "https://www.pinterest.com/{}/",
    "Tumblr": "https://{}.tumblr.com",
    "SoundCloud": "https://soundcloud.com/{}",
    "Steam": "https://steamcommunity.com/id/{}",
    "Vimeo": "https://vimeo.com/{}",
    "Medium": "https://medium.com/@{}"
}


def username_tracker():
    draw_header("Username Profile Tracker")
    username = console.input(
        "[bold yellow]Enter Username to Profile: [/bold yellow]").strip()
    if not username:
        return

    table = Table(
        title=f"Profile Intel: {username}", border_style="bold green")
    table.add_column("Platform", style="cyan")
    table.add_column("Status", style="white")
    table.add_column("Profile URL", style="blue")

    with Progress(SpinnerColumn(), TextColumn("{task.description}"), console=console) as progress:
        task = progress.add_task(
            "[cyan]Crawling social networks...", total=len(SOCIAL_SITES))

        for platform, url_fmt in SOCIAL_SITES.items():
            url = url_fmt.format(username)
            try:
                res = requests.get(url, timeout=5, allow_redirects=True)
                if res.status_code == 200 and username.lower() in res.text.lower():
                    table.add_row(
                        platform, "[bold green]FOUND[/bold green]", url)
            except:
                pass
            progress.update(task, advance=1)

    console.print(table)
    input("\nPress Enter...")

# --- 2. PHONE INTELLIGENCE ---


def phone_intel():
    draw_header("Global Phone Tracer")
    num_str = console.input(
        "[bold yellow]Enter Phone (e.g., +14155552671): [/bold yellow]").strip()
    if not num_str:
        return

    try:
        parsed_num = phonenumbers.parse(num_str)
        if not phonenumbers.is_valid_number(parsed_num):
            console.print("[red][!] Invalid international format.[/red]")
            return

        table = Table(
            title=f"Tele-Intel: {num_str}", border_style="bold magenta")
        table.add_column("Field", style="cyan")
        table.add_column("Data", style="white")

        table.add_row("Carrier", carrier.name_for_number(
            parsed_num, "en") or "Unknown")
        table.add_row("Location", geocoder.description_for_number(
            parsed_num, "en") or "Unknown")
        table.add_row("Timezone", ", ".join(
            timezone.time_zones_for_number(parsed_num)))
        table.add_row("Valid", str(phonenumbers.is_valid_number(parsed_num)))

        console.print(table)
    except:
        console.print(
            "[red][!] Parsing Error. Use +[CountryCode][Number].[/red]")
    input("\nPress Enter...")

# --- 3. GEOLOCATION HUNTER ---


def geolocate():
    draw_header("Geospatial Intel Tracker")
    target = console.input(
        "[bold yellow]Enter IP or Domain: [/bold yellow]").strip()
    if not target:
        return

    try:
        # Use ip-api for no-key rapid geolocation
        res = requests.get(
            f"http://ip-api.com/json/{target}", timeout=5).json()
        if res.get('status') == 'fail':
            console.print("[red][!] Geolocation failed for this target.[/red]")
            return

        table = Table(title=f"Geo-Intel: {target}", border_style="bold blue")
        table.add_column("Metric", style="cyan")
        table.add_column("Value", style="white")

        table.add_row(
            "Country", f"{res.get('country')} ({res.get('countryCode')})")
        table.add_row(
            "Region/City", f"{res.get('regionName')}, {res.get('city')}")
        table.add_row("Lat/Lon", f"{res.get('lat')}, {res.get('lon')}")
        table.add_row("ISP/Org", f"{res.get('isp')} / {res.get('org')}")

        console.print(table)
        console.print(
            f"\n[dim]Google Maps: https://www.google.com/maps?q={res.get('lat')},{res.get('lon')}[/dim]")
    except:
        console.print("[red][!] Geolocation API Error.[/red]")
    input("\nPress Enter...")

# --- 4. GOOGLE DORK AUTOMATOR ---


def dork_generator():
    draw_header("Tactical Google Dork Engine")
    domain = console.input(
        "[bold yellow]Target Domain (e.g., target.com): [/bold yellow]").strip()
    if not domain:
        return

    dorks = {
        "Sensitive Files": f"site:{domain} ext:log OR ext:txt OR ext:conf OR ext:cnf",
        "Public Backups": f"site:{domain} ext:bak OR ext:old OR ext:backup OR ext:sql",
        "Configuration Leaks": f"site:{domain} \"index of\" .env OR .git OR .docker",
        "Admin Portals": f"site:{domain} inurl:admin OR inurl:login OR inurl:dashboard",
        "PDF/Doc Leakage": f"site:{domain} ext:pdf OR ext:doc OR ext:docx OR ext:xls"
    }

    table = Table(
        title=f"Google Dork Intelligence: {domain}", border_style="bold yellow")
    table.add_column("Intelligence Goal", style="cyan")
    table.add_column("Tactical Search Query", style="white")

    for goal, query in dorks.items():
        table.add_row(goal, query)

    console.print(table)
    console.print(
        "\n[dim][*] Copy these queries into Google to find hidden assets.[/dim]")
    input("\nPress Enter...")
