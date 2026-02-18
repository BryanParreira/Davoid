import requests
import phonenumbers
import urllib3
import re
import socket
import concurrent.futures
import questionary
from phonenumbers import carrier, geocoder, timezone
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
from core.ui import draw_header, Q_STYLE

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
console = Console()

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
    url = url_fmt.format(username)
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Accept-Language': 'en-US,en;q=0.9'
    }
    try:
        res = requests.get(url, headers=headers,
                           timeout=6, allow_redirects=True)
        if res.status_code == 200 and username.lower() in res.text.lower():
            return platform, "[bold green]LIVE[/bold green]", url
    except:
        pass
    return None


def username_tracker():
    draw_header("Holmes Intel: Username Profiler")
    username = questionary.text(
        "Enter Username to Trace:", style=Q_STYLE).ask()
    if not username:
        return

    table = Table(
        title=f"Digital Footprint: {username}", border_style="bold green", expand=True)
    table.add_column("Platform", style="cyan")
    table.add_column("Status", style="white")
    table.add_column("Link", style="blue")

    with Progress(SpinnerColumn(), TextColumn("{task.description}"), BarColumn(), console=console) as progress:
        task = progress.add_task(
            "[cyan]Crawling Platforms...", total=len(SOCIAL_SITES))
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(
                check_username_platform, p, u, username) for p, u in SOCIAL_SITES.items()]
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result:
                    table.add_row(*result)
                progress.update(task, advance=1)

    console.print(table)
    questionary.press_any_key_to_continue(style=Q_STYLE).ask()


def phone_intel():
    draw_header("Holmes Intel: Global Phone Tracer")
    num_str = questionary.text(
        "Target Phone (e.g. +14155552671):", style=Q_STYLE).ask()
    if not num_str:
        return

    try:
        parsed_num = phonenumbers.parse(num_str)
        if not phonenumbers.is_valid_number(parsed_num):
            console.print("[red]Invalid number.[/red]")
            return

        table = Table(title=f"Carrier & Geo Intel",
                      border_style="bold magenta")
        table.add_column("Field", style="cyan")
        table.add_column("Value", style="white")

        carrier_info = carrier.name_for_number(parsed_num, "en") or "N/A"
        region_info = geocoder.description_for_number(
            parsed_num, "en") or "Unknown"
        tz_info = ", ".join(timezone.time_zones_for_number(parsed_num))

        table.add_row("Carrier", carrier_info)
        table.add_row("Region", region_info)
        table.add_row("Timezone", tz_info)
        console.print(table)
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")

    questionary.press_any_key_to_continue(style=Q_STYLE).ask()


def geolocate():
    draw_header("Holmes Intel: Geospatial Tracker")
    target = questionary.text("Target IP or Domain:", style=Q_STYLE).ask()
    if not target:
        return
    try:
        if not re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", target):
            target = socket.gethostbyname(target)
        url = f"http://ip-api.com/json/{target}"
        res = requests.get(url, timeout=10).json()

        table = Table(title=f"Geo-Intel: {target}", border_style="bold blue")
        table.add_column("Metric", style="cyan")
        table.add_column("Value", style="white")
        table.add_row("Location", f"{res.get('city')}, {res.get('country')}")
        table.add_row("Coordinates", f"{res.get('lat')}, {res.get('lon')}")
        table.add_row("ISP", res.get('isp'))
        console.print(table)
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
    questionary.press_any_key_to_continue(style=Q_STYLE).ask()


def robots_scraper():
    draw_header("Holmes Intel: Robots.txt Audit")
    domain = questionary.text("Enter Domain:", style=Q_STYLE).ask()
    if not domain:
        return
    url = f"http://{domain}/robots.txt" if not domain.startswith(
        "http") else f"{domain}/robots.txt"
    try:
        r = requests.get(url, timeout=7)
        if r.status_code == 200:
            console.print(f"\n[green]Found Robots.txt[/green]\n")
            console.print(r.text[:500] + "\n...")
        else:
            console.print("[red]Not Found.[/red]")
    except Exception as e:
        console.print(f"[red]{e}[/red]")
    questionary.press_any_key_to_continue(style=Q_STYLE).ask()


def reputation_check():
    draw_header("Holmes Intel: Reputation Check")
    domain = questionary.text("Enter Domain:", style=Q_STYLE).ask()
    console.print(f"[dim]Checking {domain} against safe browsing...[/dim]")
    # Simplified check logic for UI demo
    console.print("[green]CLEAN[/green] (Simulated Result)")
    questionary.press_any_key_to_continue(style=Q_STYLE).ask()


def dork_generator():
    draw_header("Holmes Intel: Dork Gen")
    domain = questionary.text("Target Domain:", style=Q_STYLE).ask()
    if not domain:
        return
    dorks = {
        "Config Files": f"site:{domain} ext:xml | ext:conf | ext:cnf | ext:reg | ext:inf | ext:rdp | ext:cfg | ext:txt | ext:ini",
        "Database": f"site:{domain} ext:sql | ext:dbf | ext:mdb",
        "Log Files": f"site:{domain} ext:log"
    }
    table = Table(title="Google Dorks")
    table.add_column("Type")
    table.add_column("Query")
    for k, v in dorks.items():
        table.add_row(k, v)
    console.print(table)
    questionary.press_any_key_to_continue(style=Q_STYLE).ask()


def dns_intel():
    draw_header("Holmes Intel: Passive DNS")
    domain = questionary.text("Target Domain:", style=Q_STYLE).ask()
    if not domain:
        return
    url = f"https://crt.sh/?q=%.{domain}&output=json"
    try:
        res = requests.get(url, timeout=10)
        if res.status_code == 200:
            data = res.json()
            subs = set()
            for entry in data:
                subs.add(entry['name_value'])
            console.print(
                Panel("\n".join(list(subs)[:20]), title="Subdomains Found"))
    except:
        console.print("[red]API Error[/red]")
    questionary.press_any_key_to_continue(style=Q_STYLE).ask()
