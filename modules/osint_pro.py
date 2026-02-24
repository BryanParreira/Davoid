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
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from core.ui import draw_header, Q_STYLE

try:
    from core.config import load_config
except ImportError:
    def load_config(): return None

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
    draw_header("Holmes Intel: Identity Profiler")
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


def shodan_intel():
    """Next-Gen Upgrade: Queries Shodan REST API for Attack Surface Data."""
    draw_header("Holmes Intel: Shodan Attack Surface")

    config = load_config()
    api_key = config.get("api_keys", {}).get("shodan", "") if config else ""

    if not api_key:
        console.print(
            "[yellow][!] No Shodan API key found in config.yaml.[/yellow]")
        api_key = questionary.text(
            "Enter your Shodan API Key (Or press Enter to cancel):", style=Q_STYLE).ask()
        if not api_key:
            return

    target = questionary.text("Target IP Address:", style=Q_STYLE).ask()
    if not target:
        return

    try:
        ip = socket.gethostbyname(target)
    except Exception:
        return console.print(f"[red][!] Failed to resolve IP for {target}[/red]")

    console.print(f"[*] Querying Shodan global databases for {ip}...")
    try:
        url = f"https://api.shodan.io/shodan/host/{ip}?key={api_key}"
        res = requests.get(url, timeout=15)

        if res.status_code == 200:
            data = res.json()
            table = Table(
                title=f"Shodan Node Report: {ip}", border_style="bold red", expand=True)
            table.add_column("Property", style="cyan")
            table.add_column("Details", style="white")

            table.add_row("Organization / ISP", data.get("org", "N/A"))
            table.add_row("Operating System", data.get("os", "N/A"))

            ports = [str(p) for p in data.get("ports", [])]
            table.add_row("Open Ports", ", ".join(ports))

            vulns = data.get("vulns", [])
            table.add_row("Vulnerabilities (CVEs)", "\n".join(
                vulns) if vulns else "[green]None Detected[/green]")

            console.print(table)
        elif res.status_code == 401:
            console.print("[bold red][!] Invalid Shodan API Key.[/bold red]")
        elif res.status_code == 404:
            console.print(
                "[yellow][+] No vulnerabilities or open ports indexed by Shodan for this IP.[/yellow]")
        else:
            console.print(
                f"[red][!] API Error: Status {res.status_code}[/red]")
    except Exception as e:
        console.print(f"[red][!] Error reaching Shodan: {e}[/red]")

    questionary.press_any_key_to_continue(style=Q_STYLE).ask()


def wayback_intel():
    """Next-Gen Upgrade: Mines the Internet Archive for forgotten URLs and sensitive endpoints."""
    draw_header("Holmes Intel: Deep Web Archive Mining")
    domain = questionary.text(
        "Target Domain (e.g., example.com):", style=Q_STYLE).ask()
    if not domain:
        return

    console.print(
        f"[*] Mining Wayback Machine CDX API for hidden endpoints on {domain}...")
    url = f"http://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=json&collapse=urlkey&limit=1000"

    try:
        with console.status("[bold cyan]Retrieving historical URL records...[/bold cyan]", spinner="bouncingBar"):
            res = requests.get(url, timeout=20)

        if res.status_code == 200:
            data = res.json()
            if len(data) <= 1:
                console.print(
                    "[yellow][!] No archived endpoints found for this domain.[/yellow]")
                return questionary.press_any_key_to_continue(style=Q_STYLE).ask()

            # Extract just the URLs from the JSON array (skipping the header row)
            endpoints = [row[2] for row in data[1:]]

            # Filter for highly sensitive endpoints Red Teamers look for
            interesting = []
            for ep in endpoints:
                if any(ext in ep.lower() for ext in ['.php', '.api', '.env', '.sql', '.bak', '/admin', '/login', 'token=', 'key=']):
                    interesting.append(ep)

            if interesting:
                console.print(Panel("\n".join(
                    interesting[:40]), title=f"High-Value Endpoints Found ({len(interesting)} total)", border_style="red"))
                if len(interesting) > 40:
                    console.print(
                        f"[dim]... and {len(interesting) - 40} more high-value targets.[/dim]")
            else:
                console.print(Panel("\n".join(
                    endpoints[:40]), title=f"Standard Endpoints Found ({len(endpoints)-1} total)", border_style="cyan"))

        else:
            console.print("[red][!] Wayback Machine API Error.[/red]")
    except Exception as e:
        console.print(f"[red][!] Archival mining failed: {e}[/red]")

    questionary.press_any_key_to_continue(style=Q_STYLE).ask()


def dns_intel():
    """Next-Gen Upgrade: Hybrid Passive DNS mapping via HackerTarget and CRT.sh."""
    draw_header("Holmes Intel: Passive Infrastructure Mapping")
    domain = questionary.text("Target Domain:", style=Q_STYLE).ask()
    if not domain:
        return

    console.print(
        f"[*] Performing passive DNS mapping via HackerTarget & Certificate Transparency Logs...")

    subs = set()
    with console.status("[bold cyan]Aggregating DNS records passively...[/bold cyan]"):
        # 1. HackerTarget API
        try:
            ht_url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
            ht_res = requests.get(ht_url, timeout=10)
            if ht_res.status_code == 200 and "error" not in ht_res.text.lower():
                for line in ht_res.text.splitlines():
                    parts = line.split(',')
                    if len(parts) >= 1:
                        subs.add(parts[0].strip().lower())
        except:
            pass

        # 2. CRT.sh (Certificate Transparency)
        try:
            crt_url = f"https://crt.sh/?q=%.{domain}&output=json"
            crt_res = requests.get(crt_url, timeout=15)
            if crt_res.status_code == 200:
                data = crt_res.json()
                for entry in data:
                    name = entry['name_value']
                    for n in name.split('\n'):
                        if not n.startswith('*'):
                            subs.add(n.lower().strip())
        except:
            pass

    if subs:
        table = Table(
            title=f"Discovered Infrastructure ({len(subs)} nodes)", border_style="green")
        table.add_column("Discovered Subdomain / Asset", style="cyan")

        # Display up to 40 results to keep the terminal clean
        for s in sorted(list(subs))[:40]:
            table.add_row(s)
        console.print(table)

        if len(subs) > 40:
            console.print(
                f"[dim]...and {len(subs) - 40} more subdomains hidden.[/dim]")
    else:
        console.print("[red][!] No infrastructure data found passively.[/red]")

    questionary.press_any_key_to_continue(style=Q_STYLE).ask()


def dork_generator():
    draw_header("Holmes Intel: Advanced Dork Gen")
    domain = questionary.text("Target Domain:", style=Q_STYLE).ask()
    if not domain:
        return
    dorks = {
        "Config Files": f"site:{domain} ext:xml | ext:conf | ext:cnf | ext:reg | ext:inf | ext:rdp | ext:cfg | ext:txt | ext:ini",
        "Database Dumps": f"site:{domain} ext:sql | ext:dbf | ext:mdb",
        "Log Files": f"site:{domain} ext:log",
        "Exposed Docs": f"site:{domain} ext:doc | ext:docx | ext:odt | ext:pdf | ext:rtf | ext:sxw | ext:psw | ext:ppt | ext:pptx | ext:pps | ext:csv",
        "Directory Listing": f"site:{domain} intitle:index.of"
    }
    table = Table(title="Google Dork Payloads", border_style="magenta")
    table.add_column("Type", style="cyan")
    table.add_column("Query to paste in Google", style="white")
    for k, v in dorks.items():
        table.add_row(k, v)
    console.print(table)
    questionary.press_any_key_to_continue(style=Q_STYLE).ask()
