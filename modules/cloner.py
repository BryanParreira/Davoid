import os
import subprocess
from pywebcopy import save_webpage
from rich.console import Console
from core.ui import draw_header

console = Console()

def clone_site():
    draw_header("Phantom Cloner")
    
    target_url = console.input("[bold yellow]URL to clone (e.g., https://example.com): [/bold yellow]").strip()
    project_name = console.input("[bold yellow]Project Name (e.g., login_fake): [/bold yellow]").strip()
    
    if not target_url or not project_name:
        return

    # Create the storage directory
    base_path = "/opt/davoid/cloned_sites"
    if not os.path.exists(base_path):
        os.makedirs(base_path)

    try:
        console.print(f"[bold cyan][*][/bold cyan] Cloning {target_url}... (This may take a moment)")
        
        # Clone the page with assets remapped for local hosting
        # 
        save_webpage(
            url=target_url,
            project_folder=base_path,
            project_name=project_name,
            bypass_robots=True,
            debug=False
        )

        project_path = os.path.join(base_path, project_name)
        console.print(f"[bold green][+] Success! Site cloned to: {project_path}[/bold green]")
        
        # Option to immediately host the site
        host_now = console.input("\n[bold cyan]Host this site now on Port 80? (y/N): [/bold cyan]").lower()
        if host_now == 'y':
            console.print(f"[bold red][!] Server starting on http://localhost:80[/bold red]")
            console.print("[dim]Note: This will block the terminal until you press CTRL+C.[/dim]")
            
            # Change to the project directory and start the server
            os.chdir(project_path)
            # We use sudo because Port 80 is a privileged port
            subprocess.run(["sudo", "/opt/davoid/venv/bin/python3", "-m", "http.server", "80"])

    except Exception as e:
        console.print(f"[bold red][!] Cloner Error:[/bold red] {e}")

    input("\nPress Enter to return...")