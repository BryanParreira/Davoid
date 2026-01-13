import os
from cryptography.fernet import Fernet
from rich.console import Console
from core.ui import draw_header

console = Console()

def encrypt_payload():
    draw_header("Crypt-Keeper v2")
    file_path = console.input("[bold yellow]File to Encrypt: [/bold yellow]").strip()
    
    if os.path.exists(file_path):
        key = Fernet.generate_key()
        cipher = Fernet(key)
        
        with open(file_path, "rb") as f:
            encrypted = cipher.encrypt(f.read())
            
        enc_file = f"{file_path}.enc"
        with open(enc_file, "wb") as f:
            f.write(encrypted)
            
        # Ease of Use: Generate an automatic loader stub
        stub_code = f"""
import os
from cryptography.fernet import Fernet
# Self-decrypting loader
def run_ghost():
    key = b'{key.decode()}'
    with open('{os.path.basename(enc_file)}', 'rb') as f:
        data = Fernet(key).decrypt(f.read())
    exec(data)

if __name__ == "__main__":
    run_ghost()
"""
        with open(f"loader_{os.path.basename(file_path)}", "w") as f:
            f.write(stub_code.strip())

        console.print(f"\n[bold green][+] Success![/bold green]")
        console.print(f"[*] Encrypted: [cyan]{enc_file}[/cyan]")
        console.print(f"[*] Loader Generated: [cyan]loader_{os.path.basename(file_path)}[/cyan]")
        console.print(f"[*] Key: [bold red]{key.decode()}[/bold red]")
    else:
        console.print("[red][!] File not found.[/red]")
        
    input("\nPress Enter...")