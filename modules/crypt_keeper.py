import os
from cryptography.fernet import Fernet
from rich.console import Console
from core.ui import draw_header

console = Console()

def encrypt_payload():
    draw_header("Crypt-Keeper")
    console.print("[dim]Encrypts shellcode/files to bypass static signatures.[/dim]\n")
    
    file_path = console.input("[bold yellow]Path to file to encrypt: [/bold yellow]").strip()
    
    if os.path.exists(file_path):
        key = Fernet.generate_key()
        cipher = Fernet(key)
        
        with open(file_path, "rb") as f:
            content = f.read()
            
        encrypted = cipher.encrypt(content)
        
        with open(f"{file_path}.enc", "wb") as f:
            f.write(encrypted)
            
        console.print(f"\n[bold green][+] Success![/bold green]")
        console.print(f"[*] Encrypted File: [cyan]{file_path}.enc[/cyan]")
        console.print(f"[*] Encryption Key: [bold red]{key.decode()}[/bold red]")
        console.print("\n[dim]Note: You need this key to decrypt the file in-memory on target.[/dim]")
    else:
        console.print("[red][!] File not found.[/red]")
        
    input("\nPress Enter...")