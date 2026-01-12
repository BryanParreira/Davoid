import hashlib
import os
from rich.console import Console
from rich.progress import track
from core.ui import draw_header

console = Console()

def hash_cracker():
    draw_header("Hash Cracker (MD5/SHA256)")
    target_hash = console.input("[bold yellow]Enter Hash: [/bold yellow]").strip().lower()
    
    # Auto-detect hash type
    if len(target_hash) == 32:
        algo = "md5"
    elif len(target_hash) == 64:
        algo = "sha256"
    else:
        console.print("[bold red][!] Invalid hash length.[/bold red]")
        return

    wordlist_path = console.input("[bold yellow]Wordlist Path (Leave blank for default): [/bold yellow]").strip()
    
    if wordlist_path and os.path.exists(wordlist_path):
        with open(wordlist_path, "r", errors="ignore") as f:
            words = [line.strip() for line in f]
    else:
        words = ["password", "123456", "admin", "guest", "root", "qwerty", "password123"]

    console.print(f"[*] Attempting to crack [bold cyan]{algo}[/bold cyan] hash...")

    found = False
    for word in track(words, description="[cyan]Cracking..."):
        hashed = hashlib.md5(word.encode()).hexdigest() if algo == "md5" else hashlib.sha256(word.encode()).hexdigest()
        if hashed == target_hash:
            console.print(f"\n[bold green][+] MATCH FOUND:[/bold green] {word}")
            found = True
            break

    if not found:
        console.print("\n[bold red][!] No match found.[/bold red]")
    input("\nPress Enter to return...")