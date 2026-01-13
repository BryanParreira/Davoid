import hashlib
import os
from concurrent.futures import ThreadPoolExecutor
from rich.console import Console
from rich.progress import Progress, BarColumn, TextColumn, TimeRemainingColumn
from core.ui import draw_header

console = Console()

def check_word(word, target_hash, algo, salt, result_dict):
    """Worker function for threading."""
    if result_dict['found']: return
    
    # Support for Pre-pend or Appending salt (standard approach)
    data = (salt + word).encode()
    
    if algo == "md5":
        hashed = hashlib.md5(data).hexdigest()
    else:
        hashed = hashlib.sha256(data).hexdigest()
        
    if hashed == target_hash:
        result_dict['word'] = word
        result_dict['found'] = True

def hash_cracker():
    draw_header("Hash Cracker Pro")
    target_hash = console.input("[bold yellow]Enter Hash: [/bold yellow]").strip().lower()
    salt = console.input("[bold yellow]Salt (Leave blank if none): [/bold yellow]").strip()
    
    if len(target_hash) == 32: algo = "md5"
    elif len(target_hash) == 64: algo = "sha256"
    else:
        console.print("[bold red][!] Invalid hash format.[/bold red]")
        return

    wordlist_path = console.input("[bold yellow]Wordlist Path (Blank for default): [/bold yellow]").strip()
    
    if wordlist_path and os.path.exists(wordlist_path):
        with open(wordlist_path, "r", errors="ignore") as f:
            words = [line.strip() for line in f]
    else:
        words = ["password", "123456", "admin", "guest", "root", "qwerty", "password123"]

    result = {'found': False, 'word': None}
    
    with Progress(
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        TimeRemainingColumn(),
        console=console
    ) as progress:
        task = progress.add_task("[cyan]Cracking...", total=len(words))
        
        # Power Improvement: Multi-threaded execution
        with ThreadPoolExecutor(max_workers=10) as executor:
            for word in words:
                if result['found']: break
                executor.submit(check_word, word, target_hash, algo, salt, result)
                progress.advance(task)

    if result['found']:
        console.print(f"\n[bold green][+] MATCH FOUND:[/bold green] [white on green] {result['word']} [/white on green]")
    else:
        console.print("\n[bold red][!] No match found in current wordlist.[/bold red]")
    
    input("\nPress Enter to return...")