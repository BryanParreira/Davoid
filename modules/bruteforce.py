import hashlib
import multiprocessing
import os
from rich.console import Console

console = Console()


def mutate(word):
    """Applies common mutation rules to increase cracking success."""
    variants = [word, word.upper(), word.capitalize(),
                word + "123", word + "2024"]
    # Simple l33t mutation
    variants.append(word.replace('e', '3').replace('a', '@').replace('o', '0'))
    return variants


def crack_worker(target, algo, wordlist_chunk):
    """Worker function for multiprocessing pool."""
    for word in wordlist_chunk:
        for variant in mutate(word):
            if hashlib.new(algo, variant.encode()).hexdigest() == target:
                return variant
    return None


def crack_hash(target, algo="sha256"):
    """Fixed: Fully implemented multi-core mutation cracker."""
    path = console.input("[bold yellow]Wordlist Path: [/bold yellow]")
    if not os.path.exists(path):
        console.print("[red][!] Wordlist not found.[/red]")
        return

    try:
        with open(path, 'r', errors='ignore') as f:
            words = f.read().splitlines()

        num_cores = multiprocessing.cpu_count()
        chunk_size = len(words) // num_cores
        chunks = [words[i:i + chunk_size] for i in range(0, len(words), chunk_size)]

        console.print(f"[*] Launching Mutation Crack with {num_cores} cores...")
        
        # Initialize multiprocessing pool
        pool = multiprocessing.Pool(processes=num_cores)
        results = [pool.apply_async(crack_worker, args=(target, algo, chunk)) for chunk in chunks]

        found_password = None
        for r in results:
            res = r.get()
            if res:
                found_password = res
                pool.terminate()
                break
        
        pool.close()
        pool.join()

        if found_password:
            console.print(f"\n[bold green][+] HASH CRACKED: {found_password}[/bold green]")
        else:
            console.print("\n[yellow][!] Crack failed. Try a larger wordlist.[/yellow]")

        console.print("[bold green][+] Mutations applied. Attack surface expanded 500%.[/bold green]")
    
    except Exception as e:
        console.print(f"[red][!] Cracking error: {e}[/red]")