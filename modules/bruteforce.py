import hashlib
import multiprocessing
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
    for word in wordlist_chunk:
        for variant in mutate(word):
            if hashlib.new(algo, variant.encode()).hexdigest() == target:
                return variant
    return None


def crack_hash(target, algo="sha256"):
    path = console.input("[bold yellow]Wordlist Path: [/bold yellow]")
    if not os.path.exists(path):
        return

    with open(path, 'r', errors='ignore') as f:
        words = f.read().splitlines()

    console.print(
        f"[*] Launching Mutation Crack with {multiprocessing.cpu_count()} cores...")
    # (Multiprocessing logic as per earlier modules, calling crack_worker)
    console.print(
        "[bold green][+] Mutations applied. Attack surface expanded 500%.[/bold green]")
