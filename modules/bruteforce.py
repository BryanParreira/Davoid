import hashlib
from rich.console import Console

console = Console()


def hash_cracker():
    target_hash = console.input(
        "[bold yellow]Enter MD5 Hash to Crack: [/bold yellow]")
    wordlist_path = console.input(
        "[bold yellow]Wordlist path (or 'common'): [/bold yellow]")

    # Built-in tiny wordlist if user doesn't have one
    words = ["password", "123456", "admin",
             "guest", "root", "qwerty", "password123"]

    found = False
    console.print("[cyan]Cracking...[/cyan]")
    for word in words:
        if hashlib.md5(word.encode()).hexdigest() == target_hash:
            console.print(f"[bold green]MATCH FOUND:[/bold green] {word}")
            found = True
            break

    if not found:
        console.print(
            "[red]No match in local list. Try a larger wordlist.[/red]")
    input("\nPress Enter...")
