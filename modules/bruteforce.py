import hashlib
from rich.console import Console
from rich.progress import track
from core.ui import draw_header

console = Console()


def hash_cracker():
    draw_header("Hash Cracker (MD5)")
    target_hash = console.input(
        "[bold yellow]Enter MD5 Hash: [/bold yellow]").strip().lower()

    # Common Wordlist
    words = [
        "password", "123456", "admin", "guest", "root", "qwerty",
        "password123", "12345678", "superman", "football", "welcome"
    ]

    console.print(
        f"[*] Attempting to crack: [bold cyan]{target_hash}[/bold cyan]")

    found = False
    # Using 'track' for a nice visual progress bar
    for word in track(words, description="[cyan]Cracking..."):
        if hashlib.md5(word.encode()).hexdigest() == target_hash:
            console.print(
                f"\n[bold green][+] MATCH FOUND:[/bold green] {word}")
            found = True
            break

    if not found:
        console.print(
            "\n[bold red][!] Exhausted local wordlist. No match found.[/bold red]")

    input("\nPress Enter to return...")
