"""
modules/bruteforce.py — Hash Cracker & Credential Bruteforcer
Supports: MD5, SHA1, SHA256, SHA512, NTLM (NT hash)
Modes: Wordlist attack, custom wordlist, online (requires hashcat-compatible format)
All cracked hashes saved to mission database.
"""

import os
import hashlib
import threading
import time
import questionary
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
from core.ui import draw_header, Q_STYLE
from core.database import db

console = Console()

# ─────────────────────────────────────────────────────────────────────────────
#  BUILT-IN COMMON PASSWORDS (fallback when no wordlist available)
# ─────────────────────────────────────────────────────────────────────────────
BUILTIN_PASSWORDS = [
    "password", "123456", "password1", "12345678", "qwerty", "abc123", "monkey",
    "1234567", "letmein", "trustno1", "dragon", "baseball", "iloveyou", "master",
    "sunshine", "ashley", "bailey", "passw0rd", "shadow", "123123", "654321",
    "superman", "qazwsx", "michael", "football", "Password1", "Password123",
    "admin", "admin123", "root", "toor", "pass", "test", "guest", "welcome",
    "login", "hello", "changeme", "default", "oracle", "postgres", "sa",
    "P@ssw0rd", "P@ss1234", "Summer2023", "Winter2023", "Spring2023", "Fall2023",
    "Company1", "Company123", "Welcome1", "Welcome123", "Admin@123", "Test@123",
    "password123", "qwerty123", "iloveyou123", "1q2w3e", "1q2w3e4r", "1qaz2wsx",
]


# ─────────────────────────────────────────────────────────────────────────────
#  HASH FUNCTIONS
# ─────────────────────────────────────────────────────────────────────────────

def md5_hash(s: str) -> str:
    return hashlib.md5(s.encode('utf-8', errors='replace')).hexdigest()


def sha1_hash(s: str) -> str:
    return hashlib.sha1(s.encode('utf-8', errors='replace')).hexdigest()


def sha256_hash(s: str) -> str:
    return hashlib.sha256(s.encode('utf-8', errors='replace')).hexdigest()


def sha512_hash(s: str) -> str:
    return hashlib.sha512(s.encode('utf-8', errors='replace')).hexdigest()


def ntlm_hash(s: str) -> str:
    """NT hash (used in Windows SAM / NTDS)."""
    return hashlib.new('md4', s.encode('utf-16-le')).hexdigest()


HASH_FUNCTIONS = {
    "md5":    md5_hash,
    "sha1":   sha1_hash,
    "sha256": sha256_hash,
    "sha512": sha512_hash,
    "ntlm":   ntlm_hash,
}

# Hash length → likely algorithm(s)
HASH_LENGTH_MAP = {
    32:  ["md5", "ntlm"],
    40:  ["sha1"],
    64:  ["sha256"],
    128: ["sha512"],
}


def detect_hash_type(h: str) -> list:
    """Auto-detect possible hash types from length."""
    h = h.strip().lower()
    return HASH_LENGTH_MAP.get(len(h), [])


# ─────────────────────────────────────────────────────────────────────────────
#  CRACKER ENGINE
# ─────────────────────────────────────────────────────────────────────────────

class HashCracker:
    def __init__(self, target_hash: str, hash_type: str, wordlist: list):
        self.target_hash = target_hash.strip().lower()
        self.hash_type = hash_type.lower()
        self.wordlist = wordlist
        self.result = None
        self.stopped = False
        self.tried = 0
        self.lock = threading.Lock()

    def _crack_chunk(self, chunk: list):
        if self.stopped:
            return
        hash_fn = HASH_FUNCTIONS.get(self.hash_type)
        if not hash_fn:
            return
        for word in chunk:
            if self.stopped:
                return
            word = word.strip()
            if not word:
                continue
            computed = hash_fn(word)
            with self.lock:
                self.tried += 1
            if computed == self.target_hash:
                with self.lock:
                    self.result = word
                    self.stopped = True
                return

    def crack(self) -> str | None:
        total = len(self.wordlist)
        threads = min(8, os.cpu_count() or 4)
        chunk_sz = max(1, total // threads)
        chunks = [self.wordlist[i:i+chunk_sz]
                  for i in range(0, total, chunk_sz)]

        with Progress(
            SpinnerColumn(),
            TextColumn("[cyan]Cracking...[/cyan]"),
            BarColumn(),
            TextColumn("[dim]{task.completed}/{task.total}[/dim]"),
            TimeElapsedColumn(),
            console=console
        ) as prog:
            task = prog.add_task("Cracking", total=total)

            workers = []
            for chunk in chunks:
                t = threading.Thread(
                    target=self._crack_chunk, args=(chunk,), daemon=True)
                workers.append(t)
                t.start()

            # Poll until done or cracked
            prev = 0
            while any(t.is_alive() for t in workers):
                with self.lock:
                    delta = self.tried - prev
                    prev = self.tried
                prog.update(task, advance=delta)
                if self.stopped:
                    prog.update(task, completed=total)
                    break
                time.sleep(0.15)

            for t in workers:
                t.join(timeout=1)

        return self.result


# ─────────────────────────────────────────────────────────────────────────────
#  WORDLIST LOADER
# ─────────────────────────────────────────────────────────────────────────────

def load_wordlist(path: str | None = None) -> list:
    """Load wordlist from file or return built-in list."""
    if path and os.path.exists(path):
        try:
            with open(path, 'r', encoding='utf-8', errors='replace') as f:
                words = [line.strip() for line in f if line.strip()]
            console.print(
                f"[green][+] Loaded {len(words):,} words from {path}[/green]")
            return words
        except Exception as e:
            console.print(
                f"[yellow][!] Could not read wordlist: {e} — using built-in.[/yellow]")

    # Check common system wordlist locations
    common_paths = [
        "/usr/share/wordlists/rockyou.txt",
        "/usr/share/wordlists/rockyou.txt.gz",
        "/opt/wordlists/rockyou.txt",
        os.path.join(os.path.dirname(os.path.dirname(__file__)),
                     "wordlists", "rockyou.txt"),
    ]
    for p in common_paths:
        if os.path.exists(p):
            try:
                with open(p, 'r', encoding='utf-8', errors='replace') as f:
                    words = [line.strip() for line in f if line.strip()]
                console.print(
                    f"[green][+] Auto-loaded {len(words):,} words from {p}[/green]")
                return words
            except Exception:
                pass

    console.print(
        f"[yellow][!] No wordlist found — using built-in {len(BUILTIN_PASSWORDS)} common passwords.[/yellow]")
    console.print(
        "[dim]Tip: Place rockyou.txt in /usr/share/wordlists/ or the wordlists/ folder.[/dim]")
    return BUILTIN_PASSWORDS


# ─────────────────────────────────────────────────────────────────────────────
#  MULTI-HASH CRACKER SESSION
# ─────────────────────────────────────────────────────────────────────────────

def crack_hash():
    draw_header("Hash Cracker — Multi-Algorithm Engine")

    console.print(Panel(
        "[white]Supported hash types:[/white]\n"
        "  MD5 (32 chars) | SHA1 (40) | SHA256 (64) | SHA512 (128)\n"
        "  NTLM / NT hash (32 chars) — Windows SAM / NTDS\n\n"
        "[dim]Paste one or more hashes below. Leave blank when done.[/dim]",
        border_style="cyan"
    ))

    # Collect hashes
    hashes = []
    while True:
        h = questionary.text(
            f"Hash #{len(hashes)+1} (blank = done):",
            style=Q_STYLE
        ).ask()
        if not h or not h.strip():
            break
        hashes.append(h.strip().lower())

    if not hashes:
        return

    # Hash type
    detected = detect_hash_type(hashes[0])
    if detected:
        console.print(
            f"[dim]Auto-detected possible type(s): {', '.join(detected)}[/dim]")

    hash_type = questionary.select(
        "Hash Algorithm:",
        choices=["md5", "sha1", "sha256", "sha512", "ntlm"],
        default=detected[0] if detected else "md5",
        style=Q_STYLE
    ).ask()
    if not hash_type:
        return

    # Wordlist
    wl_mode = questionary.select(
        "Wordlist Source:",
        choices=[
            "Auto (rockyou.txt or built-in fallback)",
            "Custom wordlist path",
        ],
        style=Q_STYLE
    ).ask()

    custom_path = None
    if wl_mode and "Custom" in wl_mode:
        custom_path = questionary.text(
            "Path to wordlist file:", style=Q_STYLE).ask()

    wordlist = load_wordlist(custom_path)
    console.print()

    # Results table
    results_table = Table(
        title="Hash Cracking Results",
        border_style="green",
        expand=True
    )
    results_table.add_column("Hash",     style="dim",   no_wrap=True)
    results_table.add_column("Result",   style="white", no_wrap=True)
    results_table.add_column("Password", style="bold green")

    cracked_count = 0
    for target_hash in hashes:
        console.print(
            f"\n[*] Cracking: [cyan]{target_hash[:32]}{'...' if len(target_hash) > 32 else ''}[/cyan]")
        cracker = HashCracker(target_hash, hash_type, wordlist)
        password = cracker.crack()

        if password:
            cracked_count += 1
            results_table.add_row(
                target_hash[:32] + ("..." if len(target_hash) > 32 else ""),
                "[bold green]CRACKED[/bold green]",
                password
            )
            db.log("Hash-Cracker", target_hash,
                   f"Password: {password} (type: {hash_type})", "CRITICAL")
            console.print(f"[bold green][+] CRACKED: {password}[/bold green]")
        else:
            results_table.add_row(
                target_hash[:32] + ("..." if len(target_hash) > 32 else ""),
                "[red]NOT FOUND[/red]",
                f"[dim]Tried {cracker.tried:,} words[/dim]"
            )
            console.print(
                f"[yellow][-] Not found in wordlist ({cracker.tried:,} words tried).[/yellow]")

    console.print()
    console.print(results_table)
    console.print(
        f"\n[bold green][+] Session complete: {cracked_count}/{len(hashes)} cracked.[/bold green]")

    if cracked_count > 0 and questionary.confirm(
        "Save results to a file?", default=True, style=Q_STYLE
    ).ask():
        os.makedirs("logs", exist_ok=True)
        fname = f"logs/cracked_{int(time.time())}.txt"
        with open(fname, "w") as f:
            for target_hash in hashes:
                cracker = HashCracker(target_hash, hash_type, wordlist)
                f.write(f"{target_hash}\n")
        console.print(f"[green][+] Results saved to {fname}[/green]")

    questionary.press_any_key_to_continue(style=Q_STYLE).ask()


if __name__ == "__main__":
    crack_hash()
