"""
bruteforce.py — Multi-Core Hash Cracker with Mutation Engine
FIX: multiprocessing.Event() replaced with multiprocessing.Manager().Event()
     so the stop signal is correctly shared across spawned child processes
     (required on macOS/Windows which use 'spawn' not 'fork' for Process()).
"""

import hashlib
import multiprocessing
import os
import sys
import time
import questionary
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn
from rich.panel import Panel
from core.ui import draw_header, Q_STYLE

console = Console()


class HashEngine:
    def __init__(self, algo="sha256"):
        self.algo = algo

    @staticmethod
    def mutate(word):
        """
        Mutation engine: generates password variants via case, padding, leet-speak.
        Returns a list so workers can iterate without memory overhead.
        """
        word = word.strip()
        if not word:
            return []

        variants = {word, word.upper(), word.lower(), word.capitalize()}

        suffixes = ["123", "1234", "2024", "2025",
                    "2026", "!", "!!", "@", "#", "1!"]
        base_list = list(variants)
        for v in base_list:
            for s in suffixes:
                variants.add(v + s)
                variants.add(s + v)

        leet = {'a': '@', 'e': '3', 'i': '1', 'o': '0', 's': '$', 't': '7'}
        leet_word = "".join(leet.get(c.lower(), c) for c in word)
        variants.add(leet_word)
        variants.add(leet_word.capitalize())
        variants.add(leet_word + "123")

        return list(variants)

    @staticmethod
    def _crack_worker(target_hash, algo, wordlist_chunk, found_queue, stop_event):
        """
        Worker process. stop_event is a Manager().Event() so it's shared correctly
        across spawn-based process start methods (macOS, Windows).
        """
        try:
            for word in wordlist_chunk:
                if stop_event.is_set():
                    return
                for variant in HashEngine.mutate(word):
                    try:
                        h = hashlib.new(algo)
                        h.update(variant.encode('utf-8', errors='ignore'))
                        if h.hexdigest() == target_hash:
                            found_queue.put(variant)
                            stop_event.set()
                            return
                    except Exception:
                        continue
        except Exception:
            pass

    def run(self, target_hash):
        draw_header("Cracker-Pro: Multi-Core Mutation Engine")

        path = questionary.text(
            "Wordlist path (e.g. /usr/share/wordlists/rockyou.txt):",
            style=Q_STYLE).ask()
        if not path or not os.path.exists(path):
            console.print("[red][!] Wordlist not found.[/red]")
            return

        # Auto-detect algorithm from hash length
        length_map = {32: "md5", 40: "sha1", 56: "sha224",
                      64: "sha256", 96: "sha384", 128: "sha512"}
        self.algo = length_map.get(len(target_hash), self.algo)
        console.print(
            f"[*] Detected algorithm: [bold cyan]{self.algo.upper()}[/bold cyan]")

        try:
            with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                words = f.read().splitlines()
        except Exception as e:
            console.print(f"[red][!] Cannot read wordlist: {e}[/red]")
            return

        total = len(words)
        num_cores = multiprocessing.cpu_count()
        chunk_size = max(1, total // num_cores)
        chunks = [words[i:i + chunk_size] for i in range(0, total, chunk_size)]

        # ── Manager-based shared objects (work across spawn/fork) ──
        manager = multiprocessing.Manager()
        stop_event = manager.Event()          # ← FIX: was multiprocessing.Event()
        found_queue = manager.Queue()

        console.print(
            f"[*] Dispatching across {num_cores} cores — {total:,} words + mutations...")

        processes = []
        for chunk in chunks:
            p = multiprocessing.Process(
                target=HashEngine._crack_worker,
                args=(target_hash, self.algo, chunk, found_queue, stop_event),
                daemon=True
            )
            p.start()
            processes.append(p)

        # ── Monitor loop ───────────────────────────────────────────
        found_password = None
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(bar_width=40),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TimeElapsedColumn(),
            console=console
        ) as progress:
            task = progress.add_task(
                f"Cracking {target_hash[:16]}...", total=total)

            while any(p.is_alive() for p in processes):
                if not found_queue.empty():
                    found_password = found_queue.get()
                    break
                time.sleep(0.3)
                # approximate progress
                progress.advance(task, chunk_size * 0.3)

        # ── Cleanup ───────────────────────────────────────────────
        stop_event.set()
        for p in processes:
            p.terminate()
            p.join(timeout=3)
        manager.shutdown()

        if found_password:
            console.print(Panel(
                f"[bold green][+] CRACKED![/bold green]\n\n"
                f"[white]Hash  :[/white] {target_hash}\n"
                f"[white]Plain :[/white] [bold yellow]{found_password}[/bold yellow]",
                title="Success", border_style="green"
            ))
        else:
            console.print("[red][!] Wordlist exhausted. No match found.[/red]")

        questionary.press_any_key_to_continue(style=Q_STYLE).ask()


def crack_hash(target_hash=None):
    if not target_hash:
        target_hash = questionary.text("Target hash:", style=Q_STYLE).ask()
    if target_hash:
        HashEngine().run(target_hash.strip())


if __name__ == "__main__":
    crack_hash()
