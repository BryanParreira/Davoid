import hashlib
import multiprocessing
import os
import sys
import itertools
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn
from rich.panel import Panel

console = Console()

class HashEngine:
    def __init__(self, algo="sha256"):
        self.algo = algo
        self.stop_event = multiprocessing.Event()

    @staticmethod
    def mutate(word):
        """
        Advanced mutation engine. 
        Generates variants using case toggling, padding, and leet-speak.
        """
        word = word.strip()
        if not word:
            return []
            
        variants = {word, word.upper(), word.lower(), word.capitalize()}
        
        # Common padding (Years, sequences)
        suffixes = ["123", "1234", "2024", "2025", "2026", "!", "!!", "@"]
        current_variants = list(variants)
        for v in current_variants:
            for s in suffixes:
                variants.add(v + s)

        # Leet-speak transformation map
        leet_map = {'a': '@', 'e': '3', 'i': '1', 'o': '0', 's': '$', 't': '7'}
        
        # Create a leet variant
        leet_word = "".join(leet_map.get(c.lower(), c) for c in word)
        variants.add(leet_word)
        variants.add(leet_word.capitalize())
        
        return list(variants)

    def crack_worker(self, target, wordlist_chunk, queue):
        """Worker process optimized for minimal memory overhead."""
        try:
            for word in wordlist_chunk:
                if self.stop_event.is_set():
                    return
                
                for variant in self.mutate(word):
                    # Direct check against the hashing algorithm
                    h = hashlib.new(self.algo)
                    h.update(variant.encode('utf-8', errors='ignore'))
                    if h.hexdigest() == target:
                        queue.put(variant)
                        self.stop_event.set()
                        return
        except Exception:
            pass

    def run(self, target_hash):
        """Main orchestrator for the multi-core cracking operation."""
        draw_header("Cracker-Pro: Multi-Core Mutation Engine")
        
        path = console.input("[bold yellow]Wordlist Path (e.g., rockyou.txt): [/bold yellow]").strip()
        if not os.path.exists(path):
            return console.print("[red][!] Error: Wordlist file not found.[/red]")

        # Algorithm selection (Auto-detect length as a fallback)
        if len(target_hash) == 32: self.algo = "md5"
        elif len(target_hash) == 40: self.algo = "sha1"
        elif len(target_hash) == 64: self.algo = "sha256"
        
        console.print(f"[*] Detected Algorithm: [bold cyan]{self.algo.upper()}[/bold cyan]")

        try:
            with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                words = f.read().splitlines()

            total_words = len(words)
            num_cores = multiprocessing.cpu_count()
            chunk_size = max(1, total_words // num_cores)
            chunks = [words[i:i + chunk_size] for i in range(0, total_words, chunk_size)]

            # Using a Queue to communicate found password back to main process
            found_queue = multiprocessing.Queue()
            processes = []

            console.print(f"[*] Dispatching tasks across {num_cores} logical cores...")

            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(bar_width=40),
                TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
                TimeElapsedColumn(),
                console=console
            ) as progress:
                
                progress.add_task(f"Cracking {target_hash[:10]}...", total=total_words)

                for chunk in chunks:
                    p = multiprocessing.Process(
                        target=self.crack_worker, 
                        args=(target_hash, chunk, found_queue)
                    )
                    p.start()
                    processes.append(p)

                found_password = None
                while any(p.is_alive() for p in processes):
                    if not found_queue.empty():
                        found_password = found_queue.get()
                        break
                    time.sleep(0.5)

            # Cleanup
            self.stop_event.set()
            for p in processes:
                p.terminate()
                p.join()

            if found_password:
                console.print(Panel(
                    f"[bold green][+] SUCCESS![/bold green]\n\n"
                    f"[white]Hash:[/white] {target_hash}\n"
                    f"[white]Password:[/white] [bold yellow]{found_password}[/bold yellow]",
                    title="Crack Completed", border_style="green"
                ))
            else:
                console.print("\n[red][!] Exhausted wordlist. No match found.[/red]")

        except Exception as e:
            console.print(f"[red][!] Cracking error: {e}[/red]")

def draw_header(text):
    console.print(Panel(f"[bold white]{text}[/bold white]", border_style="magenta", expand=False))

def start_crack():
    target = console.input("[bold yellow]Enter Target Hash: [/bold yellow]").strip()
    if target:
        engine = HashEngine()
        engine.run(target)

if __name__ == "__main__":
    import time
    start_crack()