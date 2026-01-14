import hashlib
import multiprocessing
import os
import sys
import time
from itertools import product

# --- Module Context: Hash Cracker Pro v2.1 (Performance Optimized) ---
# Purpose: High-speed, rule-based credential mutation & multi-core cracking.


class MutationEngine:
    """Advanced rule-based engine for credential mutations."""

    LEET_MAP = {
        'a': ['a', '4', '@'],
        'e': ['e', '3'],
        'i': ['i', '1', '!'],
        'o': ['o', '0'],
        's': ['s', '5', '$'],
        't': ['t', '7', '+'],
        'b': ['b', '8'],
        'g': ['g', '9']
    }

    @staticmethod
    def get_variants(word):
        """Generates a comprehensive set of mutations for a single word."""
        variants = set()
        word = word.strip()
        if not word:
            return []

        # 1. Base variations
        variants.add(word)
        variants.add(word.lower())
        variants.add(word.upper())
        variants.add(word.capitalize())
        variants.add(word.swapcase())

        # 2. Common Suffixes & Prefixes
        years = ["2023", "2024", "2025", "2026"]
        digits = ["1", "123", "1234", "!", "!!", "01"]

        for suffix in years + digits:
            variants.add(f"{word}{suffix}")
            variants.add(f"{word.capitalize()}{suffix}")

        # 3. LeetSpeak Mutation (Selective)
        # Optimized to only mutate the first few occurrences to prevent combinatorial explosion
        leet_word = word.lower()
        for char, replacements in MutationEngine.LEET_MAP.items():
            if char in leet_word:
                for rep in replacements:
                    variants.add(leet_word.replace(char, rep))
                    variants.add(leet_word.replace(char, rep).capitalize())

        return list(variants)


def _crack_worker(target, algo, word_chunk, found_flag, result_val):
    """Internal worker for multiprocessing."""
    for word in word_chunk:
        if found_flag.is_set():
            return

        # Generate and check mutations
        for variant in MutationEngine.get_variants(word):
            if hashlib.new(algo, variant.encode()).hexdigest() == target:
                result_val.value = variant.encode()
                found_flag.set()
                return


def crack_hash(target, algo="sha256", wordlist_path=None):
    """
    High-performance cracking entry point.
    Splits wordlist into chunks and processes them across all CPU cores.
    """
    if not wordlist_path:
        wordlist_path = input("[?] Path to wordlist: ").strip()

    if not os.path.exists(wordlist_path):
        print(f"[!] Error: File {wordlist_path} not found.")
        return None

    print(f"[*] Target: {target}")
    print(f"[*] Algorithm: {algo}")
    print(f"[*] Loading wordlist and initializing cores...")

    # Load wordlist into memory (efficient for files up to ~500MB)
    try:
        with open(wordlist_path, 'r', errors='ignore') as f:
            all_words = f.read().splitlines()
    except Exception as e:
        print(f"[!] Read Error: {e}")
        return None

    num_cores = multiprocessing.cpu_count()
    chunk_size = len(
        all_words) // num_cores if len(all_words) > num_cores else 1
    chunks = [all_words[i:i + chunk_size]
              for i in range(0, len(all_words), chunk_size)]

    # Shared state between processes
    manager = multiprocessing.Manager()
    found_flag = manager.Event()
    result_val = manager.Value(bytes, b"")

    start_time = time.time()
    processes = []

    for chunk in chunks:
        p = multiprocessing.Process(
            target=_crack_worker,
            args=(target.lower(), algo, chunk, found_flag, result_val)
        )
        p.start()
        processes.append(p)

    print(f"[*] Cracking with {num_cores} threads... (Press Ctrl+C to abort)")

    try:
        # Wait for processes or discovery
        while any(p.is_alive() for p in processes):
            if found_flag.is_set():
                break
            time.sleep(0.5)
    except KeyboardInterrupt:
        print("\n[!] Aborting...")
    finally:
        for p in processes:
            p.terminate()

    elapsed = time.time() - start_time
    final_res = result_val.value.decode()

    if final_res:
        print(f"\n[+] SUCCESS!")
        print(f"[+] Plaintext: {final_res}")
        print(f"[+] Time: {elapsed:.2f} seconds")
        return final_res
    else:
        print(
            f"\n[-] FAILURE: Hash not found in wordlist (Time: {elapsed:.2f}s)")
        return None


if __name__ == "__main__":
    # Test block / CLI usage
    print("--- Davoid: Hash Cracker Pro v2.1 ---")
    t = input("Enter Target Hash: ").strip()
    a = input("Enter Algorithm (md5/sha1/sha256/sha512): ").strip() or "sha256"
    crack_hash(t, a)
