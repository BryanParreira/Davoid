# --- Module Context: Hash Cracker Pro v2.1 ---
# Purpose: Rule-based credential mutations.
# ---------------------------------------------
import hashlib


def mutate(word):
    """Generates mutations like 'pass123', 'P@ssword', etc."""
    return [word, word+"123", word+"2026", word.replace('a', '@'), word.capitalize()]


def crack_hash(target, algo="sha256"):
    wordlist = input("Wordlist: ")
    with open(wordlist, 'r', errors='ignore') as f:
        for line in f:
            for variant in mutate(line.strip()):
                if hashlib.new(algo, variant.encode()).hexdigest() == target:
                    return variant
    return None
