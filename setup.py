import os
import sys
import subprocess


def install():
    print("[*] Davoid: Syncing root dependencies...")
    subprocess.run([sys.executable, "-m", "pip",
                   "install", "rich", "scapy", "requests"])

    python_exe = sys.executable
    script_path = os.path.abspath("main.py")
    bin_path = "/usr/local/bin/davoid"

    # Wrapper forces root and points to the hidden environment
    wrapper = f"#!/bin/bash\nsudo {python_exe} {script_path} \"$@\""

    try:
        with open(bin_path, "w") as f:
            f.write(wrapper)
        os.system(f"chmod +x {bin_path}")
        os.system(f"chmod +x {script_path}")
    except PermissionError:
        print("[-] Fatal: Installation requires sudo.")


if __name__ == "__main__":
    install()
