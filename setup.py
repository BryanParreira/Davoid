import os
import sys
import subprocess


def install():
    print("[*] Davoid: Syncing root dependencies...")
    # Updated dependency list
    packages = [
        "rich", "scapy", "requests[socks]", "cryptography",
        "jinja2", "questionary", "PyYAML", "beautifulsoup4",
        "netaddr", "psutil"
    ]

    subprocess.run([sys.executable, "-m", "pip", "install"] + packages)

    python_exe = sys.executable
    script_path = os.path.abspath("main.py")
    repo_path = os.path.dirname(script_path)
    bin_path = "/usr/local/bin/davoid"

    # Wrapper logic: Detects --update and pulls from GitHub
    wrapper_content = f"""#!/bin/bash
if [ "$1" == "--update" ]; then
    echo "[*] Davoid: Pulling latest changes from GitHub..."
    cd {repo_path} && git pull
    echo "[+] Update complete."
    exit 0
fi

sudo {python_exe} {script_path} "$@"
"""

    try:
        with open(bin_path, "w") as f:
            f.write(wrapper_content)
        os.system(f"chmod +x {bin_path}")
        os.system(f"chmod +x {script_path}")
        print(f"[+] Installed successfully. Run 'davoid' to start.")
    except PermissionError:
        print("[-] Error: Run setup with sudo.")


if __name__ == "__main__":
    install()
