"""
modules/auditor.py — System Posture & Dependency Auditor
Checks all framework dependencies, required tools, Python packages,
network exposure, and system capabilities. OS-safe (Linux/macOS/Windows).
"""

import os
import sys
import shutil
import socket
import platform
import subprocess
import questionary
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from core.ui import draw_header, Q_STYLE

console = Console()

# ─────────────────────────────────────────────────────────────────────────────
#  CONSTANTS
# ─────────────────────────────────────────────────────────────────────────────

COMMON_PORTS: list[tuple[int, str]] = [
    (21,    "FTP"),
    (22,    "SSH"),
    (23,    "Telnet"),
    (25,    "SMTP"),
    (80,    "HTTP"),
    (135,   "RPC"),
    (139,   "NetBIOS"),
    (443,   "HTTPS"),
    (445,   "SMB"),
    (3306,  "MySQL"),
    (3389,  "RDP"),
    (5432,  "PostgreSQL"),
    (5900,  "VNC"),
    (6379,  "Redis"),
    (8080,  "HTTP-Alt"),
    (27017, "MongoDB"),
]

TOOL_DEPS: list[tuple[str, str]] = [
    ("nmap",         "Network scanner — required for Scanner module"),
    ("tcpdump",      "Packet capture — required for Sniffer"),
    ("git",          "Version control — required for updates"),
    ("python3",      "Python interpreter"),
    ("searchsploit", "ExploitDB — optional, enhances Scanner"),
    ("airmon-ng",    "WiFi monitor mode — optional"),
    ("msfconsole",   "Metasploit — required for MSF module"),
    ("hashcat",      "GPU hash cracking — optional"),
    ("john",         "CPU hash cracking — optional"),
    ("tor",          "Tor proxy — required for stealth mode"),
]

PYTHON_DEPS: list[tuple[str, str]] = [
    ("rich",          "Terminal UI"),
    ("scapy",         "Packet crafting"),
    ("requests",      "HTTP client"),
    ("cryptography",  "Encryption (Fernet)"),
    ("sqlalchemy",    "Database ORM"),
    ("questionary",   "Interactive prompts"),
    ("jinja2",        "HTML templating"),
    ("nmap",          "python-nmap binding"),
    ("paramiko",      "SSH client"),
    ("ldap3",         "Active Directory LDAP"),
    ("beautifulsoup4", "Web page parsing"),
    ("phonenumbers",  "Phone number intel"),
    ("dnspython",     "DNS resolution"),
    ("langchain_ollama", "AI Cortex (LangChain)"),
    ("aiohttp",       "Async HTTP (GhostHub C2)"),
    ("yaml",          "YAML config parsing"),
]


# ─────────────────────────────────────────────────────────────────────────────
#  HELPERS
# ─────────────────────────────────────────────────────────────────────────────

def _ok(text: str) -> str: return f"[bold green]{text}[/bold green]"
def _warn(text: str) -> str: return f"[bold yellow]{text}[/bold yellow]"
def _fail(text: str) -> str: return f"[bold red]{text}[/bold red]"


def _is_root() -> bool:
    if hasattr(os, 'getuid'):
        return os.getuid() == 0
    try:
        import ctypes
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False


# ─────────────────────────────────────────────────────────────────────────────
#  CHECKS
# ─────────────────────────────────────────────────────────────────────────────

def check_system():
    table = Table(title="System Information", border_style="cyan")
    table.add_column("Property", style="cyan")
    table.add_column("Value",    style="white")

    table.add_row("OS",           f"{platform.system()} {platform.release()}")
    table.add_row("Architecture", platform.machine())
    table.add_row("Python",       sys.version.split()[0])
    table.add_row("Root/Admin",   _ok("YES") if _is_root()
                  else _warn("NO (some modules need root)"))
    table.add_row("Platform",     sys.platform)

    try:
        hostname = socket.gethostname()
        local_ip = socket.gethostbyname(hostname)
        table.add_row("Hostname",  hostname)
        table.add_row("Local IP",  local_ip)
    except Exception:
        pass

    console.print(table)


def check_tool_deps():
    table = Table(title="System Tool Dependencies",
                  border_style="cyan", expand=True)
    table.add_column("Tool",        style="cyan",  no_wrap=True)
    table.add_column("Status",      style="white", no_wrap=True)
    table.add_column("Description", style="dim")

    for tool, desc in TOOL_DEPS:
        path = shutil.which(tool)
        if path:
            try:
                ver = subprocess.check_output(
                    [tool, "--version"], stderr=subprocess.STDOUT,
                    timeout=3
                ).decode().split("\n")[0][:40]
                status = _ok(f"FOUND  ({ver})")
            except Exception:
                status = _ok("FOUND")
        else:
            status = _fail("MISSING")
        table.add_row(tool, status, desc)

    console.print(table)


def check_python_deps():
    table = Table(title="Python Package Dependencies",
                  border_style="cyan", expand=True)
    table.add_column("Package",     style="cyan",  no_wrap=True)
    table.add_column("Status",      style="white", no_wrap=True)
    table.add_column("Description", style="dim")

    for pkg, desc in PYTHON_DEPS:
        try:
            mod = __import__(pkg.replace(
                "-", "_").replace("beautifulsoup4", "bs4"))
            ver = getattr(mod, "__version__", "installed")
            status = _ok(f"OK  ({ver})")
        except ImportError:
            status = _fail("MISSING  — pip install " + pkg)
        table.add_row(pkg, status, desc)

    console.print(table)


def check_network_exposure():
    table = Table(title="Local Network Exposure",
                  border_style="yellow", expand=True)
    table.add_column("Port",    style="yellow", justify="right", no_wrap=True)
    table.add_column("Service", style="cyan",   no_wrap=True)
    table.add_column("Status",  style="white",  no_wrap=True)

    open_ports = []
    for port, service in COMMON_PORTS:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.5):
                open_ports.append(port)
                table.add_row(str(port), service, _warn(
                    f"OPEN — consider closing if unintended"))
        except Exception:
            table.add_row(str(port), service, "[dim]Closed[/dim]")

    console.print(table)
    if open_ports:
        console.print(
            f"[yellow][!] {len(open_ports)} port(s) open on localhost.[/yellow]")
    else:
        console.print(
            "[green][+] No unexpected ports open on localhost.[/green]")


def check_directories():
    table = Table(title="Framework Directories", border_style="cyan")
    table.add_column("Directory", style="cyan")
    table.add_column("Status",    style="white")
    table.add_column("Contents",  style="dim")

    base = os.path.dirname(os.path.dirname(__file__))
    dirs = ["logs", "payloads", "reports", "wordlists", "clones", "plugins"]

    for d in dirs:
        path = os.path.join(base, d)
        if os.path.exists(path):
            count = len(os.listdir(path))
            table.add_row(d, _ok("EXISTS"), f"{count} item(s)")
        else:
            table.add_row(d, _warn("MISSING"), "Will be created on next run")

    console.print(table)


def check_wordlists():
    """Check for common wordlist files."""
    table = Table(title="Wordlist Status", border_style="cyan")
    table.add_column("File",   style="cyan")
    table.add_column("Status", style="white")
    table.add_column("Size",   style="dim")

    locations = [
        "/usr/share/wordlists/rockyou.txt",
        "/usr/share/wordlists/fasttrack.txt",
        "/usr/share/wordlists/dirb/common.txt",
        os.path.join(os.path.dirname(os.path.dirname(__file__)),
                     "wordlists", "rockyou.txt"),
    ]

    for path in locations:
        if os.path.exists(path):
            size = os.path.getsize(path)
            size_str = f"{size / 1024 / 1024:.1f} MB"
            table.add_row(os.path.basename(path), _ok("FOUND"), size_str)
        else:
            table.add_row(os.path.basename(path), _fail("MISSING"), "—")

    console.print(table)
    console.print(
        "[dim]To install rockyou: apt install wordlists / gunzip /usr/share/wordlists/rockyou.txt.gz[/dim]")


# ─────────────────────────────────────────────────────────────────────────────
#  ENTRY POINT
# ─────────────────────────────────────────────────────────────────────────────

def run_auditor():
    draw_header("System Posture & Dependency Auditor")

    console.print(Panel(
        "[white]Running full framework audit...[/white]\n"
        "[dim]This checks all dependencies, tools, and system readiness.[/dim]",
        border_style="cyan"
    ))

    sections = [
        ("System Information",     check_system),
        ("System Tool Deps",       check_tool_deps),
        ("Python Package Deps",    check_python_deps),
        ("Local Network Exposure", check_network_exposure),
        ("Framework Directories",  check_directories),
        ("Wordlist Status",        check_wordlists),
    ]

    for title, fn in sections:
        console.print(f"\n[bold cyan]══ {title} ══[/bold cyan]")
        try:
            fn()
        except Exception as e:
            console.print(f"[red][!] Check failed: {e}[/red]")

    console.print("\n[bold green][+] Audit complete.[/bold green]")
    questionary.press_any_key_to_continue(style=Q_STYLE).ask()


if __name__ == "__main__":
    run_auditor()
