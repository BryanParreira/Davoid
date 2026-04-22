"""
modules/auditor.py — System Posture & Dependency Auditor
FIXES & IMPROVEMENTS:
  - os.getuid() guarded — no longer crashes on Windows
  - Windows branch now actually runs checks (was silently empty before)
  - Added macOS-specific checks
  - Dependency check extended with version info where available
  - Added Python package dependency audit
  - Network exposure check covers more ports with service labels
  - Output cleaner with color-coded pass/warn/fail status
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
    ("nmap",       "Network scanner"),
    ("tcpdump",    "Packet capture"),
    ("git",        "Version control"),
    ("python3",    "Interpreter"),
    ("searchsploit","ExploitDB search"),
    ("airmon-ng",  "WiFi monitor mode"),
    ("iw",         "WiFi control (Linux)"),
]

PYTHON_DEPS: list[tuple[str, str]] = [
    ("rich",         "Terminal UI"),
    ("scapy",        "Packet crafting"),
    ("requests",     "HTTP client"),
    ("cryptography", "Encryption"),
    ("sqlalchemy",   "Database ORM"),
    ("questionary",  "Interactive prompts"),
    ("jinja2",       "HTML templating"),
    ("nmap",         "Nmap python binding"),
    ("paramiko",     "SSH client"),
    ("ldap3",        "Active Directory"),
    ("mitmproxy",    "Proxy engine"),
    ("stegano",      "Steganography"),
]


# ─────────────────────────────────────────────────────────────────────────────
#  HELPERS
# ─────────────────────────────────────────────────────────────────────────────

def _ok(text: str)   -> str: return f"[bold green]{text}[/bold green]"
def _warn(text: str) -> str: return f"[bold yellow]{text}[/bold yellow]"
def _fail(text: str) -> str: return f"[bold red]{text}[/bold red]"

def _is_root() -> bool:
    """Cross-platform admin/root check."""
    if hasattr(os, "getuid"):
        return os.getuid() == 0
    try:
        import ctypes
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False

def _port_open(port: int, host: str = "127.0.0.1", timeout: float = 0.15) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(timeout)
        return s.connect_ex((host, port)) == 0

def _run(cmd: list[str], timeout: int = 5) -> str:
    """Run a subprocess and return stdout, empty string on failure."""
    try:
        r = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return (r.stdout or "").strip()
    except Exception:
        return ""

def _get_tool_version(tool: str) -> str:
    """Try common version flags and return a short version string."""
    for flag in ["--version", "-version", "-V", "version"]:
        out = _run([tool, flag])
        if out:
            # Return just the first line, trimmed
            return out.splitlines()[0][:60]
    return ""

def _get_python_pkg_version(pkg_name: str) -> str:
    try:
        import importlib.metadata
        return importlib.metadata.version(pkg_name)
    except Exception:
        return ""


# ─────────────────────────────────────────────────────────────────────────────
#  AUDITOR CLASS
# ─────────────────────────────────────────────────────────────────────────────

class DavoidAuditor:
    def __init__(self):
        self.os_type = platform.system()   # "Linux", "Darwin", "Windows"

    # ── 1. Tool dependencies ──────────────────────────────────────

    def audit_tools(self):
        table = Table(
            title="System Tool Dependency Report",
            border_style="cyan",
            expand=True,
        )
        table.add_column("Tool",        style="yellow", no_wrap=True)
        table.add_column("Purpose",     style="dim")
        table.add_column("Status",      style="white")
        table.add_column("Version",     style="dim")

        for tool, purpose in TOOL_DEPS:
            # Skip Linux-only tools on other platforms
            if tool in ("airmon-ng", "iw") and self.os_type != "Linux":
                continue
            # macOS uses 'airport' instead of iw
            if tool == "iw" and self.os_type == "Darwin":
                tool    = "airport"
                purpose = "WiFi control (macOS)"

            found = bool(shutil.which(tool))

            # Special case: macOS airport lives in a non-PATH location
            if not found and tool == "airport" and self.os_type == "Darwin":
                airport_path = (
                    "/System/Library/PrivateFrameworks/"
                    "Apple80211.framework/Versions/Current/Resources/airport"
                )
                found = os.path.exists(airport_path)

            version = _get_tool_version(tool) if found else ""
            status  = _ok("FOUND") if found else _fail("MISSING")
            table.add_row(tool, purpose, status, version)

        console.print(table)

    # ── 2. Python package dependencies ───────────────────────────

    def audit_python_packages(self):
        table = Table(
            title="Python Package Dependency Report",
            border_style="magenta",
            expand=True,
        )
        table.add_column("Package",   style="cyan", no_wrap=True)
        table.add_column("Purpose",   style="dim")
        table.add_column("Status",    style="white")
        table.add_column("Version",   style="dim")

        for pkg, purpose in PYTHON_DEPS:
            ver    = _get_python_pkg_version(pkg)
            found  = bool(ver)
            status = _ok("INSTALLED") if found else _warn("MISSING")
            table.add_row(pkg, purpose, status, ver)

        console.print(table)

    # ── 3. System posture ─────────────────────────────────────────

    def audit_posture(self):
        table = Table(
            title="System Security Posture Audit",
            border_style="bold magenta",
            expand=True,
        )
        table.add_column("Security Check",  style="cyan")
        table.add_column("Result",          style="white")
        table.add_column("Notes",           style="dim")

        # ── Privileges ──
        root = _is_root()
        table.add_row(
            "Elevated Privileges",
            _ok("ROOT / ADMIN") if root else _warn("Standard User"),
            "Required for raw socket operations" if not root else "Full access",
        )

        # ── OS-specific checks ──
        if self.os_type == "Linux":
            self._linux_checks(table)
        elif self.os_type == "Darwin":
            self._macos_checks(table)
        elif self.os_type == "Windows":
            self._windows_checks(table)

        # ── Open ports (all platforms) ──
        exposed = []
        for port, label in COMMON_PORTS:
            if _port_open(port):
                exposed.append(f"{port}/{label}")

        if exposed:
            table.add_row(
                "Locally Exposed Ports",
                _warn(", ".join(exposed)),
                "Verify these are expected services",
            )
        else:
            table.add_row(
                "Locally Exposed Ports",
                _ok("None detected"),
                "No risky ports listening on 127.0.0.1",
            )

        # ── Python interpreter path ──
        table.add_row(
            "Python Interpreter",
            _ok(sys.executable),
            f"v{platform.python_version()}",
        )

        console.print(table)

    def _linux_checks(self, table: Table):
        # UFW firewall
        ufw_out = _run(["ufw", "status"])
        if "active" in ufw_out.lower():
            table.add_row("UFW Firewall", _ok("ACTIVE"), ufw_out.splitlines()[0])
        elif ufw_out:
            table.add_row("UFW Firewall", _warn("INACTIVE"), "Run: sudo ufw enable")
        else:
            table.add_row("UFW Firewall", _warn("NOT FOUND"), "apt install ufw")

        # /etc/shadow readability
        shadow_readable = os.access("/etc/shadow", os.R_OK)
        table.add_row(
            "/etc/shadow Readable",
            _fail("VULNERABLE") if shadow_readable else _ok("Secure"),
            "World-readable shadow file exposes password hashes" if shadow_readable else "",
        )

        # ASLR
        aslr_path = "/proc/sys/kernel/randomize_va_space"
        if os.path.exists(aslr_path):
            with open(aslr_path) as f:
                val = f.read().strip()
            aslr_ok = val == "2"
            table.add_row(
                "ASLR (randomize_va_space)",
                _ok("ENABLED (2)") if aslr_ok else _fail(f"WEAK ({val})"),
                "echo 2 > /proc/sys/kernel/randomize_va_space" if not aslr_ok else "",
            )

        # SELinux / AppArmor
        selinux = _run(["getenforce"])
        if selinux:
            ok = selinux.strip() == "Enforcing"
            table.add_row(
                "SELinux",
                _ok(selinux) if ok else _warn(selinux),
                "" if ok else "setenforce 1",
            )
        else:
            aa = _run(["aa-status", "--enabled"])
            table.add_row(
                "AppArmor",
                _ok("ACTIVE") if "0" in aa else _warn("NOT ACTIVE"),
                "",
            )

    def _macos_checks(self, table: Table):
        # Application firewall
        fw = _run(["defaults", "read", "/Library/Preferences/com.apple.alf", "globalstate"])
        states = {"0": _fail("DISABLED"), "1": _ok("ENABLED"), "2": _ok("STEALTH MODE")}
        table.add_row(
            "macOS Application Firewall",
            states.get(fw.strip(), _warn("UNKNOWN")),
            "System Preferences → Security → Firewall" if fw.strip() == "0" else "",
        )

        # SIP (System Integrity Protection)
        sip = _run(["csrutil", "status"])
        sip_ok = "enabled" in sip.lower()
        table.add_row(
            "System Integrity Protection (SIP)",
            _ok("ENABLED") if sip_ok else _warn("DISABLED"),
            sip.replace("System Integrity Protection status: ", ""),
        )

        # Gatekeeper
        gk = _run(["spctl", "--status"])
        gk_ok = "enabled" in gk.lower()
        table.add_row(
            "Gatekeeper",
            _ok("ENABLED") if gk_ok else _warn("DISABLED"),
            "",
        )

    def _windows_checks(self, table: Table):
        # Windows Defender status
        defender = _run([
            "powershell", "-NoProfile", "-Command",
            "Get-MpComputerStatus | Select-Object -ExpandProperty RealTimeProtectionEnabled"
        ])
        if defender.strip().lower() == "true":
            table.add_row("Windows Defender Real-Time", _ok("ENABLED"),  "")
        elif defender:
            table.add_row("Windows Defender Real-Time", _fail("DISABLED"), "Enable in Windows Security")
        else:
            table.add_row("Windows Defender Real-Time", _warn("UNKNOWN"), "Could not query status")

        # Windows Firewall
        fw = _run([
            "netsh", "advfirewall", "show", "allprofiles", "state"
        ])
        fw_on = fw.count("ON") >= 1
        table.add_row(
            "Windows Firewall (All Profiles)",
            _ok("ON") if fw_on else _fail("OFF"),
            "",
        )

        # UAC
        try:
            import winreg
            key  = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                                  r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System")
            val, _ = winreg.QueryValueEx(key, "EnableLUA")
            table.add_row(
                "User Account Control (UAC)",
                _ok("ENABLED") if val else _fail("DISABLED"),
                "",
            )
        except Exception:
            table.add_row("User Account Control (UAC)", _warn("UNKNOWN"), "")

        # Secure Boot
        sb = _run(["powershell", "-NoProfile", "-Command",
                   "Confirm-SecureBootUEFI"])
        if "true" in sb.lower():
            table.add_row("Secure Boot", _ok("ENABLED"), "")
        elif "false" in sb.lower():
            table.add_row("Secure Boot", _warn("DISABLED"), "Enable in UEFI firmware settings")
        else:
            table.add_row("Secure Boot", _warn("UNKNOWN"), "")

    # ── Main run ──────────────────────────────────────────────────

    def run(self):
        draw_header("Davoid Advanced Auditor & Posture Scout")

        console.print(Panel(
            f"[white]OS:[/white] {platform.system()} {platform.release()} "
            f"({platform.machine()})\n"
            f"[white]Python:[/white] {sys.version.splitlines()[0]}\n"
            f"[white]Hostname:[/white] {platform.node()}",
            title="Environment",
            border_style="dim",
        ))

        choice = questionary.select(
            "Select Audit Scope:",
            choices=[
                "1. Full Audit (Tools + Packages + Posture)",
                "2. System Tool Dependencies Only",
                "3. Python Package Dependencies Only",
                "4. Security Posture Only",
                "Back",
            ],
            style=Q_STYLE,
        ).ask()

        if not choice or choice == "Back":
            return

        if "Full" in choice or "Tool" in choice:
            self.audit_tools()
            console.print()

        if "Full" in choice or "Package" in choice:
            self.audit_python_packages()
            console.print()

        if "Full" in choice or "Posture" in choice:
            self.audit_posture()
            console.print()

        questionary.press_any_key_to_continue(style=Q_STYLE).ask()


def run_auditor():
    DavoidAuditor().run()


if __name__ == "__main__":
    run_auditor()