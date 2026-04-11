"""
scanner.py — Nmap Tactical Orchestrator & Exploit Mapper
UPGRADED: Auto-CVE lookup from NVD (National Vulnerability Database) API
          displayed inline in scan results. No API key required.
FIX: os.getuid() wrapped with hasattr() check so it doesn't crash on Windows.
"""

import os
import re
import time
import shutil
import subprocess
import json
import requests
import questionary
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from core.ui import draw_header, Q_STYLE
from core.database import db

try:
    import nmap
except ImportError:
    nmap = None

console = Console()


def _is_root():
    """Cross-platform root/admin check — safe on Windows, macOS, and Linux."""
    if hasattr(os, 'getuid'):
        return os.getuid() == 0
    try:
        import ctypes
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False


# ══════════════════════════════════════════════════════════════════════════════
#  NVD CVE LOOKUP ENGINE
# ══════════════════════════════════════════════════════════════════════════════

# Simple in-memory cache so we don't hammer the NVD API for the same product
_nvd_cache: dict = {}


def _query_nvd(product: str, version: str) -> list:
    """
    Query the NVD (National Vulnerability Database) API v2 for CVEs
    matching the given product + version. Returns a list of dicts:
      [{"id": "CVE-...", "score": 9.8, "severity": "CRITICAL", "summary": "..."}]
    Free, no API key required (rate-limited to 5 req/30s without key).
    """
    if not product or len(product) < 3:
        return []

    cache_key = f"{product.lower()}:{version.lower()}"
    if cache_key in _nvd_cache:
        return _nvd_cache[cache_key]

    results = []
    try:
        # Build a keyword string the NVD API understands
        keyword = f"{product} {version}".strip()
        url     = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        params  = {
            "keywordSearch":   keyword,
            "resultsPerPage":  5,       # top 5 is enough for inline display
        }
        resp = requests.get(url, params=params, timeout=8)
        if resp.status_code != 200:
            _nvd_cache[cache_key] = []
            return []

        data = resp.json()
        for item in data.get("vulnerabilities", []):
            cve   = item.get("cve", {})
            cve_id = cve.get("id", "?")

            # Extract CVSS score — try v3 first, fall back to v2
            score    = None
            severity = "UNKNOWN"
            metrics  = cve.get("metrics", {})

            for v3_key in ["cvssMetricV31", "cvssMetricV30"]:
                if v3_key in metrics and metrics[v3_key]:
                    m        = metrics[v3_key][0].get("cvssData", {})
                    score    = m.get("baseScore")
                    severity = m.get("baseSeverity", "UNKNOWN")
                    break

            if score is None and "cvssMetricV2" in metrics and metrics["cvssMetricV2"]:
                m        = metrics["cvssMetricV2"][0].get("cvssData", {})
                score    = m.get("baseScore")
                severity = metrics["cvssMetricV2"][0].get("baseSeverity", "UNKNOWN")

            # Extract description
            desc = ""
            for d in cve.get("descriptions", []):
                if d.get("lang") == "en":
                    desc = d.get("value", "")[:120]
                    break

            results.append({
                "id":       cve_id,
                "score":    score or 0.0,
                "severity": severity,
                "summary":  desc,
            })

        # Sort by score descending
        results.sort(key=lambda x: x["score"], reverse=True)
        _nvd_cache[cache_key] = results

        # Polite rate limit — NVD allows 5 requests per 30 seconds without a key
        time.sleep(0.7)

    except Exception:
        _nvd_cache[cache_key] = []

    return results


def _format_nvd_results(cves: list) -> str:
    """Format CVE list for inline display in the Nmap results table."""
    if not cves:
        return ""

    lines = []
    for cve in cves[:3]:   # show max 3 inline
        score    = cve["score"]
        sev      = cve["severity"]
        cve_id   = cve["id"]
        summary  = cve["summary"][:80] + ("..." if len(cve["summary"]) > 80 else "")

        # Colour-code by severity
        if sev in ("CRITICAL",) or score >= 9.0:
            colour = "bold red"
        elif sev == "HIGH" or score >= 7.0:
            colour = "red"
        elif sev == "MEDIUM" or score >= 4.0:
            colour = "yellow"
        else:
            colour = "dim"

        lines.append(
            f"  [{colour}]⚠ {cve_id} (CVSS {score:.1f} {sev})[/{colour}]\n"
            f"    [dim]{summary}[/dim]")

    if len(cves) > 3:
        lines.append(f"  [dim]...and {len(cves)-3} more CVEs[/dim]")

    return "\n" + "\n".join(lines)


# ══════════════════════════════════════════════════════════════════════════════
#  NMAP ENGINE
# ══════════════════════════════════════════════════════════════════════════════

class NmapEngine:
    def __init__(self):
        self.nm               = None
        self.has_searchsploit = False

    def check_dependencies(self):
        if nmap is None:
            console.print("[bold red][!] Missing: python-nmap[/bold red]")
            console.print("[white]Run: pip install python-nmap[/white]")
            return False
        try:
            self.nm = nmap.PortScanner()
        except nmap.PortScannerError:
            console.print("[bold red][!] nmap binary not found.[/bold red]")
            console.print(
                "[white]Install nmap: apt install nmap  /  brew install nmap[/white]")
            return False

        if shutil.which('searchsploit'):
            self.has_searchsploit = True
        else:
            console.print(
                "[dim][!] 'searchsploit' not found — local ExploitDB disabled.[/dim]")
        return True

    def query_searchsploit(self, product, version):
        """Query local ExploitDB for known vulnerabilities (silent on failure)."""
        if not product or not self.has_searchsploit:
            return ""
        query = " ".join(f"{product} {version}".strip().split()[:2])
        try:
            result = subprocess.run(
                ['searchsploit', query, '--json'],
                capture_output=True, text=True, timeout=5)
            if result.returncode == 0 and result.stdout:
                data    = json.loads(result.stdout)
                results = data.get('RESULTS_EXPLOIT', [])
                if results:
                    count = len(results)
                    out   = f"\n  └─ [bold red][!] {count} ExploitDB hits![/bold red]"
                    for exp in results[:2]:
                        title = exp.get('Title', '?')
                        path  = exp.get('Path', '')
                        tag   = "[bold red]MSF:[/bold red] " if (
                            "metasploit" in path.lower()) else ""
                        out  += f"\n      - {tag}{title[:60]}"
                    if count > 2:
                        out += f"\n      - [dim]...and {count-2} more[/dim]"
                    return out
        except Exception:
            pass
        return ""

    def run_scan(self):
        target = questionary.text(
            "Target IP or subnet (e.g., 192.168.1.0/24):",
            default="192.168.1.1", style=Q_STYLE).ask()
        if not target:
            return

        profile = questionary.select(
            "Scan Profile:",
            choices=[
                "1. Quick Scan       (-T4 -F)",
                "2. Stealth SYN      (-sS -T4)              [root]",
                "3. Full Audit       (-sS -sV -O -sC -T4)   [root]",
                "4. UDP Discovery    (-sU --top-ports 20)    [root]",
                "5. Vuln Scripts     (-sV --script vuln)     [root]",
                "Back",
            ],
            style=Q_STYLE
        ).ask()

        if not profile or profile == "Back":
            return

        if "Quick" in profile:
            args = "-T4 -F"
        elif "Stealth" in profile:
            if not _is_root():
                return console.print(
                    "[red][!] Stealth SYN requires root. Use sudo.[/red]")
            args = "-sS -T4"
        elif "Full" in profile:
            if not _is_root():
                return console.print(
                    "[red][!] Full audit requires root. Use sudo.[/red]")
            args = "-sS -sV -O -sC -T4"
        elif "UDP" in profile:
            if not _is_root():
                return console.print(
                    "[red][!] UDP scan requires root. Use sudo.[/red]")
            args = "-sU -T4 --top-ports 20"
        elif "Vuln" in profile:
            if not _is_root():
                return console.print(
                    "[red][!] Vuln scripts require root. Use sudo.[/red]")
            args = "-sV --script vuln -T4"
        else:
            args = "-T4 -F"

        # Ask whether to run NVD lookups
        use_nvd = questionary.confirm(
            "Run NVD CVE lookups on discovered services? (requires internet)",
            default=True, style=Q_STYLE).ask()

        console.print(
            f"[*] Running nmap against [bold]{target}[/bold] "
            f"args=[cyan]{args}[/cyan]")

        try:
            with console.status(
                    "[bold cyan]Nmap running — this may take a while...[/bold cyan]",
                    spinner="bouncingBar"):
                self.nm.scan(hosts=target, arguments=args)
        except Exception as e:
            console.print(f"[bold red][!] Nmap failed:[/bold red] {e}")
            return

        hosts = self.nm.all_hosts()
        if not hosts:
            console.print("[yellow][!] No active hosts discovered.[/yellow]")
            questionary.press_any_key_to_continue(style=Q_STYLE).ask()
            return

        for host in hosts:
            state  = self.nm[host].state()
            mac    = self.nm[host]['addresses'].get('mac', 'Unknown')
            vendor = (self.nm[host]['vendor'].get(mac, 'Unknown')
                      if mac != 'Unknown' else 'Unknown')

            os_match = "Unknown"
            if self.nm[host].get('osmatch'):
                os_match = self.nm[host]['osmatch'][0]['name']

            console.print(
                f"\n[bold green]Host:[/bold green] {host} ({state})")
            console.print(
                f"[bold white]MAC:[/bold white] {mac} [dim]({vendor})[/dim]  "
                f"[bold white]OS:[/bold white] {os_match}")

            table = Table(border_style="cyan")
            table.add_column("Port",           style="yellow", justify="right")
            table.add_column("State",          style="magenta")
            table.add_column("Service",        style="cyan")
            table.add_column("Version / Intel",style="white")

            db_services = []

            for proto in self.nm[host].all_protocols():
                for port in sorted(self.nm[host][proto].keys()):
                    pd      = self.nm[host][proto][port]
                    pstate  = pd['state']
                    name    = pd.get('name',      '')
                    product = pd.get('product',   '')
                    version = pd.get('version',   '')
                    extra   = pd.get('extrainfo', '')
                    info    = f"{product} {version} {extra}".strip() or "N/A"

                    # ── Local ExploitDB lookup ────────────────────────────────
                    if product:
                        info += self.query_searchsploit(product, version)

                    # ── NVD CVE lookup ────────────────────────────────────────
                    if use_nvd and product and pstate == "open":
                        with console.status(
                                f"[dim]Querying NVD for {product} {version}...[/dim]",
                                spinner="dots"):
                            cves = _query_nvd(product, version)
                        if cves:
                            info += _format_nvd_results(cves)

                            # Log critical CVEs to the mission database
                            critical = [c for c in cves if c["score"] >= 7.0]
                            if critical:
                                cve_summary = "\n".join(
                                    f"{c['id']} (CVSS {c['score']}) — {c['summary']}"
                                    for c in critical)
                                db.log(
                                    "NVD-CVE", host,
                                    f"Port {port}/{proto} ({product} {version}):\n"
                                    f"{cve_summary}",
                                    "CRITICAL" if any(
                                        c["score"] >= 9.0 for c in critical)
                                    else "HIGH")

                    # ── NSE script output ─────────────────────────────────────
                    if 'script' in pd:
                        for sname, sres in pd['script'].items():
                            info += (
                                f"\n  └─ [bold red]{sname}:[/bold red] "
                                f"{sres.splitlines()[0]}")

                    table.add_row(f"{port}/{proto}", pstate, name, info)

                    if pstate == "open":
                        db_services.append(
                            f"{port}/{proto} ({name}): "
                            + re.sub(r'\[.*?\]', '', info))

            if db_services:
                console.print(table)
                clean = (
                    "\n".join(db_services)
                    .replace("[bold red]", "").replace("[/bold red]", "")
                    .replace("[dim]", "").replace("[/dim]", "")
                )
                db.log("Nmap-Engine", host,
                       f"OS: {os_match}\nServices:\n{clean}", "HIGH")
            else:
                console.print("[dim]No open ports on this host.[/dim]")

        console.print(
            f"\n[bold green][+] Scan complete. "
            f"Results saved to Mission Database.[/bold green]")
        questionary.press_any_key_to_continue(style=Q_STYLE).ask()

    def network_discovery(self):
        draw_header("Nmap Tactical Orchestrator & Exploit Mapper")
        if not self.check_dependencies():
            questionary.press_any_key_to_continue(style=Q_STYLE).ask()
            return
        self.run_scan()


def network_discovery():
    NmapEngine().network_discovery()


if __name__ == "__main__":
    network_discovery()