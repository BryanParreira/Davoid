"""
purple_team.py — Adversary Emulation & MITRE ATT&CK Mapper
IMPROVEMENTS:
  - Works with updated database.py dict return format
  - MITRE report can be exported to a Markdown file
  - Dynamic mapping: unknown modules get a best-effort guess from keywords
  - Detection rules rendered as proper Rich syntax panels
  - Added ATT&CK Navigator layer export (JSON) for importing into the web tool
  - Graceful handling of empty DB
"""

import json
import datetime
import questionary
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.syntax import Syntax
from core.ui import draw_header, Q_STYLE
from core.database import db

console = Console()

# ─────────────────────────────────────────────────────────────────────────────
#  STATIC MITRE MAPPINGS  (module name → ATT&CK data)
# ─────────────────────────────────────────────────────────────────────────────

MITRE_MAPPINGS: dict[str, dict] = {
    "Nmap-Engine": {
        "ttp":      "T1046",
        "tactic":   "Discovery",
        "name":     "Network Service Discovery",
        "splunk":   'index=network sourcetype=firewall action=allowed\n| stats count by src_ip, dest_port\n| where count > 100',
        "sigma": (
            "title: High Volume Port Scan Detected\n"
            "logsource:\n  category: firewall\ndetection:\n"
            "  selection:\n    dest_port|count: '>50'\n  condition: selection"
        ),
    },
    "AD Engine": {
        "ttp":      "T1558.004",
        "tactic":   "Credential Access",
        "name":     "AS-REP Roasting",
        "splunk":   'index=wineventlog EventCode=4768 TicketOptions=0x40810010\n| stats count by src_ip, Account_Name',
        "sigma": (
            "title: AS-REP Roasting (Event 4768)\n"
            "logsource:\n  product: windows\n  service: security\n"
            "detection:\n  selection:\n    EventID: 4768\n    TicketOptions: '0x40810010'\n  condition: selection"
        ),
    },
    "Live Interceptor": {
        "ttp":      "T1040",
        "tactic":   "Credential Access",
        "name":     "Network Sniffing",
        "splunk":   'index=sysmon EventCode=1\n| where match(Image, "wireshark|tcpdump|tshark")\n| stats count by ComputerName, Image',
        "sigma": (
            "title: Network Sniffer Launched\n"
            "logsource:\n  category: process_creation\ndetection:\n"
            "  selection:\n    Image|contains:\n      - 'tcpdump'\n      - 'wireshark'\n      - 'tshark'\n  condition: selection"
        ),
    },
    "MITM-DNS": {
        "ttp":      "T1557.002",
        "tactic":   "Collection",
        "name":     "ARP Cache Poisoning",
        "splunk":   'index=network sourcetype=arp\n| stats count by src_mac, src_ip\n| where count > 50',
        "sigma": (
            "title: ARP Poisoning Detected\n"
            "logsource:\n  category: network\ndetection:\n"
            "  selection:\n    arp_type: reply\n  condition: selection | count() > 50"
        ),
    },
    "MITM-Payload": {
        "ttp":      "T1557.001",
        "tactic":   "Collection",
        "name":     "LLMNR/NBT-NS Poisoning and SMB Relay",
        "splunk":   'index=network sourcetype=dns\n| stats count by src_ip, query\n| where count > 100',
        "sigma": (
            "title: Suspicious DNS Query Volume\n"
            "logsource:\n  category: dns\ndetection:\n"
            "  selection:\n    dns_type: query\n  condition: selection | count() > 100"
        ),
    },
    "Cloud-Ops": {
        "ttp":      "T1552.005",
        "tactic":   "Credential Access",
        "name":     "Cloud Instance Metadata API",
        "splunk":   'index=aws sourcetype=aws:cloudtrail\n| where EventName="GetSessionToken" OR dest_ip="169.254.169.254"\n| stats count by src_ip, EventName',
        "sigma": (
            "title: Suspicious Cloud Metadata Query\n"
            "logsource:\n  category: network\ndetection:\n"
            "  selection:\n    dest_ip: '169.254.169.254'\n  condition: selection"
        ),
    },
    "MSF-Engine": {
        "ttp":      "T1190",
        "tactic":   "Initial Access",
        "name":     "Exploit Public-Facing Application",
        "splunk":   'index=ids sourcetype=suricata\n| search alert.signature="*Metasploit*" OR alert.signature="*exploit*"\n| stats count by src_ip, dest_ip, alert.signature',
        "sigma": (
            "title: Remote Code Execution Payload Dropped\n"
            "logsource:\n  category: process_creation\ndetection:\n"
            "  selection:\n    ParentImage|endswith: 'w3wp.exe'\n    Image|endswith: 'cmd.exe'\n  condition: selection"
        ),
    },
    "PrivEsc-Looter": {
        "ttp":      "T1082",
        "tactic":   "Discovery",
        "name":     "System Information Discovery",
        "splunk":   'index=sysmon EventCode=1\n| where match(CommandLine, "whoami|uname|systeminfo|id")\n| stats count by ComputerName, CommandLine',
        "sigma": (
            "title: Automated PrivEsc Discovery Commands\n"
            "logsource:\n  category: process_creation\ndetection:\n"
            "  selection:\n    CommandLine|contains|all:\n      - 'whoami'\n      - '/priv'\n  condition: selection"
        ),
    },
    "Campaign-Scanner": {
        "ttp":      "T1595",
        "tactic":   "Reconnaissance",
        "name":     "Active Scanning",
        "splunk":   'index=network sourcetype=firewall\n| stats dc(dest_port) as port_count by src_ip\n| where port_count > 20',
        "sigma": (
            "title: Active Network Scanning Detected\n"
            "logsource:\n  category: firewall\ndetection:\n"
            "  selection:\n    action: deny\n  condition: selection | count(dest_port) > 20"
        ),
    },
    "Burp-Proxy": {
        "ttp":      "T1539",
        "tactic":   "Credential Access",
        "name":     "Steal Web Session Cookie",
        "splunk":   'index=web sourcetype=access_combined\n| search uri="/login" method=POST\n| stats count by clientip, uri',
        "sigma": (
            "title: Authentication Cookie Intercepted\n"
            "logsource:\n  category: webserver\ndetection:\n"
            "  selection:\n    http_method: POST\n    uri|contains: '/login'\n  condition: selection"
        ),
    },
    "AitM-Proxy": {
        "ttp":      "T1557",
        "tactic":   "Collection",
        "name":     "Adversary-in-the-Middle",
        "splunk":   'index=proxy sourcetype=proxy\n| stats count by src_ip, dest_host\n| where count > 200',
        "sigma": (
            "title: Reverse Proxy / AitM Activity\n"
            "logsource:\n  category: proxy\ndetection:\n"
            "  selection:\n    http_method: POST\n  condition: selection"
        ),
    },
}

# ── Keyword fallbacks for modules not in the static map ──────────────────────

KEYWORD_FALLBACKS: list[tuple[str, str]] = [
    ("ssh",      "T1021.004"),
    ("smb",      "T1021.002"),
    ("ftp",      "T1071.002"),
    ("rdp",      "T1021.001"),
    ("http",     "T1190"),
    ("scan",     "T1046"),
    ("cred",     "T1552"),
    ("hash",     "T1003"),
    ("spray",    "T1110.003"),
    ("inject",   "T1055"),
    ("persist",  "T1547"),
    ("dns",      "T1071.004"),
    ("wifi",     "T1465"),
    ("payload",  "T1059"),
]


def _best_effort_ttp(module_name: str) -> dict:
    """Return a partial mapping dict for modules not in MITRE_MAPPINGS."""
    m = module_name.lower()
    for keyword, ttp in KEYWORD_FALLBACKS:
        if keyword in m:
            return {
                "ttp":    ttp,
                "tactic": "Unknown",
                "name":   f"Inferred from keyword '{keyword}'",
                "splunk": f'index=* | search "{module_name}"',
                "sigma":  f"title: {module_name} Activity\ndetection:\n  selection:\n    module: '{module_name}'\n  condition: selection",
            }
    return {
        "ttp":    "T0000",
        "tactic": "Unknown",
        "name":   "Unmapped Technique",
        "splunk": f'index=* | search module="{module_name}"',
        "sigma":  f"title: {module_name} Activity\ndetection:\n  condition: selection",
    }


# ─────────────────────────────────────────────────────────────────────────────
#  ENGINE
# ─────────────────────────────────────────────────────────────────────────────

class PurpleTeamEngine:

    # ── MITRE report ──────────────────────────────────────────────

    def generate_mitre_report(self) -> dict[str, dict]:
        """
        Build the ATT&CK table from the DB.
        Returns a dict of { module_name: mapping_dict } for modules that were seen.
        """
        console.print("[*] Analyzing Mission Database for MITRE ATT&CK mappings...")
        raw_logs = db.get_all()

        if not raw_logs:
            console.print(
                "[yellow][!] Database is empty. Execute modules first.[/yellow]"
            )
            return {}

        # Collect unique modules seen
        seen: dict[str, dict] = {}
        for row in raw_logs:
            mod = str(row.get("module") or "").strip()
            if not mod or mod in seen:
                continue
            mapping = MITRE_MAPPINGS.get(mod) or _best_effort_ttp(mod)
            seen[mod] = mapping

        if not seen:
            console.print("[yellow][!] No recognizable modules in the database.[/yellow]")
            return {}

        # Terminal table
        table = Table(
            title="Davoid Emulation → MITRE ATT&CK Matrix",
            border_style="bold magenta",
            expand=True,
        )
        table.add_column("Module Executed",  style="cyan")
        table.add_column("MITRE ID",         style="bold red")
        table.add_column("Tactic",           style="yellow")
        table.add_column("Technique Name",   style="white")

        for mod, m in seen.items():
            table.add_row(mod, m["ttp"], m.get("tactic", "—"), m["name"])

        console.print(table)
        return seen

    # ── Detection rules ───────────────────────────────────────────

    def generate_detection_rules(self, active_modules: dict[str, dict]):
        if not active_modules:
            return

        console.print(
            Panel("Generating Defensive Telemetry (Blue Team Artifacts)", border_style="bold blue")
        )

        for mod, mapping in active_modules.items():
            console.print(
                f"\n[bold green]=== {mapping['name']} ({mapping['ttp']}) ===[/bold green]"
            )

            # Splunk SPL with syntax highlighting
            console.print("[bold cyan]Splunk SPL:[/bold cyan]")
            console.print(Syntax(mapping["splunk"], "text", theme="monokai", line_numbers=False))

            # Sigma rule with YAML highlighting
            console.print("\n[bold yellow]Sigma Rule:[/bold yellow]")
            console.print(Syntax(mapping["sigma"], "yaml", theme="monokai", line_numbers=False))

            console.print("─" * 60)

    # ── Markdown export ───────────────────────────────────────────

    def export_markdown(self, active_modules: dict[str, dict]) -> str | None:
        """Write a Markdown report and return the filename."""
        if not active_modules:
            return None

        lines = [
            "# Davoid Purple Team Report",
            f"\n**Generated:** {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n",
            "## MITRE ATT&CK Mapping\n",
            "| Module | MITRE ID | Tactic | Technique |",
            "|--------|----------|--------|-----------|",
        ]
        for mod, m in active_modules.items():
            lines.append(f"| {mod} | {m['ttp']} | {m.get('tactic','—')} | {m['name']} |")

        lines.append("\n## Detection Rules\n")
        for mod, m in active_modules.items():
            lines += [
                f"### {m['name']} ({m['ttp']})\n",
                "**Splunk SPL:**",
                f"```\n{m['splunk']}\n```\n",
                "**Sigma Rule:**",
                f"```yaml\n{m['sigma']}\n```\n",
                "---\n",
            ]

        fname = f"purple_team_{datetime.datetime.now().strftime('%Y%m%d_%H%M')}.md"
        try:
            with open(fname, "w", encoding="utf-8") as f:
                f.write("\n".join(lines))
            console.print(f"[bold green][+] Markdown report saved: {fname}[/bold green]")
            return fname
        except Exception as e:
            console.print(f"[red][!] Export failed: {e}[/red]")
            return None

    # ── ATT&CK Navigator export ───────────────────────────────────

    def export_navigator_layer(self, active_modules: dict[str, dict]) -> str | None:
        """
        Export an ATT&CK Navigator layer JSON.
        Import at https://mitre-attack.github.io/attack-navigator/
        """
        if not active_modules:
            return None

        techniques = []
        for mod, m in active_modules.items():
            ttp = m.get("ttp", "")
            if not ttp or ttp == "T0000":
                continue
            techniques.append({
                "techniqueID": ttp,
                "tactic":      m.get("tactic", "").lower().replace(" ", "-"),
                "color":       "#ff7b72",
                "comment":     f"Executed via {mod}",
                "enabled":     True,
                "score":       100,
            })

        layer = {
            "name":        "Davoid Campaign",
            "versions":    {"attack": "14", "navigator": "4.9", "layer": "4.5"},
            "domain":      "enterprise-attack",
            "description": f"Generated by Davoid on {datetime.datetime.now().isoformat()}",
            "techniques":  techniques,
            "gradient":    {"colors": ["#ff7b72", "#f0883e"], "minValue": 0, "maxValue": 100},
        }

        fname = f"navigator_layer_{datetime.datetime.now().strftime('%Y%m%d_%H%M')}.json"
        try:
            with open(fname, "w", encoding="utf-8") as f:
                json.dump(layer, f, indent=2)
            console.print(f"[bold green][+] ATT&CK Navigator layer saved: {fname}[/bold green]")
            console.print(
                "[dim]Import at: https://mitre-attack.github.io/attack-navigator/[/dim]"
            )
            return fname
        except Exception as e:
            console.print(f"[red][!] Navigator export failed: {e}[/red]")
            return None

    # ── Main menu ─────────────────────────────────────────────────

    def run(self):
        draw_header("Purple Team: Adversary Emulation & Detection")

        while True:
            choice = questionary.select(
                "Select Purple Team Operation:",
                choices=[
                    "1. Map Campaign to MITRE ATT&CK",
                    "2. Generate SIEM Detection Rules (Splunk / Sigma)",
                    "3. Export Markdown Report",
                    "4. Export ATT&CK Navigator Layer (JSON)",
                    "5. Full Run (Map + Rules + Export All)",
                    "Back",
                ],
                style=Q_STYLE,
            ).ask()

            if not choice or choice == "Back":
                break

            if "Map Campaign" in choice:
                self.generate_mitre_report()
                questionary.press_any_key_to_continue(style=Q_STYLE).ask()

            elif "SIEM" in choice:
                active = self.generate_mitre_report()
                self.generate_detection_rules(active)
                questionary.press_any_key_to_continue(style=Q_STYLE).ask()

            elif "Markdown" in choice:
                active = self.generate_mitre_report()
                self.export_markdown(active)
                questionary.press_any_key_to_continue(style=Q_STYLE).ask()

            elif "Navigator" in choice:
                active = self.generate_mitre_report()
                self.export_navigator_layer(active)
                questionary.press_any_key_to_continue(style=Q_STYLE).ask()

            elif "Full Run" in choice:
                active = self.generate_mitre_report()
                self.generate_detection_rules(active)
                self.export_markdown(active)
                self.export_navigator_layer(active)
                questionary.press_any_key_to_continue(style=Q_STYLE).ask()


def run_purple_team():
    PurpleTeamEngine().run()