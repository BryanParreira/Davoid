"""
purple_team.py — Adversary Emulation & MITRE ATT&CK Mapper
"""

import os
import questionary
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from core.ui import draw_header, Q_STYLE
from core.database import db

console = Console()

# A mapping dictionary to translate Davoid actions into defensive telemetry
MITRE_MAPPINGS = {
    "Nmap-Engine": {
        "ttp": "T1046", "name": "Network Service Discovery",
        "splunk": 'index=network sourcetype=firewall action=allowed | stats count by src_ip, dest_port | where count > 100',
        "sigma": "title: High Volume Port Scan Detected\nlogsource:\n  category: firewall\ndetection:\n  condition: selection | count(dest_port) > 50"
    },
    "AD Engine": {
        "ttp": "T1558.004", "name": "AS-REP Roasting",
        "splunk": 'index=wineventlog EventCode=4768 TicketOptions=0x40810010',
        "sigma": "title: AS-REP Roasting (Event 4768)\ndetection:\n  selection:\n    EventID: 4768\n    TicketOptions: '0x40810010'"
    },
    "Live Interceptor": {
        "ttp": "T1040", "name": "Network Sniffing",
        "splunk": 'index=sysmon EventCode=1 (Image="*wireshark*" OR Image="*tcpdump*" OR Image="*tshark*")',
        "sigma": "title: Promiscuous Mode Interface / Sniffer\ndetection:\n  selection:\n    EventID: 1\n    Image|contains: 'tcpdump'"
    },
    "Cloud-Ops": {
        "ttp": "T1552.005", "name": "Cloud Instance Metadata API",
        "splunk": 'index=aws sourcetype=aws:cloudtrail EventName=GetSessionToken OR dest_ip="169.254.169.254"',
        "sigma": "title: Suspicious Cloud Metadata Query\ndetection:\n  selection:\n    dest_ip: '169.254.169.254'"
    },
    "MSF-Engine": {
        "ttp": "T1190", "name": "Exploit Public-Facing Application",
        "splunk": 'index=ids sourcetype=suricata alert.signature="*Metasploit*"',
        "sigma": "title: Remote Code Execution Payload Dropped\ndetection:\n  selection:\n    ParentImage|endswith: 'w3wp.exe'\n    Image|endswith: 'cmd.exe'"
    },
    "PrivEsc-Looter": {
        "ttp": "T1082", "name": "System Information Discovery",
        "splunk": 'index=sysmon EventCode=1 CommandLine="*whoami /priv*" OR CommandLine="*uname -a*"',
        "sigma": "title: Automated PrivEsc Discovery\ndetection:\n  selection:\n    CommandLine|contains|all:\n      - 'whoami'\n      - '/priv'"
    }
}


class PurpleTeamEngine:
    def _get_attr(self, obj, key):
        if isinstance(obj, dict):
            return obj.get(key, "")
        return getattr(obj, key, "")

    def generate_mitre_report(self):
        console.print(
            "[*] Analyzing Mission Database for MITRE ATT&CK Mappings...")
        raw_logs = db.get_all()

        if not raw_logs:
            return console.print("[yellow][!] Database empty. Execute attacks first to generate telemetry.[/yellow]")

        table = Table(title="Davoid Emulation -> MITRE ATT&CK Matrix",
                      border_style="bold magenta", expand=True)
        table.add_column("Module Executed", style="cyan")
        table.add_column("MITRE ID", style="bold red")
        table.add_column("Tactic/Technique", style="white")

        seen_modules = set()
        for row in raw_logs:
            mod = str(self._get_attr(row, "module") or "")
            if mod and mod not in seen_modules and mod in MITRE_MAPPINGS:
                seen_modules.add(mod)
                mapping = MITRE_MAPPINGS[mod]
                table.add_row(mod, mapping["ttp"], mapping["name"])

        console.print(table)
        return seen_modules

    def generate_detection_rules(self, active_modules):
        if not active_modules:
            return

        console.print(
            "\n" + Panel("Generating Defensive Telemetry (Blue Team Artifacts)", border_style="bold blue"))

        for mod in active_modules:
            mapping = MITRE_MAPPINGS.get(mod)
            if mapping:
                console.print(
                    f"\n[bold green]=== Detection Logic for {mapping['name']} ({mapping['ttp']}) ===[/bold green]")
                console.print(
                    f"[bold cyan]Splunk SPL:[/bold cyan]\n{mapping['splunk']}")
                console.print(
                    f"[bold yellow]Sigma Rule:[/bold yellow]\n{mapping['sigma']}")
                console.print("-" * 60)

    def run(self):
        draw_header("Purple Team: Adversary Emulation & Detection")

        choice = questionary.select(
            "Select Purple Team Operation:",
            choices=[
                "1. Map Database Campaign to MITRE ATT&CK",
                "2. Generate SIEM Detection Rules (Splunk/Sigma) for recent attacks",
                "Back"
            ],
            style=Q_STYLE
        ).ask()

        if not choice or choice == "Back":
            return

        if "Map" in choice:
            self.generate_mitre_report()
            questionary.press_any_key_to_continue(style=Q_STYLE).ask()
        elif "Generate" in choice:
            active = self.generate_mitre_report()
            self.generate_detection_rules(active)
            questionary.press_any_key_to_continue(style=Q_STYLE).ask()


def run_purple_team():
    PurpleTeamEngine().run()
