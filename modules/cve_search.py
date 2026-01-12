import requests
from rich.console import Console
from rich.table import Table

console = Console()

def lookup_cves(service_name):
    """
    Queries the Shodan CVEDB for known vulnerabilities based on service name.
    """
    if not service_name or service_name == "Unknown":
        return []

    try:
        # High-speed public vulnerability lookup
        # 
        url = f"https://cvedb.shodan.io/cves?query={service_name}&limit=5"
        response = requests.get(url, timeout=3)
        if response.status_code == 200:
            data = response.json()
            return data.get('matches', [])
    except:
        pass
    return []

def display_vulnerabilities(service, cves):
    """Renders a specialized table for vulnerability matches."""
    if not cves:
        return

    table = Table(title=f"Vulnerability Analysis: {service}", border_style="bold red")
    table.add_column("CVE ID", style="cyan")
    table.add_column("Score", style="bold yellow")
    table.add_column("Summary", style="white", overflow="fold")

    for entry in cves:
        cve_id = entry.get('id', 'N/A')
        summary = entry.get('summary', 'No description available.')[:100] + "..."
        score = str(entry.get('cvss', 'N/A'))
        table.add_row(cve_id, score, summary)

    console.print(table)