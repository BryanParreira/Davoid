import socket
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
from scapy.all import ARP, Ether, srp, IP, sr1
from core.ui import draw_header
from core.context import ctx  # Import context

console = Console()


def get_os_guess(ip):
    """TTL-based OS fingerprinting."""
    try:
        pkt = sr1(IP(dst=ip), timeout=1, verbose=0)
        if pkt:
            ttl = pkt.getlayer(IP).ttl
            if ttl <= 64:
                return "Linux/Unix"
            if ttl <= 128:
                return "Windows"
    except:
        pass
    return "Unknown"


def auto_cve_check(ip, port):
    """Smater Banner Grabbing."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1.0)
            if s.connect_ex((ip, port)) == 0:
                s.send(b"HEAD / HTTP/1.1\r\n\r\n")
                banner = s.recv(1024).decode().strip()
                # Advanced matching
                vulns = {"vsFTPd 2.3.4": "CVE-2011-2523",
                         "Apache/2.4.49": "CVE-2021-41773"}
                for sig, cve in vulns.items():
                    if sig in banner:
                        return f"[bold red]{cve}[/bold red]"
                return f"Port {port} Open"
    except:
        pass
    return None


def network_discovery():
    draw_header("Root Discovery & Vuln-Hunter")

    # Use RHOST from context if available, otherwise auto-detect
    target_range = ctx.get("RHOST")
    if not target_range:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            target_range = ".".join(
                s.getsockname()[0].split('.')[:-1]) + ".0/24"
            s.close()
        except:
            target_range = "192.168.1.0/24"

    ip_range = console.input(
        f"[bold yellow]IP Range (Default {target_range}): [/bold yellow]") or target_range
    do_vuln = console.input(
        "[bold cyan]Deep Port Scan/Vuln Check? (y/N): [/bold cyan]").lower() == 'y'

    try:
        packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip_range)
        table = Table(
            title=f"Network Intel: {ip_range}", border_style="bold red")
        table.add_column("IP", style="cyan")
        table.add_column("OS Guess", style="white")
        table.add_column("Status/CVE", style="bold yellow")
        table.add_column("MAC", style="magenta")

        with Progress(SpinnerColumn(), TextColumn("{task.description}"), console=console) as progress:
            task = progress.add_task("[cyan]Scanning Network...", total=None)
            ans, _ = srp(packet, timeout=2, verbose=False)

            for _, rcv in ans:
                ip, mac = rcv.psrc, rcv.hwsrc
                progress.update(task, description=f"[yellow]Analyzing {ip}...")

                os_type = get_os_guess(ip)
                vuln_info = "Active"
                if do_vuln:
                    # Check critical ports
                    for p in [21, 22, 80, 443, 445]:
                        res = auto_cve_check(ip, p)
                        if "CVE" in str(res):
                            vuln_info = res
                            break

                table.add_row(ip, os_type, vuln_info, mac)

        console.print(table)
    except Exception as e:
        console.print(f"[red]Error:[/red] {e}")
    input("\nPress Enter to return...")
