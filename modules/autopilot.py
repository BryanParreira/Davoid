import time
import os
import threading
import questionary
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from core.ui import draw_header, Q_STYLE

# Import capabilities
from modules.scanner import ScannerEngine
from modules.web_recon import WebGhost
from modules.bruteforce import HashEngine # Placeholder for service brute force logic
from core.context import ctx

console = Console()

class AutoPilot:
    def __init__(self):
        self.targets = []
        self.vulnerabilities = []

    def scan_phase(self, subnet):
        """Phase 1: Discovery"""
        console.print(Panel(f"PHASE 1: ACQUIRING TARGETS ON {subnet}", style="bold cyan"))
        scanner = ScannerEngine()
        
        # We perform a stealth scan to populate active hosts
        # Note: In a real integration, we'd capture the return value of scanner.network_discovery()
        # For this Auto-Pilot, we will use a specialized discovery method
        active_hosts = []
        
        with Progress(SpinnerColumn(), TextColumn("[cyan]Scanning Sector..."), console=console) as p:
            task = p.add_task("scan", total=None)
            # Simulated discovery for the 'Auto-Pilot' logic flow using Scapy
            # (Re-using logic from ScannerEngine but streamlined for automation)
            from scapy.all import ARP, Ether, srp
            try:
                ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=subnet), timeout=2, verbose=False)
                for _, rcv in ans:
                    active_hosts.append(rcv.psrc)
            except:
                pass
            p.update(task, completed=100)
            
        console.print(f"[green][+] Found {len(active_hosts)} targets.[/green]")
        return active_hosts

    def enumeration_phase(self, target_ip):
        """Phase 2: Service Enumeration"""
        console.print(f"\n[bold yellow]PHASE 2: ANALYZING {target_ip}[/bold yellow]")
        scanner = ScannerEngine()
        
        # Fast port check for critical services
        critical_ports = {
            80: "HTTP",
            443: "HTTPS",
            22: "SSH",
            21: "FTP",
            445: "SMB",
            3306: "MySQL"
        }
        
        found_services = []
        for port, service in critical_ports.items():
            res = scanner.service_audit(target_ip, port)
            if res and "Open" in res or "2." in str(res): # Simple check if open
                console.print(f"   [green]-> Detected {service} on port {port}[/green]")
                found_services.append((port, service))
                
        return found_services

    def exploitation_decision(self, target, services):
        """Phase 3: Automated Action"""
        console.print(f"\n[bold red]PHASE 3: ENGAGING {target}[/bold red]")
        
        for port, service in services:
            if service == "HTTP" or service == "HTTPS":
                console.print(f"[dim][*] Triggering Web Ghost on port {port}...[/dim]")
                prefix = "https://" if port == 443 else "http://"
                url = f"{prefix}{target}"
                
                # Run Web Ghost automatically
                ghost = WebGhost(url, use_tor=False) # Tor off for speed in auto-mode
                ghost.run()
                
            elif service == "FTP" or service == "SSH":
                console.print(f"[dim][*] Flagged {service} for Brute Force Queue.[/dim]")
                # Here you would trigger a hydra-like module if implemented
                # For now, we log it as a high-value target
                self.vulnerabilities.append(f"{target}:{port} ({service}) - Ready for Brute Force")

    def run_mission(self):
        draw_header("AUTO-PILOT: HUNTER KILLER")
        
        target_subnet = questionary.text("Enter Mission Subnet (e.g. 192.168.1.0/24):", style=Q_STYLE).ask()
        if not target_subnet: return

        # 1. SCAN
        targets = self.scan_phase(target_subnet)
        
        if not targets:
            console.print("[red]No targets found. Mission Aborted.[/red]")
            return

        # 2. ENUMERATE & 3. ENGAGE
        for target in targets:
            services = self.enumeration_phase(target)
            if services:
                self.exploitation_decision(target, services)
            else:
                console.print(f"[dim]No critical vectors found on {target}.[/dim]")

        # 4. DEBRIEF
        console.print(Panel("MISSION COMPLETE. DEBRIEFING...", style="bold green"))
        if self.vulnerabilities:
            for v in self.vulnerabilities:
                console.print(f"[bold red][!] TARGET:[/bold red] {v}")
        else:
            console.print("[green]Network appears hardened. No auto-exploitable vectors found.[/green]")
            
        questionary.press_any_key_to_continue(style=Q_STYLE).ask()

def run_autopilot():
    bot = AutoPilot()
    bot.run_mission()