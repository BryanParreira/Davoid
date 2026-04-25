"""
modules/scope_manager.py — Engagement Scope Manager
Load and manage in-scope targets. Provides is_in_scope() guard used by
offensive modules to prevent out-of-scope attacks.
Scope is stored in scope.txt in the project root.
"""

import os
import ipaddress
import socket
import questionary
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from core.ui import draw_header, Q_STYLE

console = Console()

SCOPE_FILE = os.path.join(os.path.dirname(
    os.path.dirname(__file__)), "scope.txt")
_scope_cache: list = []


# ─────────────────────────────────────────────────────────────────────────────
#  SCOPE STORE
# ─────────────────────────────────────────────────────────────────────────────

def load_scope() -> list:
    """Load scope entries from scope.txt. Returns list of strings."""
    global _scope_cache
    if not os.path.exists(SCOPE_FILE):
        _scope_cache = []
        return []
    try:
        with open(SCOPE_FILE, "r") as f:
            entries = [
                line.strip()
                for line in f
                if line.strip() and not line.strip().startswith("#")
            ]
        _scope_cache = entries
        return entries
    except Exception as e:
        console.print(f"[yellow][!] Could not read scope file: {e}[/yellow]")
        return []


def save_scope(entries: list) -> None:
    """Save scope entries to scope.txt."""
    global _scope_cache
    try:
        with open(SCOPE_FILE, "w") as f:
            f.write("# Davoid Scope File\n")
            f.write("# One entry per line: IP, CIDR, or domain\n")
            f.write("# Lines starting with # are comments\n\n")
            for entry in entries:
                f.write(entry + "\n")
        _scope_cache = entries
        console.print(f"[green][+] Scope saved to {SCOPE_FILE}[/green]")
    except Exception as e:
        console.print(f"[red][!] Could not save scope: {e}[/red]")


def is_in_scope(target: str) -> bool:
    """
    Check if a target IP/domain is in scope.
    Returns True if scope is empty (no restrictions) or target matches an entry.
    """
    scope = _scope_cache or load_scope()
    if not scope:
        return True  # no scope = no restrictions

    # Resolve domain to IP if needed
    target_ip = None
    try:
        target_ip = ipaddress.ip_address(target)
    except ValueError:
        try:
            resolved = socket.gethostbyname(target)
            target_ip = ipaddress.ip_address(resolved)
        except Exception:
            pass

    for entry in scope:
        entry = entry.strip()
        if not entry:
            continue

        # Exact match (IP or domain)
        if entry.lower() == target.lower():
            return True

        # CIDR network check
        if "/" in entry and target_ip:
            try:
                network = ipaddress.ip_network(entry, strict=False)
                if target_ip in network:
                    return True
            except ValueError:
                pass

        # Domain wildcard (*.example.com matches sub.example.com)
        if entry.startswith("*."):
            base = entry[2:].lower()
            if target.lower().endswith("." + base):
                return True

        # Partial IP network (e.g., 192.168.1 matches 192.168.1.*)
        if target.startswith(entry):
            return True

    return False


def check_scope_guard(target: str) -> bool:
    """
    Hard guard for offensive modules.
    Returns True if attack should proceed, False if out of scope.
    Prints a warning if out of scope.
    """
    scope = _scope_cache or load_scope()
    if not scope:
        return True  # no scope defined = unrestricted

    in_scope = is_in_scope(target)
    if not in_scope:
        console.print(Panel(
            f"[bold red]⚠ OUT OF SCOPE: {target}[/bold red]\n\n"
            f"[white]This target is not in your defined scope.[/white]\n"
            f"[dim]Edit scope.txt or use the Scope Manager to add it.[/dim]",
            border_style="red", title="SCOPE VIOLATION"
        ))
    return in_scope


# ─────────────────────────────────────────────────────────────────────────────
#  SCOPE MANAGER UI
# ─────────────────────────────────────────────────────────────────────────────

def run_scope_manager():
    while True:
        os.system('cls' if os.name == 'nt' else 'clear')
        draw_header("Engagement Scope Manager")

        entries = load_scope()

        if entries:
            table = Table(title=f"In-Scope Targets ({len(entries)})",
                          border_style="green", expand=True)
            table.add_column("#",      style="dim",   justify="right")
            table.add_column("Entry",  style="cyan")
            table.add_column("Type",   style="white")

            for i, entry in enumerate(entries, 1):
                if "/" in entry:
                    etype = "CIDR Network"
                elif entry.startswith("*."):
                    etype = "Wildcard Domain"
                else:
                    try:
                        ipaddress.ip_address(entry)
                        etype = "Single IP"
                    except ValueError:
                        etype = "Domain"
                table.add_row(str(i), entry, etype)

            console.print(table)
        else:
            console.print(Panel(
                "[yellow]No scope defined.[/yellow]\n\n"
                "[dim]Without a scope, all targets are allowed.\n"
                "Define a scope to enforce engagement boundaries.[/dim]",
                border_style="yellow"
            ))

        console.print()
        choice = questionary.select(
            "Scope Options:",
            choices=[
                questionary.Choice("Add target(s) to scope",     value="add"),
                questionary.Choice(
                    "Load from targets.txt file",  value="load"),
                questionary.Choice("Remove an entry",
                                   value="remove"),
                questionary.Choice("Clear all scope",
                                   value="clear"),
                questionary.Choice(
                    "Test a target against scope", value="test"),
                questionary.Separator(
                    "─────────────────────────────────────────"),
                questionary.Choice("Return to Main Menu",        value="back"),
            ],
            style=Q_STYLE
        ).ask()

        if not choice or choice == "back":
            break

        elif choice == "add":
            console.print(
                "[dim]Enter targets one per line. Supports IPs, CIDRs (192.168.1.0/24), domains.[/dim]")
            while True:
                entry = questionary.text(
                    f"Target #{len(entries)+1} (blank = done):",
                    style=Q_STYLE
                ).ask()
                if not entry or not entry.strip():
                    break
                entries.append(entry.strip())
            save_scope(entries)

        elif choice == "load":
            path = questionary.text(
                "Path to targets file (one per line):",
                style=Q_STYLE
            ).ask()
            if path and os.path.exists(path):
                with open(path, "r") as f:
                    new_entries = [
                        line.strip() for line in f
                        if line.strip() and not line.strip().startswith("#")
                    ]
                entries.extend(new_entries)
                # Deduplicate
                entries = list(dict.fromkeys(entries))
                save_scope(entries)
                console.print(
                    f"[green][+] Loaded {len(new_entries)} entries.[/green]")
            else:
                console.print("[red][!] File not found.[/red]")
            questionary.press_any_key_to_continue(style=Q_STYLE).ask()

        elif choice == "remove":
            if not entries:
                console.print("[yellow]Scope is empty.[/yellow]")
                questionary.press_any_key_to_continue(style=Q_STYLE).ask()
                continue

            choices = [questionary.Choice(f"{i+1}. {e}", value=i)
                       for i, e in enumerate(entries)]
            idx = questionary.select(
                "Select entry to remove:", choices=choices, style=Q_STYLE).ask()
            if idx is not None:
                removed = entries.pop(idx)
                save_scope(entries)
                console.print(f"[green][+] Removed: {removed}[/green]")
            questionary.press_any_key_to_continue(style=Q_STYLE).ask()

        elif choice == "clear":
            if questionary.confirm(
                "Clear all scope entries? (will allow all targets)", default=False, style=Q_STYLE
            ).ask():
                save_scope([])
                entries = []
                console.print("[green][+] Scope cleared.[/green]")
            questionary.press_any_key_to_continue(style=Q_STYLE).ask()

        elif choice == "test":
            target = questionary.text("Target to test:", style=Q_STYLE).ask()
            if target:
                result = is_in_scope(target.strip())
                if result:
                    console.print(
                        f"[bold green][+] {target} — IN SCOPE[/bold green]")
                else:
                    console.print(
                        f"[bold red][!] {target} — OUT OF SCOPE[/bold red]")
            questionary.press_any_key_to_continue(style=Q_STYLE).ask()


if __name__ == "__main__":
    run_scope_manager()
