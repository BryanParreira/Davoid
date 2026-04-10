"""
burp_proxy.py — Web Interception Proxy with Full HTTPS MITM
Zero external dependencies beyond what Davoid already uses (cryptography).

How HTTPS interception works:
  1. On first run a local CA cert+key is generated and saved to ~/.davoid/
  2. When a browser sends CONNECT host:443, we intercept it
  3. We generate a fake cert for that host signed by our CA on-the-fly
  4. The browser gets our fake cert; we connect to the real server with real TLS
  5. We sit in the middle reading everything in plain text
  6. User must install the CA cert in their browser/OS once (instructions shown on launch)
"""

import os
import ssl
import json
import socket
import select
import datetime
import ipaddress
import threading
import urllib.request
import urllib.parse
import urllib.error
import http.server
import http.client
import questionary
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from core.ui import draw_header, Q_STYLE
from core.database import db

# cryptography is already in requirements.txt
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

console = Console()

# ── Paths ─────────────────────────────────────────────────────────────────────
STATE_DIR      = os.path.join(os.path.expanduser("~"), ".davoid")
CA_KEY_PATH    = os.path.join(STATE_DIR, "davoid_ca.key")
CA_CERT_PATH   = os.path.join(STATE_DIR, "davoid_ca.crt")
CERT_CACHE_DIR = os.path.join(STATE_DIR, "cert_cache")

os.makedirs(STATE_DIR, exist_ok=True)
os.makedirs(CERT_CACHE_DIR, exist_ok=True)

# ── Shared state ──────────────────────────────────────────────────────────────
captured_requests = []
capture_lock      = threading.Lock()

SENSITIVE_KEYS = [
    "password", "passwd", "pwd", "token", "api_key",
    "secret", "auth", "access_token", "client_secret", "pass",
]


# ══════════════════════════════════════════════════════════════════════════════
#  CERTIFICATE AUTHORITY ENGINE
# ══════════════════════════════════════════════════════════════════════════════

def _generate_ca():
    key = rsa.generate_private_key(
        public_exponent=65537, key_size=2048, backend=default_backend())
    name = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME,       "Davoid Proxy CA"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Davoid Security"),
        x509.NameAttribute(NameOID.COUNTRY_NAME,      "US"),
    ])
    now  = datetime.datetime.utcnow()
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .sign(key, hashes.SHA256(), default_backend())
    )
    return key, cert


def load_or_create_ca():
    if os.path.exists(CA_KEY_PATH) and os.path.exists(CA_CERT_PATH):
        with open(CA_KEY_PATH, "rb") as f:
            ca_key = serialization.load_pem_private_key(
                f.read(), password=None, backend=default_backend())
        with open(CA_CERT_PATH, "rb") as f:
            ca_cert = x509.load_pem_x509_certificate(f.read(), default_backend())
        return ca_key, ca_cert

    console.print("[*] Generating Davoid CA certificate (first-time setup)...")
    ca_key, ca_cert = _generate_ca()

    with open(CA_KEY_PATH, "wb") as f:
        f.write(ca_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption()))
    with open(CA_CERT_PATH, "wb") as f:
        f.write(ca_cert.public_bytes(serialization.Encoding.PEM))
    os.chmod(CA_KEY_PATH, 0o600)
    console.print(f"[bold green][+] CA cert saved to {CA_CERT_PATH}[/bold green]")
    return ca_key, ca_cert


def generate_host_cert(hostname: str, ca_key, ca_cert):
    safe   = hostname.replace("*", "wildcard").replace(":", "_")
    k_path = os.path.join(CERT_CACHE_DIR, f"{safe}.key")
    c_path = os.path.join(CERT_CACHE_DIR, f"{safe}.crt")

    if os.path.exists(k_path) and os.path.exists(c_path):
        return k_path, c_path

    key = rsa.generate_private_key(
        public_exponent=65537, key_size=2048, backend=default_backend())

    san_list = []
    try:
        san_list.append(x509.IPAddress(ipaddress.ip_address(hostname)))
    except ValueError:
        san_list.append(x509.DNSName(hostname))
        parts = hostname.split(".")
        if len(parts) > 2:
            san_list.append(x509.DNSName("*." + ".".join(parts[1:])))

    now  = datetime.datetime.utcnow()
    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, hostname)]))
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=365))
        .add_extension(x509.SubjectAlternativeName(san_list), critical=False)
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),
            critical=False)
        .sign(ca_key, hashes.SHA256(), default_backend())
    )

    with open(k_path, "wb") as f:
        f.write(key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption()))
    with open(c_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    return k_path, c_path


# ══════════════════════════════════════════════════════════════════════════════
#  CREDENTIAL EXTRACTION
# ══════════════════════════════════════════════════════════════════════════════

def _walk_json(obj, out: list):
    if isinstance(obj, dict):
        for k, v in obj.items():
            if any(s in k.lower() for s in SENSITIVE_KEYS) and isinstance(v, (str, int, float, bool)):
                out.append(f"{k}: {v}")
            else:
                _walk_json(v, out)
    elif isinstance(obj, list):
        for item in obj:
            _walk_json(item, out)


def _extract_creds(body_str: str, content_type: str) -> list:
    found = []
    try:
        if "application/json" in content_type:
            _walk_json(json.loads(body_str), found)
        else:
            for k, v in urllib.parse.parse_qs(body_str).items():
                if any(s in k.lower() for s in SENSITIVE_KEYS):
                    found.append(f"{k}: {v[0]}")
    except Exception:
        pass
    return found


def _log_capture(method, url, status, src):
    with capture_lock:
        captured_requests.append(
            {"method": method, "url": url, "status": status, "src": src})
        if len(captured_requests) > 500:
            captured_requests.pop(0)


# ══════════════════════════════════════════════════════════════════════════════
#  PROXY HANDLER
# ══════════════════════════════════════════════════════════════════════════════

class ProxyHandler(http.server.BaseHTTPRequestHandler):

    ca_key  = None   # set by run_burp_proxy before server starts
    ca_cert = None

    def log_message(self, fmt, *args):
        pass

    # ── Plain HTTP forwarding ─────────────────────────────────────────────────
    def _forward(self, method: str, body: bytes = b"", scheme: str = "http"):
        url = self.path
        if not url.startswith("http"):
            host = self.headers.get("Host", "")
            url  = f"{scheme}://{host}{self.path}"

        auth = (self.headers.get("Authorization", "") or
                self.headers.get("X-API-Key", ""))
        if auth:
            console.print(
                f"\n[bold magenta][!] AUTH HEADER — {self.client_address[0]}[/bold magenta]\n"
                f"    [dim]{auth[:120]}[/dim]")
            db.log("Burp-Proxy", self.client_address[0],
                   f"Auth Header at {url}:\n{auth}", "CRITICAL")

        if method in ("POST", "PUT", "PATCH") and body:
            creds = _extract_creds(
                body.decode("utf-8", errors="ignore"),
                self.headers.get("Content-Type", ""))
            if creds:
                console.print(
                    f"\n[bold red][!] CREDENTIALS — {self.client_address[0]}[/bold red]")
                for c in creds:
                    console.print(f"    [yellow]{c}[/yellow]")
                db.log("Burp-Proxy", self.client_address[0],
                       f"Captured at {url}:\n" + "\n".join(creds), "CRITICAL")

        fwd_headers = {
            k: v for k, v in self.headers.items()
            if k.lower() not in {
                "proxy-connection", "connection", "keep-alive",
                "proxy-authenticate", "proxy-authorization",
                "te", "trailers", "transfer-encoding",
            }
        }

        try:
            parsed = urllib.parse.urlparse(url)
            host   = parsed.hostname
            port   = parsed.port or (443 if scheme == "https" else 80)
            path   = parsed.path or "/"
            if parsed.query:
                path += "?" + parsed.query

            if scheme == "https":
                ctx  = ssl.create_default_context()
                conn = http.client.HTTPSConnection(host, port, context=ctx, timeout=15)
            else:
                conn = http.client.HTTPConnection(host, port, timeout=15)

            conn.request(method, path, body=body or None, headers=fwd_headers)
            resp      = conn.getresponse()
            resp_body = resp.read()

            for name, value in resp.getheaders():
                if name.lower() == "set-cookie" and any(
                        x in value.lower() for x in ["session", "auth", "token", "jwt"]):
                    console.print(
                        f"\n[bold cyan][!] AUTH COOKIE — {self.client_address[0]}[/bold cyan]\n"
                        f"    [dim]{value.split(';')[0][:120]}[/dim]")
                    db.log("Burp-Proxy", self.client_address[0],
                           f"Cookie at {url}:\n{value.split(';')[0]}", "HIGH")

            _log_capture(method, url, resp.status, self.client_address[0])

            self.send_response(resp.status)
            skip = {"transfer-encoding", "connection", "keep-alive"}
            for name, value in resp.getheaders():
                if name.lower() not in skip:
                    self.send_header(name, value)
            self.end_headers()
            self.wfile.write(resp_body)
            conn.close()

        except Exception as e:
            try:
                self.send_response(502)
                self.end_headers()
                self.wfile.write(f"Proxy error: {e}".encode())
            except Exception:
                pass

    def do_GET(self):     self._forward("GET")
    def do_HEAD(self):    self._forward("HEAD")
    def do_DELETE(self):  self._forward("DELETE")
    def do_OPTIONS(self): self._forward("OPTIONS")

    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0))
        self._forward("POST", self.rfile.read(n) if n else b"")

    def do_PUT(self):
        n = int(self.headers.get("Content-Length", 0))
        self._forward("PUT", self.rfile.read(n) if n else b"")

    # ── HTTPS CONNECT — full MITM ─────────────────────────────────────────────
    def do_CONNECT(self):
        try:
            host, port_str = self.path.split(":", 1)
            port = int(port_str)
        except ValueError:
            self.send_error(400)
            return

        try:
            k_path, c_path = generate_host_cert(
                host, ProxyHandler.ca_key, ProxyHandler.ca_cert)
        except Exception as e:
            console.print(f"[dim red][!] Cert gen failed ({host}): {e}[/dim red]")
            self._blind_tunnel(host, port)
            return

        # Tell client we're ready to receive its TLS ClientHello
        self.send_response(200, "Connection Established")
        self.end_headers()

        # Wrap client socket with our fake host cert
        try:
            c_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            c_ctx.load_cert_chain(certfile=c_path, keyfile=k_path)
            client_ssl = c_ctx.wrap_socket(self.connection, server_side=True)
        except ssl.SSLError as e:
            console.print(f"[dim red][!] Client SSL wrap failed ({host}): {e}[/dim red]")
            return

        # Connect to real upstream with genuine TLS
        try:
            u_ctx      = ssl.create_default_context()
            u_raw      = socket.create_connection((host, port), timeout=10)
            upstream   = u_ctx.wrap_socket(u_raw, server_hostname=host)
        except Exception as e:
            console.print(f"[dim red][!] Upstream connect failed ({host}): {e}[/dim red]")
            try: client_ssl.close()
            except Exception: pass
            return

        threading.Thread(
            target=self._mitm_relay,
            args=(client_ssl, upstream, host),
            daemon=True,
        ).start()

    def _mitm_relay(self, client_ssl, upstream, host: str):
        try:
            # Read the decrypted HTTP request from the client
            raw = b""
            client_ssl.settimeout(10)
            try:
                while True:
                    chunk = client_ssl.recv(4096)
                    if not chunk:
                        break
                    raw += chunk
                    if b"\r\n\r\n" in raw:
                        break
            except socket.timeout:
                pass

            if not raw:
                return

            # Parse request line + headers
            try:
                header_raw, _, body = raw.partition(b"\r\n\r\n")
                first_line, _, rest = header_raw.partition(b"\r\n")
                parts  = first_line.decode("utf-8", errors="ignore").split()
                method = parts[0] if parts else "GET"
                path   = parts[1] if len(parts) > 1 else "/"
                url    = f"https://{host}{path}"

                hdrs = {}
                for line in rest.decode("utf-8", errors="ignore").splitlines():
                    if ":" in line:
                        k, _, v = line.partition(":")
                        hdrs[k.strip().lower()] = v.strip()

                # Read remaining body
                cl = int(hdrs.get("content-length", 0))
                while len(body) < cl:
                    try:
                        more = client_ssl.recv(4096)
                        if not more: break
                        body += more
                    except socket.timeout:
                        break

                # Auth header check
                auth = hdrs.get("authorization", "") or hdrs.get("x-api-key", "")
                if auth:
                    console.print(
                        f"\n[bold magenta][!] HTTPS AUTH HEADER — {host}[/bold magenta]\n"
                        f"    [dim]{auth[:120]}[/dim]")
                    db.log("Burp-Proxy", host, f"Auth Header at {url}:\n{auth}", "CRITICAL")

                # Credential check
                if method in ("POST", "PUT", "PATCH") and body:
                    creds = _extract_creds(
                        body.decode("utf-8", errors="ignore"),
                        hdrs.get("content-type", ""))
                    if creds:
                        console.print(
                            f"\n[bold red][!] HTTPS CREDENTIALS — {host}[/bold red]")
                        for c in creds:
                            console.print(f"    [yellow]{c}[/yellow]")
                        db.log("Burp-Proxy", host,
                               f"HTTPS capture at {url}:\n" + "\n".join(creds),
                               "CRITICAL")

                _log_capture(method, url, "HTTPS-intercepted", host)

            except Exception:
                pass

            # Forward request upstream and relay rest bidirectionally
            try:
                upstream.sendall(raw)
            except Exception:
                return

            self._relay(client_ssl, upstream)

        except Exception:
            pass
        finally:
            try: client_ssl.close()
            except Exception: pass
            try: upstream.close()
            except Exception: pass

    def _relay(self, a, b):
        sockets = [a, b]
        while True:
            try:
                r, _, e = select.select(sockets, [], sockets, 5)
                if e or not r:
                    break
                for s in r:
                    try:
                        data = s.recv(8192)
                    except Exception:
                        return
                    if not data:
                        return
                    try:
                        (b if s is a else a).sendall(data)
                    except Exception:
                        return
            except Exception:
                break

    def _blind_tunnel(self, host: str, port: int):
        try:
            remote = socket.create_connection((host, port), timeout=10)
        except Exception:
            return
        self._relay(self.connection, remote)
        try: remote.close()
        except Exception: pass


# ══════════════════════════════════════════════════════════════════════════════
#  LIVE TRAFFIC DISPLAY
# ══════════════════════════════════════════════════════════════════════════════

def _display_loop(stop_event: threading.Event):
    import time
    while not stop_event.is_set():
        time.sleep(8)
        with capture_lock:
            recent = list(captured_requests[-12:])
        if recent:
            t = Table(title="Intercepted Traffic", border_style="cyan", expand=False)
            t.add_column("Method", style="yellow",  width=7)
            t.add_column("Status", style="magenta", width=18)
            t.add_column("URL",    style="white",   max_width=70)
            for r in recent:
                t.add_row(r["method"], str(r["status"]), r["url"][:90])
            console.print(t)


# ══════════════════════════════════════════════════════════════════════════════
#  ENTRY POINT
# ══════════════════════════════════════════════════════════════════════════════

def is_port_in_use(port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        return s.connect_ex(("127.0.0.1", port)) == 0


def run_burp_proxy():
    draw_header("Web Interception Proxy (Full HTTPS MITM)")

    console.print("[dim]HTTP + HTTPS interception — zero external dependencies.[/dim]\n")

    try:
        ca_key, ca_cert = load_or_create_ca()
        ProxyHandler.ca_key  = ca_key
        ProxyHandler.ca_cert = ca_cert
    except Exception as e:
        console.print(f"[bold red][!] CA init failed: {e}[/bold red]")
        questionary.press_any_key_to_continue(style=Q_STYLE).ask()
        return

    port_str = questionary.text(
        "Listen Port (Default 8080):", default="8080", style=Q_STYLE).ask()
    if not port_str:
        return
    try:
        port = int(port_str)
    except ValueError:
        console.print("[red][!] Invalid port.[/red]")
        return

    if is_port_in_use(port):
        console.print(f"[bold red][!] Port {port} already in use.[/bold red]")
        questionary.press_any_key_to_continue(style=Q_STYLE).ask()
        return

    console.print(Panel(
        f"[bold green]Proxy active on 0.0.0.0:{port} (HTTP + HTTPS)[/bold green]\n\n"
        "[white]Step 1 — Set your browser/device proxy:[/white]\n"
        f"         [bold cyan]<YOUR_IP>:{port}[/bold cyan]\n\n"
        "[white]Step 2 — Install the CA cert ONCE to intercept HTTPS:[/white]\n"
        f"         [bold yellow]{CA_CERT_PATH}[/bold yellow]\n"
        "  • Chrome  → Settings → Privacy → Manage Certs → Authorities → Import\n"
        "  • Firefox → Settings → Privacy → View Certs → Authorities → Import\n"
        "  • macOS   → Double-click .crt → Keychain → Trust Always\n"
        "  • curl    → --proxy http://127.0.0.1:8080 "
        f"--cacert {CA_CERT_PATH}\n\n"
        "[white]Step 3 — Browse normally. Everything is intercepted.[/white]\n\n"
        "[bold yellow]Ctrl+C[/bold yellow] to stop.",
        border_style="green",
        title="[bold white]PROXY ACTIVE[/bold white]"
    ))

    stop_event = threading.Event()
    threading.Thread(target=_display_loop, args=(stop_event,), daemon=True).start()

    try:
        server = http.server.ThreadingHTTPServer(("0.0.0.0", port), ProxyHandler)
        console.print(f"[bold green][+] Listening on port {port}...[/bold green]\n")
        server.serve_forever()
    except PermissionError:
        console.print("[bold red][!] Permission denied. Use sudo for ports < 1024.[/bold red]")
    except KeyboardInterrupt:
        console.print("\n[yellow][*] Proxy stopped.[/yellow]")
    finally:
        stop_event.set()

    questionary.press_any_key_to_continue(style=Q_STYLE).ask()


if __name__ == "__main__":
    run_burp_proxy()