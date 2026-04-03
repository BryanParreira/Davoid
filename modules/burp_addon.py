import re
import urllib.parse
from mitmproxy import http
from core.database import db


class DavoidInterceptor:
    def __init__(self):
        self.sensitive_params = [b"password", b"passwd",
                                 b"pwd", b"token", b"api_key", b"secret", b"auth"]

    def request(self, flow: http.HTTPFlow):
        req = flow.request
        target = req.pretty_host

        if req.method == "POST" and req.content:
            content = req.content.lower()
            if any(param in content for param in self.sensitive_params):
                try:
                    payload = req.content.decode('utf-8', errors='ignore')
                    db.log(
                        module="Burp-Proxy",
                        target=target,
                        data=f"Intercepted Sensitive POST Request to {req.path}:\n{payload[:500]}",
                        severity="CRITICAL"
                    )
                except Exception:
                    pass

    def response(self, flow: http.HTTPFlow):
        res = flow.response
        target = flow.request.pretty_host

        if "set-cookie" in res.headers:
            cookie_data = res.headers["set-cookie"].lower()
            if any(x in cookie_data for x in ["sessionid", "auth", "token"]):
                db.log(
                    module="Burp-Proxy",
                    target=target,
                    data=f"Server assigned Auth Cookie:\n{res.headers['set-cookie']}",
                    severity="HIGH"
                )


addons = [DavoidInterceptor()]
