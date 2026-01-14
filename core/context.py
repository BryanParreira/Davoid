# --- Davoid Core: Global Context Engine ---
import os


class Context:
    def __init__(self):
        self.vars = {
            "LHOST": "127.0.0.1",
            "LPORT": "4444",
            "RHOST": "",
            "INTERFACE": "wlan0",
            "DOMAIN": ""
        }

    def set(self, key, value):
        key = key.upper()
        if key in self.vars:
            self.vars[key] = value
            return True
        return False

    def get(self, key):
        return self.vars.get(key.upper(), "")


ctx = Context()
