# --- Davoid Core: Global Context Engine ---
import os


class Context:
    def __init__(self):
        self.vars = {
            "LHOST": "127.0.0.1",
            "LPORT": "4444",
            "RHOST": "",
            "INTERFACE": "eth0",
            "DOMAIN": "",
            "STEALTH": "OFF",
            "THREADS": "40"
        }
        self.selected_module = None

    def set(self, key, value):
        key = key.upper().strip()
        # Allows setting any variable, even if not in the default list
        self.vars[key] = value
        return True

    def get(self, key):
        return self.vars.get(key.upper(), "")

    def show_options(self):
        """Returns the current state of variables for the UI."""
        return self.vars


ctx = Context()
