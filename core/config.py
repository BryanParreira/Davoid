"""
core/config.py — Global Configuration Loader
Reads config.yaml and applies values to the global context (LHOST, LPORT,
wordlist paths, Ollama model, API keys, etc.) so users don't have to
retype them on every run.

If config.yaml doesn't exist, it is created with sensible defaults.
"""

import os
import yaml
from rich.console import Console

console   = Console()
CONFIG_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                           "..", "config.yaml")
CONFIG_FILE = os.path.abspath(CONFIG_FILE)

# ── Default config written on first run ───────────────────────────────────────
DEFAULT_CONFIG = {
    "network": {
        "lhost":      "127.0.0.1",   # Your attacker IP
        "lport":      4444,          # Default listener port
        "interface":  "eth0",        # Network interface
    },
    "ai": {
        "model":      "llama3",      # Default Ollama model
        "base_url":   "http://127.0.0.1:11434/api",
        "timeout":    60,            # Seconds before AI phase skipped in God Mode
    },
    "wordlists": {
        "passwords":  "/usr/share/wordlists/rockyou.txt",
        "subdomains": "",            # Optional custom subdomain list
    },
    "api_keys": {
        "virustotal": "",            # Free: https://www.virustotal.com
        "shodan":     "",            # Optional paid Shodan key
    },
    "reporting": {
        "operator_name":    "Red Team Operator",
        "company_name":     "Davoid Security",
        "output_dir":       "reports",
    },
    "notifications": {
        "enabled":    True,          # Desktop notifications for critical events
    },
    "bruteforce": {
        "checkpoint_interval": 100000,  # Save resume point every N words
    },
}


def _write_default():
    """Write the default config.yaml if it doesn't exist."""
    try:
        with open(CONFIG_FILE, "w") as f:
            yaml.dump(DEFAULT_CONFIG, f, default_flow_style=False, sort_keys=False)
        console.print(
            f"[dim][*] Default config created: {CONFIG_FILE}[/dim]")
    except Exception as e:
        console.print(f"[dim red][!] Could not write default config: {e}[/dim red]")


def load_config():
    """
    Load config.yaml, create it with defaults if missing, and apply all
    values to the global context so every module can read them.
    Returns the raw config dict (or empty dict on failure).
    """
    if not os.path.exists(CONFIG_FILE):
        _write_default()

    try:
        with open(CONFIG_FILE, "r") as f:
            config = yaml.safe_load(f) or {}
    except Exception as e:
        console.print(f"[red][!] Config load error: {e}[/red]")
        return {}

    # ── Apply to global context ───────────────────────────────────────────────
    try:
        from core.context import ctx

        net = config.get("network", {})
        if net.get("lhost"):
            ctx.set("LHOST",     str(net["lhost"]))
        if net.get("lport"):
            ctx.set("LPORT",     str(net["lport"]))
        if net.get("interface"):
            ctx.set("INTERFACE", str(net["interface"]))

        ai = config.get("ai", {})
        if ai.get("model"):
            ctx.set("AI_MODEL",   str(ai["model"]))
        if ai.get("base_url"):
            ctx.set("AI_URL",     str(ai["base_url"]))
        if ai.get("timeout"):
            ctx.set("AI_TIMEOUT", str(ai["timeout"]))

        wl = config.get("wordlists", {})
        if wl.get("passwords"):
            ctx.set("WORDLIST",   str(wl["passwords"]))
        if wl.get("subdomains"):
            ctx.set("SUB_LIST",   str(wl["subdomains"]))

        keys = config.get("api_keys", {})
        if keys.get("virustotal"):
            ctx.set("VT_KEY",     str(keys["virustotal"]))
        if keys.get("shodan"):
            ctx.set("SHODAN_KEY", str(keys["shodan"]))

        rep = config.get("reporting", {})
        if rep.get("operator_name"):
            ctx.set("OPERATOR",   str(rep["operator_name"]))
        if rep.get("company_name"):
            ctx.set("COMPANY",    str(rep["company_name"]))
        if rep.get("output_dir"):
            ctx.set("REPORT_DIR", str(rep["output_dir"]))
            os.makedirs(str(rep["output_dir"]), exist_ok=True)

        notif = config.get("notifications", {})
        ctx.set("NOTIFICATIONS", "1" if notif.get("enabled", True) else "0")

        bf = config.get("bruteforce", {})
        if bf.get("checkpoint_interval"):
            ctx.set("BF_CHECKPOINT", str(bf["checkpoint_interval"]))

    except Exception as e:
        console.print(f"[dim red][!] Config apply error: {e}[/dim red]")

    return config


def get(section: str, key: str, fallback=None):
    """
    Convenience helper — load config and return a single value.
    Usage:  from core.config import get
            vt_key = get("api_keys", "virustotal")
    """
    try:
        with open(CONFIG_FILE, "r") as f:
            config = yaml.safe_load(f) or {}
        return config.get(section, {}).get(key, fallback)
    except Exception:
        return fallback


def save(section: str, key: str, value):
    """
    Write a single value back to config.yaml.
    Usage:  from core.config import save
            save("api_keys", "virustotal", "abc123")
    """
    try:
        with open(CONFIG_FILE, "r") as f:
            config = yaml.safe_load(f) or {}
        if section not in config:
            config[section] = {}
        config[section][key] = value
        with open(CONFIG_FILE, "w") as f:
            yaml.dump(config, f, default_flow_style=False, sort_keys=False)
        return True
    except Exception as e:
        console.print(f"[red][!] Config save error: {e}[/red]")
        return False