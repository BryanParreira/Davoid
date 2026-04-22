"""
core/config.py — Enterprise Configuration Management
Upgraded to use Pydantic for strict type validation and environment variable overrides.
Maintains backward compatibility with legacy `ctx` context manager.
"""

import os
import yaml
from typing import Optional
from pydantic import BaseModel, Field
from pydantic_settings import BaseSettings
from rich.console import Console

console = Console()
CONFIG_FILE = os.path.abspath(os.path.join(
    os.path.dirname(__file__), "..", "config.yaml"))

# --- Pydantic Data Models for Strict Validation ---


class NetworkConfig(BaseModel):
    lhost: str = Field(default="127.0.0.1", description="Attacker IP")
    lport: int = Field(default=4444, description="Default listener port")
    interface: str = Field(default="eth0", description="Network interface")


class AIConfig(BaseModel):
    model: str = Field(default="llama3", description="Ollama model name")
    base_url: str = Field(
        default="http://127.0.0.1:11434/api", description="Ollama API URL")
    timeout: int = Field(default=60, description="AI connection timeout")


class WordlistConfig(BaseModel):
    passwords: str = Field(default="/usr/share/wordlists/rockyou.txt")
    subdomains: str = Field(default="")


class APIKeys(BaseModel):
    virustotal: str = Field(default="")
    shodan: str = Field(default="")


class ReportingConfig(BaseModel):
    operator_name: str = Field(default="Red Team Operator")
    company_name: str = Field(default="Davoid Security")
    output_dir: str = Field(default="reports")


class DavoidConfig(BaseSettings):
    """Master Configuration Object"""
    network: NetworkConfig = NetworkConfig()
    ai: AIConfig = AIConfig()
    wordlists: WordlistConfig = WordlistConfig()
    api_keys: APIKeys = APIKeys()
    reporting: ReportingConfig = ReportingConfig()
    notifications_enabled: bool = True
    bruteforce_checkpoint: int = 100000


def _write_default():
    """Write the default config.yaml if it doesn't exist."""
    default_cfg = DavoidConfig().model_dump()
    try:
        with open(CONFIG_FILE, "w") as f:
            yaml.dump(default_cfg, f, default_flow_style=False, sort_keys=False)
        console.print(f"[dim][*] Default config created: {CONFIG_FILE}[/dim]")
    except Exception as e:
        console.print(
            f"[dim red][!] Could not write default config: {e}[/dim red]")


def load_config() -> dict:
    """
    Load config.yaml, validate via Pydantic, and apply to global context.
    Returns the raw dictionary for legacy support.
    """
    if not os.path.exists(CONFIG_FILE):
        _write_default()

    try:
        with open(CONFIG_FILE, "r") as f:
            raw_data = yaml.safe_load(f) or {}

        # Validate data using Pydantic
        validated_config = DavoidConfig(**raw_data)
    except Exception as e:
        console.print(f"[red][!] Config validation error: {e}[/red]")
        return {}

    # --- Apply to global context (Backward Compatibility) ---
    try:
        from core.context import ctx

        ctx.set("LHOST", validated_config.network.lhost)
        ctx.set("LPORT", str(validated_config.network.lport))
        ctx.set("INTERFACE", validated_config.network.interface)

        ctx.set("AI_MODEL", validated_config.ai.model)
        ctx.set("AI_URL", validated_config.ai.base_url)
        ctx.set("AI_TIMEOUT", str(validated_config.ai.timeout))

        ctx.set("WORDLIST", validated_config.wordlists.passwords)
        ctx.set("SUB_LIST", validated_config.wordlists.subdomains)

        ctx.set("VT_KEY", validated_config.api_keys.virustotal)
        ctx.set("SHODAN_KEY", validated_config.api_keys.shodan)

        ctx.set("OPERATOR", validated_config.reporting.operator_name)
        ctx.set("COMPANY", validated_config.reporting.company_name)
        ctx.set("REPORT_DIR", validated_config.reporting.output_dir)
        os.makedirs(validated_config.reporting.output_dir, exist_ok=True)

        ctx.set("NOTIFICATIONS",
                "1" if validated_config.notifications_enabled else "0")
        ctx.set("BF_CHECKPOINT", str(validated_config.bruteforce_checkpoint))

    except Exception as e:
        console.print(f"[dim red][!] Context injection error: {e}[/dim red]")

    return validated_config.model_dump()


def get(section: str, key: str, fallback=None):
    """Convenience helper for accessing raw config keys."""
    try:
        with open(CONFIG_FILE, "r") as f:
            config = yaml.safe_load(f) or {}
        return config.get(section, {}).get(key, fallback)
    except Exception:
        return fallback


def save(section: str, key: str, value):
    """Write a single value back to config.yaml safely."""
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
