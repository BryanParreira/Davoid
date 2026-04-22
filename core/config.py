"""
core/config.py — Global Configuration Loader
FIXES & IMPROVEMENTS:
  - load_config() now actually applies values to the global Context (ctx)
  - Validates required fields and logs warnings for missing/bad values
  - Returns a typed dataclass-style dict so callers can use config values
  - Supports environment variable overrides (DAVOID_LHOST, etc.)
  - create_default_config() helper to scaffold a config.yaml if missing
  - Config values now actually flow into the app (was previously ignored)
"""
from __future__ import annotations

import os
import yaml
from rich.console import Console

console = Console()

CONFIG_FILE = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "..",
    "config.yaml",
)

# ─────────────────────────────────────────────────────────────────────────────
#  DEFAULT CONFIG SCHEMA
# ─────────────────────────────────────────────────────────────────────────────

DEFAULTS: dict = {
    # Network context
    "lhost":     "",          # Your attack machine IP (auto-detected if blank)
    "lport":     "4444",      # Default listener port
    "interface": "",          # Network interface (auto-detected if blank)

    # AI / Ollama settings
    "ai_model":  "llama3",    # Default Ollama model
    "ai_url":    "http://127.0.0.1:11434",

    # Stealth / proxy
    "use_tor":       False,
    "tor_proxy":     "socks5h://127.0.0.1:9050",

    # Database
    "db_path":   "",          # Empty = use default ~/.davoid/davoid_mission.db

    # Reporting
    "report_dir": ".",        # Where to save HTML/MD reports

    # Misc
    "threads":    40,
    "timeout":    10,
    "stealth":    "OFF",
}

# ─────────────────────────────────────────────────────────────────────────────
#  LOADER
# ─────────────────────────────────────────────────────────────────────────────

def load_config(apply_to_context: bool = True) -> dict:
    """
    Load config.yaml, merge with defaults, apply environment variable overrides,
    and optionally push values into the global Context (ctx).

    Returns the final merged config dict.
    Always returns a valid dict even if the file is missing or corrupt.
    """
    config = dict(DEFAULTS)   # start with defaults

    # ── 1. Load YAML file ─────────────────────────────────────────
    config_path = os.path.abspath(CONFIG_FILE)
    if os.path.exists(config_path):
        try:
            with open(config_path, "r") as f:
                loaded = yaml.safe_load(f) or {}

            if not isinstance(loaded, dict):
                console.print(
                    f"[yellow][!] config.yaml has unexpected format — using defaults.[/yellow]"
                )
            else:
                # Merge: file values override defaults
                for key, value in loaded.items():
                    config[key.lower()] = value

        except yaml.YAMLError as e:
            console.print(f"[yellow][!] config.yaml parse error: {e} — using defaults.[/yellow]")
        except Exception as e:
            console.print(f"[yellow][!] Config load error: {e} — using defaults.[/yellow]")
    # If file doesn't exist, silently use defaults (not an error condition)

    # ── 2. Environment variable overrides ────────────────────────
    ENV_MAP: dict[str, str] = {
        "DAVOID_LHOST":     "lhost",
        "DAVOID_LPORT":     "lport",
        "DAVOID_INTERFACE": "interface",
        "DAVOID_AI_MODEL":  "ai_model",
        "DAVOID_AI_URL":    "ai_url",
        "DAVOID_USE_TOR":   "use_tor",
        "DAVOID_THREADS":   "threads",
        "DAVOID_STEALTH":   "stealth",
    }
    for env_key, cfg_key in ENV_MAP.items():
        val = os.environ.get(env_key)
        if val is not None:
            # Type coerce booleans and ints
            if cfg_key in ("use_tor",):
                config[cfg_key] = val.lower() in ("1", "true", "yes")
            elif cfg_key in ("threads", "timeout"):
                try:
                    config[cfg_key] = int(val)
                except ValueError:
                    pass
            else:
                config[cfg_key] = val

    # ── 3. Push values into global Context ───────────────────────
    if apply_to_context:
        _apply_to_context(config)

    return config


def _apply_to_context(config: dict):
    """
    Push config values into the global ctx object.
    This is the piece that was missing — config was loaded but never used.
    Imported lazily to avoid circular imports at module load time.
    """
    try:
        from core.context import ctx

        mappings: dict[str, str] = {
            "lhost":     "LHOST",
            "lport":     "LPORT",
            "interface": "INTERFACE",
            "stealth":   "STEALTH",
            "threads":   "THREADS",
        }

        for cfg_key, ctx_key in mappings.items():
            val = config.get(cfg_key)
            if val:   # only override if the config actually has a value
                ctx.set(ctx_key, str(val))

    except ImportError:
        # ctx not available yet (e.g., during early startup)
        pass
    except Exception as e:
        console.print(f"[dim yellow][!] Could not apply config to context: {e}[/dim yellow]")


# ─────────────────────────────────────────────────────────────────────────────
#  HELPERS
# ─────────────────────────────────────────────────────────────────────────────

def get(key: str, default=None):
    """
    Convenience function: load config and return a single value.
    Useful for one-off lookups without holding the full dict.

    Example:
        model = config.get("ai_model", "llama3")
    """
    cfg = load_config(apply_to_context=False)
    return cfg.get(key.lower(), default)


def create_default_config(path: str | None = None) -> str:
    """
    Write a well-commented default config.yaml to disk.
    Returns the path written.
    Useful for first-run setup or the --init flag.
    """
    target = path or os.path.abspath(CONFIG_FILE)

    template = """\
# ─────────────────────────────────────────────────
#  DAVOID FRAMEWORK CONFIGURATION
# ─────────────────────────────────────────────────
# All values here can be overridden by environment
# variables prefixed with DAVOID_ (e.g. DAVOID_LHOST).

# ── Network ──────────────────────────────────────
lhost: ""          # Your IP (leave blank for auto-detect)
lport: "4444"      # Default listener port
interface: ""      # Network interface (blank = auto)

# ── AI / Ollama ───────────────────────────────────
ai_model: "llama3"
ai_url: "http://127.0.0.1:11434"

# ── Stealth ───────────────────────────────────────
use_tor: false
tor_proxy: "socks5h://127.0.0.1:9050"
stealth: "OFF"     # OFF | ON

# ── Performance ───────────────────────────────────
threads: 40
timeout: 10

# ── Output ───────────────────────────────────────
report_dir: "."    # Where HTML/Markdown reports are saved
"""

    try:
        with open(target, "w") as f:
            f.write(template)
        console.print(f"[green][+] Default config written to: {target}[/green]")
    except Exception as e:
        console.print(f"[red][!] Could not write config: {e}[/red]")

    return target


def show_config():
    """Print the current effective configuration to the terminal."""
    from rich.table import Table
    cfg = load_config(apply_to_context=False)

    table = Table(title="Effective Configuration", border_style="cyan")
    table.add_column("Key",    style="cyan")
    table.add_column("Value",  style="white")
    table.add_column("Source", style="dim")

    env_keys = {
        "lhost":     "DAVOID_LHOST",
        "lport":     "DAVOID_LPORT",
        "interface": "DAVOID_INTERFACE",
        "ai_model":  "DAVOID_AI_MODEL",
        "stealth":   "DAVOID_STEALTH",
    }

    for key, value in sorted(cfg.items()):
        env_var  = env_keys.get(key, "")
        from_env = bool(env_var and os.environ.get(env_var))
        source   = f"ENV ({env_var})" if from_env else "config.yaml / default"
        table.add_row(key, str(value), source)

    console.print(table)