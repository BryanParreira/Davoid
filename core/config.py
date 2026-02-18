import yaml
import os
from rich.console import Console

console = Console()
CONFIG_FILE = "config.yaml"


def load_config():
    """Loads the global configuration file."""
    if not os.path.exists(CONFIG_FILE):
        return None

    try:
        with open(CONFIG_FILE, 'r') as f:
            config = yaml.safe_load(f)
            return config
    except Exception as e:
        console.print(f"[red][!] Config Load Error: {e}[/red]")
        return None
