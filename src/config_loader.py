"""
Configuration Loader
Loads and provides access to config/config.json
"""
import json
import os

_CONFIG = None
_CONFIG_PATH = os.path.join(os.path.dirname(__file__), '..', 'config', 'config.json')


def load_config(path=None):
    """Load configuration from JSON file."""
    global _CONFIG
    config_path = path or _CONFIG_PATH
    with open(os.path.abspath(config_path), 'r') as f:
        _CONFIG = json.load(f)
    return _CONFIG


def get_config():
    """Return cached config, loading it if necessary."""
    global _CONFIG
    if _CONFIG is None:
        load_config()
    return _CONFIG
