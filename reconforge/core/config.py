"""Core configuration management for ReconForge."""

import os
from pathlib import Path
from typing import Optional

# Default port list for scanning (common service ports)
DEFAULT_PORTS = [21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 3306, 3389, 5432, 8080]

# Default timeout values (in seconds)
DEFAULT_CONNECT_TIMEOUT = 2
DEFAULT_BANNER_TIMEOUT = 2
DEFAULT_PING_TIMEOUT = 2

# Default number of worker threads
DEFAULT_WORKERS = 5

# Logging configuration
LOG_LEVEL = os.getenv("RECONFORGE_LOG_LEVEL", "INFO")
LOG_DIR = Path(os.getenv("RECONFORGE_LOG_DIR", "logs"))
LOG_FORMAT = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"

# Ensure log directory exists
LOG_DIR.mkdir(exist_ok=True)


def get_config() -> dict:
    """Get current configuration as a dictionary.
    
    Returns:
        dict: Current configuration values
    """
    return {
        "default_ports": DEFAULT_PORTS,
        "default_connect_timeout": DEFAULT_CONNECT_TIMEOUT,
        "default_banner_timeout": DEFAULT_BANNER_TIMEOUT,
        "default_ping_timeout": DEFAULT_PING_TIMEOUT,
        "default_workers": DEFAULT_WORKERS,
        "log_level": LOG_LEVEL,
        "log_dir": str(LOG_DIR),
    }
