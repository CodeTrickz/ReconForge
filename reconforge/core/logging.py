"""Logging configuration for ReconForge."""

import logging
import logging.handlers
from pathlib import Path

from reconforge.core.config import LOG_DIR, LOG_FORMAT, LOG_LEVEL


def setup_logging(log_level: str = LOG_LEVEL, console: bool = False) -> logging.Logger:
    """Set up logging for ReconForge.
    
    Args:
        log_level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        
    Returns:
        logging.Logger: Configured logger instance
    """
    logger = logging.getLogger("reconforge")
    logger.setLevel(log_level)
    
    # Remove existing handlers
    for handler in logger.handlers[:]:
        logger.removeHandler(handler)
    
    # Create formatter
    formatter = logging.Formatter(LOG_FORMAT)
    
    if console:
        console_handler = logging.StreamHandler()
        console_handler.setLevel(log_level)
        console_handler.setFormatter(formatter)
        logger.addHandler(console_handler)
    
    # File handler
    log_file = LOG_DIR / "reconforge.log"
    file_handler = logging.handlers.RotatingFileHandler(
        log_file,
        maxBytes=10485760,  # 10 MB
        backupCount=5
    )
    file_handler.setLevel(log_level)
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)
    
    logger.debug(f"Logging configured: level={log_level}, log_file={log_file}")
    
    return logger


def get_logger(name: str) -> logging.Logger:
    """Get or create a logger with the given name.
    
    Args:
        name: Logger name (typically __name__)
        
    Returns:
        logging.Logger: Logger instance
    """
    if name == "reconforge" or name.startswith("reconforge."):
        return logging.getLogger(name)
    return logging.getLogger(f"reconforge.{name}")
