"""
Logging configuration for AuditAgent.
"""

import logging
import sys
from typing import Optional


# Color codes for console output
class LogColors:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    PURPLE = "\033[95m"
    CYAN = "\033[96m"
    WHITE = "\033[97m"
    GRAY = "\033[90m"


class ColoredFormatter(logging.Formatter):
    """Custom formatter with colors for different log levels."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.colors = {
            logging.DEBUG: LogColors.GRAY,
            logging.INFO: LogColors.BLUE,
            logging.WARNING: LogColors.YELLOW,
            logging.ERROR: LogColors.RED,
            logging.CRITICAL: LogColors.RED + LogColors.BOLD,
        }

    def format(self, record):
        # Add color to the level name
        if record.levelno in self.colors:
            record.levelname = (
                f"{self.colors[record.levelno]}{record.levelname}{LogColors.RESET}"
            )

        return super().format(record)


def setup_logging(verbosity: int = 0, use_colors: bool = True) -> None:
    """
    Setup logging configuration based on verbosity level.

    Args:
        verbosity: Verbosity level (0-2)
            0: Only show essential messages (WARNING and above)
            1: Show DEBUG messages from AuditAgent modules (-v)
            2: Show all DEBUG messages including external libraries (-vv)
        use_colors: Whether to use colored output
    """
    # Determine log level based on verbosity
    if verbosity == 0:
        level = logging.WARNING
    elif verbosity >= 1:
        level = logging.DEBUG
    else:
        level = logging.WARNING

    # Create formatter
    if use_colors and sys.stderr.isatty():
        formatter = ColoredFormatter(
            fmt="%(levelname)s: %(message)s", datefmt="%H:%M:%S"
        )
    else:
        formatter = logging.Formatter(
            fmt="%(levelname)s: %(message)s", datefmt="%H:%M:%S"
        )

    # Setup root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(logging.DEBUG)

    # Remove existing handlers
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)

    # Create console handler
    console_handler = logging.StreamHandler(sys.stderr)
    console_handler.setLevel(level)
    console_handler.setFormatter(formatter)
    root_logger.addHandler(console_handler)

    # Configure specific loggers based on verbosity
    if verbosity <= 1:
        # For lower verbosity, suppress external library logs
        logging.getLogger("paramiko").setLevel(logging.WARNING)
        logging.getLogger("urllib3").setLevel(logging.WARNING)
        logging.getLogger("requests").setLevel(logging.WARNING)

        if verbosity == 0:
            # For default verbosity, only show audit_agent warnings
            logging.getLogger("audit_agent").setLevel(logging.WARNING)
        else:
            # For -v, show audit_agent debug logs but suppress external libraries
            logging.getLogger("audit_agent").setLevel(logging.DEBUG)
    else:
        # For -vv, show everything including external libraries
        root_logger.setLevel(logging.DEBUG)


def get_logger(name: str) -> logging.Logger:
    """
    Get a logger with the appropriate audit_agent prefix.

    Args:
        name: Module name (usually __name__)

    Returns:
        Configured logger instance
    """
    # Ensure the name starts with audit_agent
    if not name.startswith("audit_agent"):
        if name == "__main__":
            name = "audit_agent.cli"
        elif "." not in name:
            name = f"audit_agent.{name}"

    return logging.getLogger(name)


# Convenience functions for different log levels
def log_success(message: str, logger: Optional[logging.Logger] = None) -> None:
    """Log a success message."""
    if logger is None:
        logger = get_logger("audit_agent")
    logger.info(f"✓ {message}")


def log_error(message: str, logger: Optional[logging.Logger] = None) -> None:
    """Log an error message."""
    if logger is None:
        logger = get_logger("audit_agent")
    logger.error(f"✗ {message}")


def log_warning(message: str, logger: Optional[logging.Logger] = None) -> None:
    """Log a warning message."""
    if logger is None:
        logger = get_logger("audit_agent")
    logger.warning(f"⚠ {message}")


def log_info(message: str, logger: Optional[logging.Logger] = None) -> None:
    """Log an info message."""
    if logger is None:
        logger = get_logger("audit_agent")
    logger.info(message)


def log_debug(message: str, logger: Optional[logging.Logger] = None) -> None:
    """Log a debug message."""
    if logger is None:
        logger = get_logger("audit_agent")
    logger.debug(message)
