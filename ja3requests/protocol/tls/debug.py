"""
ja3requests.protocol.tls.debug
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Logging utilities for TLS implementation.
Uses Python's standard logging module with backward-compatible JA3_DEBUG env var.
"""

import logging
import os

# Module-level loggers
logger = logging.getLogger("ja3requests")
tls_logger = logging.getLogger("ja3requests.tls")
h2_logger = logging.getLogger("ja3requests.h2")

# Backward compat: JA3_DEBUG env var sets logging level
_debug_env = int(os.environ.get('JA3_DEBUG', '0'))
if _debug_env >= 2:
    logging.basicConfig(level=logging.DEBUG, format="%(name)s [%(levelname)s] %(message)s")
    tls_logger.setLevel(logging.DEBUG)
elif _debug_env >= 1:
    logging.basicConfig(level=logging.DEBUG, format="%(name)s [%(levelname)s] %(message)s")
    tls_logger.setLevel(logging.DEBUG)


def set_debug_level(level: int):
    """Set debug level programmatically (backward compat)."""
    if level >= 2:
        tls_logger.setLevel(logging.DEBUG)
    elif level >= 1:
        tls_logger.setLevel(logging.DEBUG)
    else:
        tls_logger.setLevel(logging.WARNING)


def get_debug_level() -> int:
    """Get current debug level (backward compat)."""
    if tls_logger.isEnabledFor(logging.DEBUG):
        return 2
    return 0


def debug(msg: str, level: int = 1):
    """Log a debug message. level=1 → DEBUG, level=2 → DEBUG (verbose)."""
    tls_logger.debug(msg)


def debug_hex(label: str, data: bytes, level: int = 2, max_len: int = 50):
    """Log hex dump of data."""
    hex_str = data[:max_len].hex()
    if len(data) > max_len:
        hex_str += "..."
    tls_logger.debug("%s: %s", label, hex_str)
