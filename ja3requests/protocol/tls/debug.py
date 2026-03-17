"""
ja3requests.protocol.tls.debug
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Debug logging utilities for TLS implementation.
"""

import os

# Debug level can be controlled via environment variable
# JA3_DEBUG=0 (off), JA3_DEBUG=1 (basic), JA3_DEBUG=2 (verbose)
_debug_level = int(os.environ.get('JA3_DEBUG', '0'))


def set_debug_level(level: int):
    """Set debug level programmatically"""
    global _debug_level  # pylint: disable=global-statement
    _debug_level = level


def get_debug_level() -> int:
    """Get current debug level"""
    return _debug_level


def debug(msg: str, level: int = 1):
    """Print debug message if debug level is sufficient"""
    if _debug_level >= level:
        print(msg)


def debug_hex(label: str, data: bytes, level: int = 2, max_len: int = 50):
    """Print hex dump of data if debug level is sufficient"""
    if _debug_level >= level:
        hex_str = data[:max_len].hex()
        if len(data) > max_len:
            hex_str += "..."
        print(f"{label}: {hex_str}")
