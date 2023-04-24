"""
ja3Requests.sessions
~~~~~~~~~~~~~~~~~~~~

This module provides a Session object to manage and persist settings across
ja3Requests.
"""
import sys
import time
from typing import AnyStr

# Preferred clock, based on which one is more accurate on a given system.
if sys.platform == "win32":
    preferred_clock = time.perf_counter
else:
    preferred_clock = time.time
