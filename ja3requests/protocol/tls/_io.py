"""Small I/O boundary for the existing TLS handshake state machine.

Decorated methods keep their synchronous calling convention. Their generators
are also consumed by the native async transport, without a second TLS engine.
"""

from collections import namedtuple
from functools import wraps
import time


Read = namedtuple("Read", "size")
Write = namedtuple("Write", "data")
Pause = namedtuple("Pause", "seconds")
Call = namedtuple("Call", "method args", defaults=((),))


def handshake_io(method):
    """Keep a synchronous method and expose its byte-driven handshake steps."""

    @wraps(method)
    def synchronous(self, *args, **kwargs):
        return run_sync(self.conn, method(self, *args, **kwargs))

    synchronous.handshake_steps = method
    return synchronous


def run_sync(conn, steps):
    """Execute the same socket operations, exceptions and sleeps as before."""
    result = None
    failure = None
    try:
        while True:
            try:
                if failure is None:
                    operation = steps.send(result)
                else:
                    error, failure = failure, None
                    operation = steps.throw(error)
            except StopIteration as completed:
                return completed.value
            try:
                if isinstance(operation, Read):
                    result = conn.recv(operation.size)
                elif isinstance(operation, Write):
                    result = conn.sendall(operation.data)
                elif isinstance(operation, Pause):
                    result = time.sleep(operation.seconds)
                elif isinstance(operation, Call):
                    result = operation.method(*operation.args)
                else:
                    raise TypeError("Unknown TLS handshake operation")
            except Exception as error:
                failure = error
    finally:
        steps.close()
