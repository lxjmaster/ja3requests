"""
ja3requests.protocol.exceptions
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

This module contains socket exceptions.
"""


class SocketException(Exception):
    """
    Base exception used by this module.
    """


class SocketTimeout(OSError):
    """ Timeout expired. """


class LocationParseError(SocketException, ValueError):
    """
    Socket host encode error.
    """


class SocketTimeoutError(SocketException):
    """
    Raised when a socket timeout error occurs.
    """


class ConnectTimeoutError(SocketTimeoutError):
    """
    Raised when a socket timeout occurs while connecting to a server
    """