"""
Ja3Requests.exceptions
~~~~~~~~~~~~~~~~~~~~~~

This module contains the set of Requests' exceptions.
"""


class RequestException(IOError):
    """
    There was an ambiguous exception that occurred while handling your request.
    """

    def __init__(self, *args, **kwargs):
        """
        Initialize RequestException with `request` and `response` objects.
        """
        response = kwargs.pop("response", None)
        self.response = response
        self.request = kwargs.pop("request", None)
        if response is not None and not self.request and hasattr(response, "request"):
            self.request = self.response.request
        super().__init__(*args, **kwargs)


class NotAllowedRequestMethod(RequestException, ValueError):
    """
    If the request method not allowed and raise it.
    """


class MissingScheme(RequestException, ValueError):
    """
    The URL scheme (e.g. http or https) is missing and raise it.
    """


class NotAllowedScheme(RequestException, ValueError):
    """
    If the scheme not allowed and raise it.
    """


class InvalidParams(RequestException, ValueError):
    """
    If request params invalid and raise it.
    """


class InvalidData(RequestException, ValueError):
    """
    If request data invalid and raise it.
    """


class InvalidHost(RequestException, ValueError):
    """
    Raised it while host can not parse.
    """


class InvalidStatusLine(RequestException, ValueError):
    """
    Raised it when can't receive streamline.
    """


class InvalidResponseHeaders(RequestException, ValueError):
    """
    Raised it when cant receive response headers.
    """


class MaxRetriedException(RuntimeError):
    """
    Raised it when retried
    """


class IssueError(ValueError):
    """
    This situation may not be considered yet, please issue it
    """


class HTTPError(RequestException):
    """An HTTP error occurred (4xx/5xx status codes)."""


class ConnectionException(RequestException):
    """A connection error occurred."""


class Timeout(RequestException):
    """The request timed out."""


class TLSError(RequestException):
    """Base exception for all TLS-related errors."""


class TLSEncryptionError(TLSError):
    """Encryption operation failed (AES-CBC, AES-GCM, RSA)."""


class TLSDecryptionError(TLSError):
    """Decryption operation failed (AES-CBC, AES-GCM)."""


class TLSMACVerificationError(TLSDecryptionError):
    """MAC or AEAD authentication tag verification failed."""


class TLSHandshakeError(TLSError):
    """TLS handshake protocol error (missing keys, bad Finished, etc.)."""


class TLSKeyError(TLSError):
    """Missing or invalid encryption keys."""
