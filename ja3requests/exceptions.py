"""
ja3requests.exceptions
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