from .http import HttpSocket
from .https import HttpSocket
from ja3requests.exceptions import NotAllowedScheme


class Socket:

    def __init__(self, request):

        self.request = request

    def create_sock(self):
        if self.request.schema == "http":
            return HttpSocket()
        elif self.request.schema == "https":
            return HttpSocket()
        else:
            raise NotAllowedScheme(f"Schema: {self.request.scheme} not allowed.")
