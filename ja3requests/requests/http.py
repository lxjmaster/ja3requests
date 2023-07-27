from .base import BaseRequest
from ja3requests.sockets.socket import Socket


class HttpRequest(BaseRequest):

    # def __init__(self, request):
    #
    #     self.request = request
    #     self.socket = Socket(self)
    #     self.proxy = None
    #     self.proxy_auth = None

    def send(self):

        sock = self.socket.create_sock()
        # conn = sock.create_connect()
        # conn.send()
