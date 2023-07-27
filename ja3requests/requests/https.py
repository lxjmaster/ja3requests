from .base import BaseRequest


class HttpsRequest(BaseRequest):

    def __init__(self, request):

        self.request = request

    def send(self):
        print(self.request)
