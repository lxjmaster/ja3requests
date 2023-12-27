from abc import ABC, abstractmethod
import typing
from urllib.parse import urlsplit
from ja3requests.base import BaseContext


class BaseRequest(ABC):

    def __init__(self, context: BaseContext):

        self.context = context

    @staticmethod
    def parse_proxy(proxy: typing.AnyStr = None):
        if proxy is None:
            return None, None, None, None

        split_result = urlsplit(f'https://{proxy}')
        username = split_result.username
        password = split_result.password
        host = split_result.hostname
        port = split_result.port

        return username, password, host, port

    @abstractmethod
    def send(self):

        raise NotImplementedError("send method must be implemented by subclass.")


if __name__ == '__main__':
    BaseRequest.parse_proxy("9jjmn:uweo3gw@123@169.197.83.75:6887")