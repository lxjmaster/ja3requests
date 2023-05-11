import unittest
from ja3requests.request import ReadyRequest


class TestReadyRequest(unittest.TestCase):

    request = ReadyRequest(
        "GET",
        "http://www.baidu.com"
    )

    def test_ready(self):

        self.request.ready()
        print(self.request.scheme, self.request.url)

    def test_request(self):
        req = self.request.request()
        req.send()


if __name__ == '__main__':
    unittest.main()
