import unittest
from ja3requests.sessions import Session
import requests
from io import BufferedRandom, TextIOWrapper, BytesIO, IOBase


class TestSession(unittest.TestCase):

    session = Session()
    headers = {
        "connection": "close"
    }

    def test_get(self):

        # response = self.session.get("http://www.baidu.com", headers=headers)
        response = requests.get("http://www.baidu.com")
        print(response)
        print(response.status_code)
        print(response.headers)
        print(response.text)

    def test_request_index(self):

        response = self.session.get("http://127.0.0.1:8080/", headers=self.headers)
        print(self.session.Request)
        # response = requests.get("http://127.0.0.1:8000/")
        print(response)
        print(response.status_code)
        print(response.headers)
        print(response.text)

    def test_request1(self):
        response = self.session.get("http://127.0.0.1:8080/test1?page=1&limit=100", headers=self.headers)
        # response = requests.get("http://127.0.0.1:8000/")
        print(response)
        print(response.status_code)
        print(response.headers)
        print(response.text)

    def test_request2(self):
        response = self.session.get("http://127.0.0.1:8080/test2/hello/9", headers=self.headers)
        # response = requests.get("http://127.0.0.1:8000/")
        print(response)
        print(response.status_code)
        print(response.headers)
        print(response.text)

    def test_post_data(self):

        data = {
            "username": "admin",
            "password": "admin",
        }
        headers = {
            "content-type": "multipart/form-data"
        }
        response = self.session.post("http://127.0.0.1:8080/login", data=data, headers=headers)
        # response = requests.post("http://127.0.0.1:8080/login", data=data)

        print(response)
        print(response.status_code)
        print(response.headers)
        print(response.json())

    def test_r(self):
        response = requests.post("https://baidu.com", data={"a": 1})
        print(response.text)


if __name__ == '__main__':
    unittest.main()


