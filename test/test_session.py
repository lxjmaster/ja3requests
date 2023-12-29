import unittest
from ja3requests.sessions import Session
import requests


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

    def test_post_data(self):

        data = {
            "username": "admin",
            "password": "admin"
        }
        response = self.session.post("http://127.0.0.1:8080/login", data=data)
        print(response)
        print(response.status_code)
        print(response.headers)
        print(response.content)


if __name__ == '__main__':
    unittest.main()


