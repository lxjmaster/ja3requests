import unittest
from ja3requests.sessions import Session


class TestSession(unittest.TestCase):

    session = Session()

    def test_get(self):

        headers = {
            "connection": "close"
        }
        self.session.get("http://www.baidu.com")

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


