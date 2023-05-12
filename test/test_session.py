import unittest
from ja3requests.sessions import Session


class TestSession(unittest.TestCase):

    session = Session()

    def test_get(self):

        headers = {
            "connection": "close"
        }
        self.session.get("http://www.baidu.com")


if __name__ == '__main__':
    unittest.main()
