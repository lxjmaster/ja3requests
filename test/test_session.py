import unittest
from ja3requests.sessions import Session


class TestSession(unittest.TestCase):

    session = Session()

    def test_get(self):

        self.session.get("http://localhost:8080/")


if __name__ == '__main__':
    unittest.main()
