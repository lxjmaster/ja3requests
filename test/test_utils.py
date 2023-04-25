import unittest
from ja3requests.utils import default_headers


class TestUtils(unittest.TestCase):

    def test_default_headers(self):

        result = default_headers()
        print(result)


if __name__ == '__main__':
    unittest.main()
