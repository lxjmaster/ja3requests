import unittest
from ja3requests.sessions import Session
import requests
from io import BufferedRandom, TextIOWrapper, BytesIO, IOBase
import mimetypes


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
        f = open("test.txt", "rb+")

        response = self.session.post("http://127.0.0.1:8080/login", json=data, files={"file": f}, headers=headers)
        # response = requests.post("http://127.0.0.1:8080/login", data=data, files={"file": f})

        print(response)
        print(response.status_code)
        print(response.headers)
        print(response.json())
        f.close()

    def test_post_multi_files(self):

        data = {
            "name": "test",
            "project_type": 1
        }
        files = {
            "documents": ["/Users/pledgebox/Projects/ja3requests/test/test.txt", "/Users/pledgebox/Projects/ja3requests/test/1.csv"]
        }

        response = self.session.post("http://127.0.0.1:8080/api/v1/project/create", data=data, files=files)
        print(response)
        print(response.status_code)
        print(response.headers)
        print(response.json())

    def test_r(self):
        response = requests.post("https://baidu.com", data={"a": 1})
        print(response.text)

    def test_proxy(self):

        proxies = {
            "http": "127.0.0.1:7890",
            "https": "127.0.0.1:7890"
        }
        # proxies = {
        #     "http": "9jjmn:uweo3gw@169.197.83.75:6887",
        #     "https": "9jjmn:uweo3gw@169.197.83.75:6887"
        # }
        response = self.session.get("http://ifconfig.me", proxies=proxies)
        print(response)
        print(response.status_code)
        print(response.content)
        print(response.headers)
        print(response.text)
        # print(response.json())

    def test_redirect(self):

        response = self.session.get("http://127.0.0.1:8080/redirect")
        print(response)
        print(response.status_code)
        print(response.content)
        print(response.headers)
        print(response.text)

    def test_cookies(self):

        response = self.session.get("http://127.0.0.1:8080/cookies", cookies="visitor_id=46f759b7a4163bb6cdb75496d0f20d9d4c923c99e66e70b51a42a2565e51bbb2; x-spec-id=b37a2959d518daa20e1a925235efda7b; _ga=GA1.1.1180078114.1700553181; _gcl_au=1.1.939381393.1700794101; _fbp=fb.1.1700794100765.899406327; _tt_enable_cookie=1; _ttp=RFpK3PVl4QTlExYptLDW7bC8EtS; permutive-id=f06468b0-cfd1-44b8-ab89-31dae4a29dfd; __stripe_mid=2c79449d-c8c7-47b6-96b1-ad9b7e2cd2852694b5; __ssid=1bfc66fd636400f35038cffd272dc33; cto_bundle=ZSrZj19vNENzVndIRW54VklPeVpHRU01QWw4eVFBQ2lFOHF6TnV3JTJCYmRZSmxCd3N4eExhTEFKV3Z4Z3JqOHMwMDclMkZyYkJGRnc4TERJNDRoSjl4UWlEZ2Q0ODd4Mzg0UUxBM1NhUWJsMHhwc2h3bmlXOXVQa1l4VSUyRlE0czYlMkIyVE1ENkIybHBrak9YS2QlMkZmRXRoQ3UwRUxZMVoweGlZejV2Tm1kN3dod2lMbmJmSlI4JTNE; _ga_QETRR7E37F=GS1.1.1700794116.1.1.1700794291.28.0.0; localCurrencyIsoCode=USD; romref_referer_host=www.indiegogo.com; optimizelyEndUserId=oeu1704278791748r0.3067598211937421; optimizelySegments=%7B%222354810435%22%3A%22true%22%7D; optimizelyBuckets=%7B%7D; _ga_39QX3WF5EB=GS1.1.1704279034.1.1.1704279038.0.0.0; _session_id=cc851bc32228e4c6d9f596336d3f0b5e; analytics_session_id=e05d0a8d53bdbca46ecae3e8f106986809b4e77dd8264b3f4aefd05182a3c7bf; romref=shr-hmco; cohort=www.indiegogo.com%7Cdir-XXXX%7Cshr-hmco%7Cref-XXXX%7Cshr-hmhd%7Cshr-pies%7Cshr-hmco; recent_project_ids=2870703%262557678%262501412%262262076%262865436%262871402%262889001%26332405%26245753%262850915%262863909%262854586%262830934%262869077; __stripe_sid=490fec6f-b50b-4fb6-a4e0-7a3958ab62e015210d; _ga_DTZH7F2EYR=GS1.1.1704941476.8.1.1704941526.10.0.0; _ga_CLN2NQBG5Y=GS1.1.1704941496.1.1.1704941711.0.0.0")
        print(self.session.cookies)
        # print(response)
        # print(response.status_code)
        # print(response.content)
        # print(response.headers)
        # print(response.cookies)
        # print(response.text)


if __name__ == '__main__':
    unittest.main()


