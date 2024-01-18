# Ja3Requests
**Ja3Requests**是一个可以自定义ja3指纹（tls指纹）和HTTP2指纹的请求库

[English Document](README.md)

```pycon
>>> import ja3requests
>>> session = ja3requests.Session()
>>> response = session.get("http://www.baidu.com/")
>>> response
<Response [200]>
>>> response.status_code
200
>>> response.headers
{'Content-Length': '405968', 'Content-Type': 'text/html; charset=utf-8', 'Server': 'BWS/1.1', 'Vary': 'Accept-Encoding', 'X-Ua-Compatible': 'IE=Edge,chrome=1', ...}
>>> response.text
'<!DOCTYPE html><!--STATUS OK--><html><head><meta http-equiv="Content-Type" content="text/html;char...'
```

Ja3Requests目前只实现了HTTP协议和部分方法.

## 安装 Ja3Requests/ 支持的版本

从PYPI安装:

```console
$ python -m pip install ja3requests
```

Ja3Requests正式支持Python 3.7+

## 如何使用
### 不同的请求方法
Ja3Requests支持多种请求方法，如Get，Post，Put，Delete等
```python
import ja3requests

session = ja3requests.session()
# Get
session.get("http://example.com/")

# POST
session.post("http://example.com/")
...
```

### 使用headers属性
```python
import ja3requests

headers = {
    "Accept": "*/*",
    "Accept-Encoding": "gzip, deflate, br",
    "Connection": "keep-alive",
    "Host": "example.com",
    "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:120.0) Gecko/20100101 Firefox/120.0"
}

session = ja3requests.session()

response = session.get("http://example.com/", headers=headers)
print(response)
```

### 使用params属性
```python
import ja3requests

session = ja3requests.session()

params = {
    "page": 1,
    "page_size": 100
}
# OR
# params = "page=1&page_zie=100"
# OR
# params = [("page", 1), ("page_size", 100)]
# OR
# params = (("page", 1), ("page_size", 100))
response = session.get("http://example.com/", params=params)
print(response)
```


### Post请求提交data数据
```python
import ja3requests

session = ja3requests.session()

data = {
    "username": "admin",
    "password": "admin"
}
# OR (Content-Type: application/x-www-form-urlencoded)
# data = "username=admin&password=admin"
# OR
# data = [("username", "admin"), ("password": "admin")]
# OR
# data = (("username", "admin"), ("password", "admin"))

response = session.post("http://example.com/", data=data)
print(response)
```


### Post提交json

```python
import ja3requests

session = ja3requests.session()

data = {
    "username": "admin",
    "password": "admin"
}
# OR
# import json
# data = json.dumps(data)

response = session.post("http://example.com/", json=data)
print(response)
```


### Post提交文件

```python
import ja3requests

session = ja3requests.session()

with open("/user/home/demo.txt", "r") as f:
    response = session.post("http://example.com/", files={"field_name": f})
print(response)

# OR
# response = session.post("http://example.com/", files={"field_name": "/user/home/demo.txt"})

# multiple files
# response = session.post("http://example.com/", files={"field_name": ["/user/home/demo.txt", "/user/home/demo2.txt"]})
```


### 使用proxies属性

```python
import ja3requests

session = ja3requests.session()

proxies = {
    "http": "127.0.0.1:7890",
    "https": "127.0.0.1:7890"
}

response = session.get("http://example.com/", proxies=proxies)
print(response)

# With Authorization information
# proxies = {
#     "http": "user:password@127.0.0.1:7890",
#     "https": "user:password@127.0.0.1:7890"
# }
```


### 使用cookies属性

```python
import ja3requests

session = ja3requests.session()
cookies = {
    "sessionId": "xxxx",
    "userId": "xxxx",
}
# OR
# cookies = "sessionId=xxxx; userId=xxxx;...."
# OR
# cookies = <CookieJar()>

# Or set cookies in headers = {"Cookies": "sessionId=xxxx; userId=xxxx;...."}

response = session.get("http://example.com/", cookies=cookies)
print(response)
```


### 允许重定向

```python
import ja3requests

session = ja3requests.session()

# Default allow_redirects=True
response = session.get("http://example.com/", allow_redirects=False)
print(response)
```


## 参考
- [HTTP](https://developer.mozilla.org/en-US/docs/Web/HTTP)
- [HTTP-RFC](https://www.rfc-editor.org/rfc/rfc2068.html)
- [TLS v1.1-RFC](https://datatracker.ietf.org/doc/html/rfc4346)
- [TLS v1.2-RFC](https://datatracker.ietf.org/doc/html/rfc5246)
- [TLS v1.3-RFC](https://datatracker.ietf.org/doc/html/rfc8446)
- [HTTP2-RFC](https://httpwg.org/specs/rfc9113.html)
- [SSL-CONFIG-GENERATOR](https://ssl-config.mozilla.org/)
- [SHA-256/384 and AES GCM](https://www.rfc-editor.org/rfc/rfc5289.html)
- [ECC Cipher Suites for TLS 1.2 and Earlier](https://www.rfc-editor.org/rfc/rfc8422.html)
