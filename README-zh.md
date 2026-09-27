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

Ja3Requests 支持 HTTP 和 HTTPS 上的 HTTP/1.1；HTTPS 连接也可以通过 ALPN
协商 HTTP/2。默认使用 TLS 1.2，TLS 1.3 可通过配置启用。

## 安装 Ja3Requests/ 支持的版本

从PYPI安装:

```console
$ python -m pip install ja3requests
```

Ja3Requests正式支持Python 3.7+

## HTTPS 证书验证

为保持兼容，默认不验证服务器证书。需要验证证书、优先使用 TLS 1.3 并允许
TLS 1.2 ECDHE/AES-GCM 回退时，显式选择安全配置：

```python
import ja3requests

config = ja3requests.TlsConfig.secure()
with ja3requests.Session(tls_config=config) as session:
    response = session.get("https://example.com/")
```

安全配置验证证书，仅提供 TLS 1.3 套件和 TLS 1.2 ECDHE/AES-128/256-GCM 套件，
并通过 ALPN 使用 HTTP/1.1；它不模拟浏览器指纹。TLS 1.3 ClientHello
同时携带 X25519 和 P-256 密钥份额；服务端要求其他组时，尚不能处理
HelloRetryRequest。单次请求也可传入
`verify=True` 启用验证。
要获得包含目标主机 SNI 扩展的 JA3 字符串，使用
`config.get_ja3_string(server_name="example.com")`。HTTP/2 请求目前每次新建
连接，待连接级 HTTP/2 状态可复用后再启用连接复用。

请求显式传入的 `verify=True` 或 `verify=False` 会覆盖会话设置，重定向也沿用
本次请求的设置。本版本 `TlsConfig()` 保持旧默认；`TlsConfig.legacy()`
显式固定旧行为，且关闭证书验证。未来切换构造器默认值需要破坏性版本变更
和更广的互通测试。已测试的路径及限制见[本地协议测试](test/README.md)。

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
- [IANA Registry Updates for TLS and DTLS](https://datatracker.ietf.org/doc/html/rfc8447)
- [HTTP2-RFC](https://httpwg.org/specs/rfc9113.html)
- [SSL-CONFIG-GENERATOR](https://ssl-config.mozilla.org/)
- [SHA-256/384 and AES GCM](https://www.rfc-editor.org/rfc/rfc5289.html)
- [ECC Cipher Suites for TLS 1.2 and Earlier](https://www.rfc-editor.org/rfc/rfc8422.html)
- [TLS EXTENSIONS](https://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xhtml)
