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
协商 HTTP/2。2.0 默认验证证书，优先使用 TLS 1.3，并允许 TLS 1.2 ECDHE/GCM 回退。

## 安装 Ja3Requests/ 支持的版本

从PYPI安装:

```console
$ python -m pip install ja3requests
```

Ja3Requests正式支持Python 3.7+

## HTTPS 证书验证

2.0 默认验证服务器证书。`TlsConfig()`、`Session()` 和模块级请求使用
TLS 1.3/TLS 1.2 ECDHE-GCM 安全配置，也可以继续显式选择：

```python
import ja3requests

config = ja3requests.TlsConfig.secure()
with ja3requests.Session(tls_config=config) as session:
    response = session.get("https://example.com/")
```

安全配置验证证书，仅提供 TLS 1.3 套件和 TLS 1.2 ECDHE/AES-128/256-GCM 套件，
并通过 ALPN 使用 HTTP/1.1；它不模拟浏览器指纹。TLS 1.3 ClientHello
默认同时携带 X25519 和 P-256 密钥份额。如需首次只提供 X25519、允许
P-256 服务端通过 HelloRetryRequest 要求重试，可在创建 Session 前设置
`config.key_share_groups = [29]`；其他组尚未实现。
TLS 1.3 连接可处理服务端 KeyUpdate，并在服务端要求时更新客户端发送密钥。
会话缓存可用内存中的票据和 PSK-DHE 恢复 TLS 1.3 连接；目前不支持 0-RTT。
TLS 1.2 可在原会话使用扩展主密钥、且证书策略仍匹配时，通过内存中的
Session ID 完成简化握手；配置 `SessionTicketExtension()` 后也可使用会话票据。
该扩展可从 `ja3requests.protocol.tls.extensions` 导入。
单次请求也可传入
`verify=True` 启用验证。
要获得包含目标主机 SNI 扩展的 JA3 字符串，使用
`config.get_ja3_string(server_name="example.com")`。同一个连接池中的
HTTP/2 请求（包括带请求体的请求）可在一条 TLS 连接上并发处理；响应按流 ID
对应，请求 DATA 遵守服务端的帧大小、连接窗口和流窗口。HTTP/1.1 连接仍顺序复用。
服务端推送尚未实现，因此 HTTP/2 默认禁用推送，并拒绝显式设置
`SETTINGS_ENABLE_PUSH=1`。
旧式 HTTP/2 优先级信号可被接收，但不影响请求调度。

请求显式传入的 `verify=True` 或 `verify=False` 会覆盖会话设置，重定向也沿用
本次请求的设置。`TlsConfig.legacy()` 显式恢复 1.x 的 TLS 1.2 RSA/AES-CBC
配置并关闭证书验证。新默认会改变 ClientHello/JA3 指纹，并拒绝不受信任、
过期或目标主机名不匹配的证书。[TLS 默认值迁移指南](docs/tls_defaults_migration.md)（英文）
说明私有 CA 信任、目标主机名与服务名称指示（SNI）、请求覆盖、旧服务配置及
2.0 兼容性变化。浏览器预设工厂保留显式协议参数并默认验证证书；自定义
构建方法继承原配置的验证策略和扩展。详见[版本说明](CHANGELOG.md)。`verify` 接受布尔覆盖；自定义 CA 文件使用
`SSL_CERT_FILE`，SNI 覆盖不会替代对 URL 目标主机的证书校验。
已验证的组合与环境限制见[安全配置互通矩阵](test/secure_profile_matrix.md)，
具体测试见[本地协议测试](test/README.md)。

TLS 1.2 和 TLS 1.3 客户端证书认证均在服务端请求证书时使用 `client_cert`
和 `client_key`。配置 TLS 1.3 客户端证书后，不使用 PSK 票据恢复。TLS 1.3
握手后客户端认证需显式启用：创建会话前向 `config.extensions` 加入
`PostHandshakeAuthExtension()`。未配置客户端证书时会发送空的 Certificate 消息。
该扩展会改变 ClientHello 指纹。

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


### Cookie 文件持久化

使用 `session.save_cookies(path)` 和 `session.load_cookies(path)` 显式保存、
加载 JSON 文件，以便进程重启后恢复 Cookie。加载默认替换已有存储；
`merge=True` 按域名、路径和名称合并。保存和加载会话 Cookie 均需传入
`include_session=True`，过期项始终跳过。文件可能明文包含登录令牌；POSIX
上以仅所有者可读写的 `0600` 权限保存。范围约束、格式、限制、失败处理及
可运行示例见 [Cookie 文件持久化指南](docs/cookie_persistence.md)（英文）。

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
