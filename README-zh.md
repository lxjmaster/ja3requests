

# Ja3Requests
**Ja3Requests**是一个可以自定义ja3指纹（tls指纹）和HTTP2指纹的请求库

[English Document](README.md)

```python
>>> import ja3requests
>>> session = ja3requests.Session()
>>> response = session.get("http://www.baidu.com")
>>> response
<Response [200]>
>>> response.status_code
200
>>> response.headers
[{'Bdqid': '0xdc8736c700095118'}, {'Connection': 'keep-alive'},...]
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

## 参考
- [HTTP](https://developer.mozilla.org/en-US/docs/Web/HTTP)
- [HTTP-RFC](https://www.rfc-editor.org/rfc/rfc2068.html)