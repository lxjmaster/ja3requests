

# Ja3Requests
**Ja3Requests** is An http request library that can customize ja3 fingerprints.

[中文文档](README-zh.md)

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

Ja3Requests currently implements only the HTTP protocol and a few methods.

## Installing Requests and Supported Versions

Ja3Requests is available on PyPI:

```console
$ python -m pip install ja3requests
```

Ja3Requests officially supports Python 3.7+.

## Reference
- [HTTP](https://developer.mozilla.org/en-US/docs/Web/HTTP)