"""Basic HTTP request examples: GET, POST, JSON, headers, status codes."""

import ja3requests

# GET request
resp = ja3requests.get("http://httpbin.org/get")
print(f"Status: {resp.status_code}")
print(f"Headers: {resp.headers}")
print(f"Body: {resp.text[:200]}")

# POST with form data
resp = ja3requests.post("http://httpbin.org/post", data={"username": "test", "password": "secret"})
print(f"POST status: {resp.status_code}")

# POST with JSON
resp = ja3requests.post("http://httpbin.org/post", json={"key": "value", "items": [1, 2, 3]})
print(f"JSON response: {resp.json()}")

# Custom headers
resp = ja3requests.get("http://httpbin.org/headers", headers={
    "X-Custom-Header": "MyValue",
    "Accept-Language": "en-US",
})

# Check status with raise_for_status
resp = ja3requests.get("http://httpbin.org/status/404")
try:
    resp.raise_for_status()
except ja3requests.HTTPError as e:
    print(f"HTTP Error: {e}")
