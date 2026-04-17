"""Proxy configuration: HTTP CONNECT, SOCKS5, SOCKS4 with authentication."""

from ja3requests import Session

session = Session(use_pooling=False)

# HTTP CONNECT proxy
# resp = session.get("https://httpbin.org/ip", proxies={
#     "https": "127.0.0.1:8080",
# })

# HTTP proxy with authentication
# resp = session.get("https://httpbin.org/ip", proxies={
#     "https": "user:password@proxy.example.com:8080",
# })

# SOCKS5 proxy
# resp = session.get("https://httpbin.org/ip", proxies={
#     "https": "socks5://127.0.0.1:1080",
# })

# SOCKS5 proxy with authentication
# resp = session.get("https://httpbin.org/ip", proxies={
#     "https": "socks5://user:pass@127.0.0.1:1080",
# })

# SOCKS4 proxy (hostname resolved by proxy)
# resp = session.get("https://httpbin.org/ip", proxies={
#     "https": "socks4://127.0.0.1:1080",
# })

print("Proxy examples ready (uncomment to use with real proxies)")
