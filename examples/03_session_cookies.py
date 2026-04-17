"""Session cookies: persistence across requests, manual cookie management."""

from ja3requests import Session

# Cookies persist across requests in a session
session = Session(use_pooling=False)

# Set cookies manually
session._cookies["session_id"] = "abc123"
session._cookies["lang"] = "en"

# Cookies are automatically sent with each request
# resp = session.get("http://httpbin.org/cookies")

# Per-request cookies (merged with session cookies)
# resp = session.get("http://httpbin.org/cookies", cookies={"extra": "value"})

# Inspect session cookies
print(f"Session cookies: {dict(session._cookies.items())}")

# Context manager auto-closes session
with Session(use_pooling=False) as s:
    s._cookies["token"] = "xyz"
    print(f"In-context cookies: {dict(s._cookies.items())}")
