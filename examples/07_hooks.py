"""Event hooks: before_request and after_request callbacks."""

import time
from ja3requests import Session


def log_request(request):
    """Log every outgoing request."""
    print(f"[HOOK] Sending: {getattr(request, 'method', '?')} {getattr(request, 'url', '?')}")
    request._start_time = time.time()
    return request


def log_response(response):
    """Log every incoming response with timing."""
    elapsed = time.time() - getattr(response.request, '_start_time', time.time())
    print(f"[HOOK] Response: {response.status_code} ({elapsed:.3f}s)")
    return response


# Session-level hooks (persist across all requests)
session = Session(
    use_pooling=False,
    hooks={
        "before_request": [log_request],
        "after_request": [log_response],
    }
)

# Or add hooks after creation
session.hooks["after_request"].append(lambda r: print(f"[HOOK2] Content-Length: {len(r.body)}") or r)

# Per-request hooks (only for this specific request)
# resp = session.get("https://httpbin.org/get", hooks={
#     "after_request": [lambda r: print(f"Per-request hook: {r.status_code}") or r]
# })

print("Hook system configured with 2 session hooks")
