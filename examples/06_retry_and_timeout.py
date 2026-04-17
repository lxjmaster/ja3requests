"""Retry strategy and timeout configuration."""

from ja3requests import Session
from ja3requests.retry import HTTPRetry

# Separate connect and read timeouts
session = Session(use_pooling=False)
# resp = session.get("https://httpbin.org/delay/2", timeout=(5, 30))
# Connect timeout: 5s, Read timeout: 30s

# Single timeout (applies to both)
# resp = session.get("https://httpbin.org/get", timeout=10)

# HTTP-level retry with exponential backoff
retry = HTTPRetry(
    total=3,                                  # max 3 retries
    backoff_factor=0.5,                       # 0.5s, 1s, 2s delay
    status_forcelist={500, 502, 503, 504},    # retry on these status codes
    allowed_methods={"GET", "HEAD", "POST"},  # methods safe to retry
    respect_retry_after=True,                 # honor Retry-After header
)

session = Session(use_pooling=False, retry=retry)
# resp = session.get("https://httpbin.org/status/503")
# Will retry 3 times with backoff before raising MaxRetriedException

print("Retry config:", retry.__dict__)
print(f"Backoff times: {[retry.get_backoff_time(i) for i in range(1, 4)]}")
