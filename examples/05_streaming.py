"""Streaming responses: large file download and line-by-line processing."""

import json
from ja3requests import Session

session = Session(use_pooling=False)

# Stream large file download
# resp = session.get("https://example.com/large-file.zip", stream=True)
# with open("download.zip", "wb") as f:
#     for chunk in resp.iter_content(chunk_size=8192):
#         f.write(chunk)
# resp.close()

# Line-by-line processing (NDJSON, SSE, logs)
# resp = session.get("https://api.example.com/events", stream=True)
# for line in resp.iter_lines():
#     if line:
#         event = json.loads(line)
#         print(f"Event: {event}")

# Custom delimiter
# resp = session.get("https://example.com/csv", stream=True)
# for record in resp.iter_lines(delimiter=b"\r\n"):
#     print(record.decode())

print("Streaming examples ready (uncomment to use with real endpoints)")
