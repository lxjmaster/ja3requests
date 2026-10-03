"""Capture one clean-profile Chrome ClientHello on loopback, then exit.

Usage: python -m test.capture_browser_hello /absolute/chrome /output.json
No personal browser profile, external target or client TLS implementation is used.
"""

import hashlib
import json
import platform
import socket
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path


def capture(executable, output):
    version = subprocess.check_output([executable, '--version'], text=True).strip()
    with tempfile.TemporaryDirectory(prefix='ja3requests-browser-') as profile:
        with socket.socket() as listener:
            listener.bind(('127.0.0.1', 0))
            listener.listen(1)
            listener.settimeout(25)
            url = 'https://localhost:%d/' % listener.getsockname()[1]
            flags = [
                '--headless',
                '--disable-background-networking',
                '--disable-component-update',
                '--disable-sync',
                '--no-first-run',
                '--no-default-browser-check',
                '--no-proxy-server',
                '--user-data-dir=' + profile,
                '--dump-dom',
                url,
            ]
            process = subprocess.Popen(
                [executable] + flags,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            try:
                with listener.accept()[0] as conn:
                    conn.settimeout(5)

                    def read(size):
                        value = b''
                        while len(value) < size:
                            part = conn.recv(size - len(value))
                            if not part:
                                raise EOFError('Browser closed before ClientHello')
                            value += part
                        return value

                    header = read(5)
                    record = header + read(int.from_bytes(header[3:5], 'big'))
            finally:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
    Path(output).parent.mkdir(parents=True, exist_ok=True)
    Path(output).write_text(
        json.dumps(
            dict(
                browser=version,
                platform=platform.platform(),
                captured_at=datetime.now(timezone.utc).isoformat(),
                target='loopback localhost',
                profile='new isolated temporary profile, removed after capture',
                flags=[
                    f
                    for f in flags
                    if not f.startswith('--user-data-dir=') and f != url
                ],
                sha256=hashlib.sha256(record).hexdigest(),
                record_hex=record.hex(),
            ),
            indent=2,
        )
        + '\n'
    )
    print(version, 'captured', len(record), 'bytes to', output)


if __name__ == '__main__':
    capture(*sys.argv[1:])
