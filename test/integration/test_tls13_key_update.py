"""OpenSSL interoperability for TLS 1.3 post-handshake KeyUpdate."""

import os
import select
import shutil
import socket
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor
from threading import Event

import pytest

from ja3requests import Session, TlsConfig
from ja3requests.protocol.tls.tls13 import TLS13Handshake
from ja3requests.sockets.https import HttpsSocket


@pytest.mark.skipif(shutil.which("openssl") is None, reason="OpenSSL CLI unavailable")
@pytest.mark.parametrize("initiator", ["server", "client"])
def test_openssl_requested_key_update(trusted_certificates, monkeypatch, initiator):
    monkeypatch.setenv("SSL_CERT_FILE", str(trusted_certificates.ca_path))
    certificate = trusted_certificates.leaves["valid"]
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        port = listener.getsockname()[1]

    command = [
        "openssl",
        "s_server",
        "-accept",
        f"127.0.0.1:{port}",
        "-cert",
        str(certificate[0]),
        "-key",
        str(certificate[1]),
        "-tls1_3",
        "-no_ticket",
    ]
    process = subprocess.Popen(
        command,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        bufsize=0,
    )
    key_update_received = Event()
    original = TLS13Handshake.process_post_handshake
    expected_update = b"\x18\x00\x00\x01" + (
        b"\x01" if initiator == "server" else b"\x00"
    )

    def record_key_update(handshake, plaintext):
        if plaintext.startswith(expected_update):
            key_update_received.set()
        return original(handshake, plaintext)

    monkeypatch.setattr(TLS13Handshake, "process_post_handshake", record_key_update)
    if initiator == "client":
        original_send = HttpsSocket._send_h1

        def send_after_update(transport):
            transport.send_key_update(request_update=True)
            return original_send(transport)

        monkeypatch.setattr(HttpsSocket, "_send_h1", send_after_update)
    try:
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            if process.poll() is not None:
                raise AssertionError(
                    "OpenSSL server exited before accepting connections"
                )
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=0.1):
                    break
            except OSError:
                time.sleep(0.05)
        else:
            raise AssertionError("OpenSSL server did not start")

        def request():
            with Session(tls_config=TlsConfig.secure(), use_pooling=False) as session:
                return session.get(f"https://127.0.0.1:{port}/", timeout=5).content

        with ThreadPoolExecutor(max_workers=1) as executor:
            result = executor.submit(request)
            received = b""
            deadline = time.monotonic() + 6
            while b"GET / HTTP/1.1" not in received and time.monotonic() < deadline:
                ready, _, _ = select.select([process.stdout], [], [], 0.2)
                if ready:
                    received += os.read(process.stdout.fileno(), 4096)
            assert b"GET / HTTP/1.1" in received, received

            if initiator == "server":
                process.stdin.write(b"K\n")
                process.stdin.flush()
                assert key_update_received.wait(3), "OpenSSL did not send KeyUpdate"
            process.stdin.write(b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nok\n")
            process.stdin.flush()
            assert result.result(timeout=8) == b"ok\n"
            assert key_update_received.wait(1), "OpenSSL did not send KeyUpdate"
    finally:
        process.terminate()
        try:
            process.communicate(timeout=2)
        except subprocess.TimeoutExpired:
            process.kill()
            process.communicate(timeout=2)
