"""Small independent wire peers; no project protocol code is used here."""

import socket
import ssl
import struct
import threading


def recv_with_ragged_eof(conn, size):
    """Normalize old Python/OpenSSL EOF reporting in the test peer only."""
    try:
        return conn.recv(size)
    except ssl.SSLError as error:
        # Python 3.7 can expose this as SSLError with a stale reason name,
        # instead of honoring SSLSocket's default suppress_ragged_eofs.
        if "unexpected eof while reading" in str(error).lower():
            return b""
        raise


def read_exact(conn, size):
    """Read a wire field, failing promptly on a truncated message."""
    data = b""
    while len(data) < size:
        chunk = recv_with_ragged_eof(conn, size - len(data))
        if not chunk:
            raise EOFError("Peer closed before completing a message")
        data += chunk
    return data


def read_headers(conn):
    """Read one HTTP header block without consuming the next request."""
    data = b""
    while not data.endswith(b"\r\n\r\n"):
        data += read_exact(conn, 1)
        if len(data) > 65536:
            raise ValueError("HTTP headers too large")
    return data


class LocalServer:
    """Serve one bounded connection, propagating thread errors to the test."""

    def __init__(self, handler, tls_context=None, connections=1):
        self.handler = handler
        self.tls_context = tls_context
        self.connections = connections
        self.errors = []
        self.conn = None
        self.listener = socket.socket()
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(1)
        self.listener.settimeout(5)
        self.port = self.listener.getsockname()[1]
        self.thread = threading.Thread(target=self._serve, daemon=True)

    def _serve(self):
        try:
            for _ in range(self.connections):
                self.conn, _ = self.listener.accept()
                self.conn.settimeout(5)
                if self.tls_context is not None:
                    self.conn = self.tls_context.wrap_socket(
                        self.conn, server_side=True
                    )
                with self.conn:
                    self.handler(self.conn)
        except Exception as error:
            self.errors.append(error)

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, exc_type, exc, traceback):
        self.thread.join(6)
        if self.thread.is_alive() and self.conn is not None:
            self.conn.close()
        self.listener.close()
        self.thread.join(1)
        if exc_type is None:
            assert not self.thread.is_alive(), "Server thread did not terminate"
            if self.errors:
                raise self.errors[0]


def tls12_context(cert_path, key_path, alpn="http/1.1", cipher="AES128-SHA"):
    """Restrict the test peer to a known TLS 1.2 cipher and ALPN selection."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.maximum_version = ssl.TLSVersion.TLSv1_2
    # The library's legacy RSA default needs SECLEVEL=0 on modern OpenSSL.
    # This relaxation applies only to this ephemeral loopback test server.
    context.set_ciphers(cipher + ":@SECLEVEL=0")
    context.load_cert_chain(str(cert_path), str(key_path))
    context.set_alpn_protocols([alpn])
    return context


def h2_frame(kind, flags, stream, payload=b""):
    """Encode a frame independently of the implementation under test."""
    return (
        len(payload).to_bytes(3, "big")
        + struct.pack("!BBI", kind, flags, stream)
        + payload
    )


def tls13_context(cert_path, key_path, alpn="http/1.1", group=None):
    """Use OpenSSL's TLS 1.3 implementation as an independent peer."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.maximum_version = ssl.TLSVersion.TLSv1_3
    context.load_cert_chain(str(cert_path), str(key_path))
    context.set_alpn_protocols([alpn])
    if group is not None:
        context.set_ecdh_curve(group)
    return context


def serve_h2(conn, observed):
    """A minimal H2 peer: observe SETTINGS and return a split DATA response."""
    assert conn.selected_alpn_protocol() == "h2"
    assert read_exact(conn, 24) == b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
    conn.sendall(h2_frame(4, 0, 0))
    while True:
        header = read_exact(conn, 9)
        length = int.from_bytes(header[:3], "big")
        kind, flags, stream = struct.unpack("!BBI", header[3:])
        payload = read_exact(conn, length)
        if kind == 4 and not flags & 1:
            observed["settings"] = dict(struct.iter_unpack("!HI", payload))
            conn.sendall(h2_frame(4, 1, 0))
        elif kind == 8:
            observed["window"] = int.from_bytes(payload, "big")
        elif kind == 1:
            observed["stream"] = stream
            assert flags & 4  # END_HEADERS
            # HPACK static table index 8 is :status = 200.
            conn.sendall(h2_frame(1, 4, stream, b"\x88"))
            conn.sendall(h2_frame(0, 0, stream, b"hello "))
            conn.sendall(h2_frame(0, 1, stream, b"h2"))
            # Drain SETTINGS acknowledgements until the client closes its pool.
            while recv_with_ragged_eof(conn, 4096):
                pass
            return


def serve_h2_serial(
    conn,
    observed,
    count=2,
    goaway=False,
    fragment_ack=False,
    body=b"ok",
    table_size=None,
):
    """Serve consecutive streams while observing preface and stream IDs."""
    assert conn.selected_alpn_protocol() == "h2"
    assert read_exact(conn, 24) == b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
    settings = (
        b"\x00\x01" + table_size.to_bytes(4, "big") if table_size is not None else b""
    )
    conn.sendall(h2_frame(4, 0, 0, settings))
    observed["streams"] = []
    observed["settings"] = 0
    observed["header_blocks"] = []
    observed["window_updates"] = []
    deferred = b""
    while len(observed["streams"]) < count:
        header = read_exact(conn, 9)
        length = int.from_bytes(header[:3], "big")
        kind, flags, stream = struct.unpack("!BBI", header[3:])
        payload = read_exact(conn, length)
        if kind == 4 and not flags & 1:
            observed["settings"] += 1
        elif kind == 8:
            observed["window_updates"].append((stream, int.from_bytes(payload, "big")))
        elif kind == 1:
            assert flags & 4  # END_HEADERS
            observed["streams"].append(stream)
            observed["header_blocks"].append(payload)
            response = deferred + h2_frame(1, 4, stream, b"\x88")
            for offset in range(0, len(body), 16384):
                chunk = body[offset : offset + 16384]
                end_stream = int(offset + len(chunk) == len(body))
                response += h2_frame(0, end_stream, stream, chunk)
            if not body:
                response += h2_frame(0, 1, stream)
            deferred = b""
            if fragment_ack and len(observed["streams"]) == 1 and count > 1:
                ack = h2_frame(4, 1, 0)
                response += ack[:5]
                deferred = ack[5:]
            if goaway and len(observed["streams"]) == count:
                response += h2_frame(7, 0, 0, stream.to_bytes(4, "big") + b"\x00" * 4)
            conn.sendall(response)


def read_cstring(conn):
    """Read a bounded SOCKS4 zero-terminated field."""
    data = b""
    for _ in range(256):
        char = read_exact(conn, 1)
        if char == b"\x00":
            return data
        data += char
    raise ValueError("SOCKS field too long")


def serve_socks(
    conn, observed, version=5, auth=False, reject=False, tunnel_handler=None
):
    """Emulate a SOCKS endpoint and echo tunnel data without external access."""
    if version == 5:
        assert read_exact(conn, 1) == b"\x05"
        methods = read_exact(conn, read_exact(conn, 1)[0])
        method = 2 if auth else 0
        assert method in methods
        conn.sendall(bytes([5, method]))
        if auth:
            assert read_exact(conn, 1) == b"\x01"
            username = read_exact(conn, read_exact(conn, 1)[0])
            password = read_exact(conn, read_exact(conn, 1)[0])
            observed["credentials"] = (username, password)
            conn.sendall(b"\x01\x00")
        assert read_exact(conn, 4) == b"\x05\x01\x00\x03"
        observed["host"] = read_exact(conn, read_exact(conn, 1)[0])
        observed["port"] = int.from_bytes(read_exact(conn, 2), "big")
        reply = bytes([5, 5 if reject else 0, 0, 1]) + b"\x7f\x00\x00\x01\x1f\x90"
    else:
        assert read_exact(conn, 2) == b"\x04\x01"
        observed["port"] = int.from_bytes(read_exact(conn, 2), "big")
        address = read_exact(conn, 4)
        observed["user"] = read_cstring(conn)
        observed["host"] = (
            read_cstring(conn)
            if address == b"\x00\x00\x00\x01"
            else socket.inet_ntoa(address).encode()
        )
        reply = bytes([0, 0x5B if reject else 0x5A]) + b"\x1f\x90\x7f\x00\x00\x01"
    # Separate writes also exercise exact-field reads on the client side.
    for byte in reply:
        conn.sendall(bytes([byte]))
    if not reject:
        if tunnel_handler is not None:
            tunnel_handler(conn)
        else:
            conn.sendall(read_exact(conn, 4))
