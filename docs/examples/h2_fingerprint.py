"""Run the fingerprint guide's exact snippet over real local TLS and inspect H2.

ssl is used only by the independent server. The client uses the project's TLS
handshake/record engine and verifies an ephemeral local certificate.
"""

import datetime
import ipaddress
import os
from pathlib import Path
import re
import socket
import ssl
import struct
from tempfile import TemporaryDirectory
import threading

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from ja3requests.protocol.h2.hpack import HPACKDecoder


def read_exact(conn, size):
    result = b''
    while len(result) < size:
        piece = conn.recv(size - len(result))
        if not piece:
            raise EOFError('Truncated local H2 frame')
        result += piece
    return result


def frame(kind, flags, stream, payload=b''):
    return (
        len(payload).to_bytes(3, 'big')
        + struct.pack('!BBI', kind, flags, stream)
        + payload
    )


def certificate(directory):
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'Local demo CA')])
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'localhost')])
    now = datetime.datetime.now(datetime.timezone.utc)

    def builder(name, public_key):
        return (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(issuer)
            .public_key(public_key)
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(minutes=1))
            .not_valid_after(now + datetime.timedelta(hours=1))
        )

    ca = (
        builder(issuer, ca_key.public_key())
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(False, False, False, False, False, True, True, False, False),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )
    cert = (
        builder(subject, key.public_key())
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(True, False, True, False, False, False, False, False, False),
            critical=True,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.SubjectAlternativeName(
                [x509.IPAddress(ipaddress.ip_address('127.0.0.1'))]
            ),
            critical=False,
        )
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False
        )
        .sign(ca_key, hashes.SHA256())
    )
    cert_path, key_path, ca_path = (
        directory / 'cert.pem',
        directory / 'key.pem',
        directory / 'ca.pem',
    )
    ca_path.write_bytes(ca.public_bytes(serialization.Encoding.PEM))
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.touch(mode=0o600)
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    return cert_path, key_path, ca_path


def main():
    errors, observed = [], []
    with TemporaryDirectory(prefix='ja3requests-h2-demo-') as directory:
        cert_path, key_path, ca_path = certificate(Path(directory))
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        context.maximum_version = ssl.TLSVersion.TLSv1_3
        context.load_cert_chain(str(cert_path), str(key_path))
        context.set_alpn_protocols(['h2'])
        with socket.socket() as listener:
            listener.bind(('127.0.0.1', 0))
            listener.listen(1)
            listener.settimeout(5)

            def serve():
                try:
                    raw, _ = listener.accept()
                    raw.settimeout(5)
                    with context.wrap_socket(raw, server_side=True) as conn:
                        assert conn.version() == 'TLSv1.3'
                        assert conn.selected_alpn_protocol() == 'h2'
                        assert (
                            read_exact(conn, 24) == b'PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n'
                        )
                        conn.sendall(frame(4, 0, 0))
                        while True:
                            header = read_exact(conn, 9)
                            size = int.from_bytes(header[:3], 'big')
                            kind, flags, stream = struct.unpack('!BBI', header[3:])
                            payload = read_exact(conn, size)
                            if kind in (4, 8, 2) and not flags & 1:
                                observed.append((kind, stream, payload))
                            if kind == 4 and not flags & 1:
                                conn.sendall(frame(4, 1, 0))
                            if kind == 1:
                                assert flags & 5 == 5
                                names = [
                                    name
                                    for name, _ in HPACKDecoder().decode_headers(
                                        payload
                                    )
                                ]
                                assert names[:4] == [
                                    ':method',
                                    ':path',
                                    ':authority',
                                    ':scheme',
                                ]
                                assert stream == 1
                                conn.sendall(frame(1, 5, stream, b'\x88'))
                                return
                except Exception as error:
                    errors.append(error)

            worker = threading.Thread(target=serve, daemon=True)
            worker.start()
            previous_trust = os.environ.get('SSL_CERT_FILE')
            try:
                os.environ['SSL_CERT_FILE'] = str(ca_path)
                guide = Path(__file__).resolve().parents[1] / 'fingerprints.md'
                blocks = re.findall(
                    r'^```python\s*\n(.*?)^```\s*$',
                    guide.read_text(),
                    re.MULTILINE | re.DOTALL,
                )
                code = next(
                    block for block in blocks if 'config.h2_settings =' in block
                )
                url = 'https://127.0.0.1:%d/' % listener.getsockname()[1]
                namespace = {}
                exec(
                    compile(
                        code.replace('https://example.com/', url), str(guide), 'exec'
                    ),
                    namespace,
                )
                assert namespace['response'].status_code == 200
            finally:
                if previous_trust is None:
                    os.environ.pop('SSL_CERT_FILE', None)
                else:
                    os.environ['SSL_CERT_FILE'] = previous_trust
                worker.join(6)
            assert not worker.is_alive(), 'Local TLS server survived cleanup'
            if errors:
                raise errors[0]
    assert observed == [
        (
            4,
            0,
            b''.join(
                struct.pack('!HI', identifier, value)
                for identifier, value in [(1, 65536), (2, 0), (4, 6291456), (6, 262144)]
            ),
        ),
        (8, 0, struct.pack('!I', 15663105)),
        (2, 3, struct.pack('!IB', 0, 200)),
        (2, 5, struct.pack('!IB', 0x80000003, 100)),
    ]
    print(
        'PASS: guide snippet completed verified TLS 1.3, exact SETTINGS/window/PRIORITY/pseudo-header order'
    )


if __name__ == '__main__':
    main()
