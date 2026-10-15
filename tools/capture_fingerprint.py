"""Capture real browser and installed ja3requests TLS/H2 bytes on loopback.

Python >=3.12, development only. ssl is the independent server; library probes
use the installed package's own TLS engine. See tools/README.md for reproduction.
"""

from __future__ import annotations

import argparse
import base64
from datetime import datetime, timedelta, timezone
from email.parser import BytesParser
import hashlib
from importlib.metadata import version as distribution_version
import ipaddress
import json
import math
import os
from pathlib import Path
import platform
import re
import signal
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import threading
import time
import zipfile

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from hpack import Decoder, Encoder
from hpack.huffman import HuffmanEncoder
from hpack.huffman_constants import REQUEST_CODES, REQUEST_CODES_LENGTH
import psutil

from test.wire_client_hello import decode, grease, profile, reassemble


ROOT = Path(__file__).resolve().parents[1]
PREFACE = b'PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n'
CAPTURE_LIMIT = 1024 * 1024
HEADER_LIMIT = 64 * 1024
PNG = base64.b64decode(
    'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+a9b8AAAAASUVORK5CYII='
)
HTML = (
    b'<!doctype html><html><head><link rel="icon" href="data:,"></head>'
    b'<body data-complete="no"><img src="/pixel.png" '
    b'onload="document.body.dataset.complete=\'yes\'"></body></html>'
)
BODIES = {'/': HTML, '/pixel.png': PNG}


class CaptureError(RuntimeError):
    """An incomplete or unverifiable capture; never a calibration success."""


def require(condition, message):
    if not condition:
        raise CaptureError(message)


def digest(value):
    return hashlib.sha256(value).hexdigest()


def save_json(path, value):
    path.write_text(json.dumps(value, indent=2, ensure_ascii=True) + '\n')


def remaining(deadline):
    value = deadline - time.monotonic()
    require(value > 0, 'Capture absolute deadline exceeded')
    return value


def append_bounded(target, data):
    require(len(target) + len(data) <= CAPTURE_LIMIT, 'Capture exceeds 1 MiB budget')
    target.extend(data)


def frame(kind, flags, stream, payload=b''):
    return (
        len(payload).to_bytes(3, 'big')
        + struct.pack('!BBI', kind, flags, stream)
        + payload
    )


def integer(data, offset, bits):
    require(offset < len(data), 'Truncated HPACK integer')
    value = data[offset] & ((1 << bits) - 1)
    offset += 1
    if value < (1 << bits) - 1:
        return value, offset
    shift = 0
    while True:
        require(offset < len(data) and shift <= 28, 'Invalid HPACK integer')
        byte = data[offset]
        offset += 1
        value += (byte & 127) << shift
        if byte < 128:
            return value, offset
        shift += 7


def string_shape(data, offset):
    require(offset < len(data), 'Truncated HPACK string')
    huffman = bool(data[offset] & 128)
    length, start = integer(data, offset, 7)
    require(start + length <= len(data), 'Truncated HPACK string payload')
    return {'huffman': huffman, 'encoded_length': length}, start + length


def representations(block):
    """Inspect representation choices without decoding strings or dynamic indexes."""
    result = []
    offset = 0
    while offset < len(block):
        byte = block[offset]
        if byte & 128:
            index, offset = integer(block, offset, 7)
            result.append({'kind': 'indexed', 'index': index})
        elif byte & 32 and not byte & 64:
            size, offset = integer(block, offset, 5)
            result.append({'kind': 'table-size', 'size': size})
        else:
            bits = 6 if byte & 64 else 4
            kind = 'incremental' if byte & 64 else ('never' if byte & 16 else 'without')
            index, offset = integer(block, offset, bits)
            entry = {'kind': kind, 'name_index': index}
            if not index:
                entry['name'], offset = string_shape(block, offset)
            entry['value'], offset = string_shape(block, offset)
            result.append(entry)
    return result


class H2Trace:
    """Limited independent peer parser, retaining one HPACK table per connection."""

    def __init__(self):
        self.pending = bytearray()
        self.preface = False
        self.frames = []
        self.requests = []
        self.decoder = Decoder(max_header_list_size=HEADER_LIMIT)
        self.continuation = None
        self.block = bytearray()
        self.header_frame = None

    def feed(self, data):
        append_bounded(self.pending, data)
        completed = []
        if not self.preface:
            require(
                PREFACE.startswith(bytes(self.pending[: len(PREFACE)])),
                'Invalid H2 preface',
            )
            if len(self.pending) < len(PREFACE):
                return completed
            del self.pending[: len(PREFACE)]
            self.preface = True
        while len(self.pending) >= 9:
            size = int.from_bytes(self.pending[:3], 'big')
            require(size <= 16384, 'Client frame exceeds default server MAX_FRAME_SIZE')
            if len(self.pending) < 9 + size:
                break
            raw = bytes(self.pending[: 9 + size])
            del self.pending[: 9 + size]
            kind, flags, stream = struct.unpack('!BBI', raw[3:9])
            stream &= 0x7FFFFFFF
            payload = raw[9:]
            entry = {
                'kind': kind,
                'flags': flags,
                'stream': stream,
                'payload_hex': payload.hex(),
            }
            self.frames.append(entry)
            if self.continuation is not None:
                require(
                    kind == 9 and stream == self.continuation,
                    'Interleaved CONTINUATION',
                )
            if kind == 4:
                require(
                    stream == 0 and (size == 0 if flags & 1 else size % 6 == 0),
                    'Invalid SETTINGS',
                )
                entry['settings'] = [
                    list(pair) for pair in struct.iter_unpack('!HI', payload)
                ]
            elif kind == 8:
                require(size == 4, 'Invalid WINDOW_UPDATE')
                entry['increment'] = int.from_bytes(payload, 'big') & 0x7FFFFFFF
                require(entry['increment'] > 0, 'Zero WINDOW_UPDATE')
            elif kind == 2:
                require(stream != 0 and size == 5, 'Invalid PRIORITY')
                entry['priority'] = self.priority(payload, stream)
            elif kind == 6:
                require(stream == 0 and size == 8, 'Invalid PING')
            elif kind in (1, 9):
                require(stream != 0 and stream % 2 == 1, 'Invalid request stream')
                if kind == 1:
                    require(self.continuation is None, 'Nested header block')
                    self.header_frame = entry
                    if flags & 8:
                        require(
                            payload and payload[0] < len(payload),
                            'Invalid HEADERS padding',
                        )
                        padding = payload[0]
                        payload = payload[1 : len(payload) - padding]
                        entry['padding'] = padding
                    if flags & 32:
                        require(len(payload) >= 5, 'Truncated HEADERS priority')
                        entry['priority'] = self.priority(payload[:5], stream)
                        payload = payload[5:]
                append_bounded(self.block, payload)
                if flags & 4:
                    before = len(self.decoder.header_table.dynamic_entries)
                    headers = self.decoder.decode(bytes(self.block), raw=True)
                    request = {
                        'stream': stream,
                        'flags': self.header_frame['flags'],
                        'priority': self.header_frame.get('priority'),
                        'headers': [
                            [name.hex(), value.hex()] for name, value in headers
                        ],
                        'block_hex': self.block.hex(),
                        'representations': representations(bytes(self.block)),
                        'dynamic_entries_before': before,
                        'dynamic_entries_after': len(
                            self.decoder.header_table.dynamic_entries
                        ),
                    }
                    self.requests.append(request)
                    completed.append(request)
                    self.block.clear()
                    self.continuation = None
                else:
                    self.continuation = stream
        return completed

    @staticmethod
    def priority(payload, stream):
        value, weight = struct.unpack('!IB', payload)
        dependency = value & 0x7FFFFFFF
        require(dependency != stream, 'Self-dependent priority')
        return [dependency, weight + 1, bool(value & 0x80000000)]

    def finish(self):
        require(
            self.preface and not self.pending and self.continuation is None,
            'Truncated H2 trace',
        )


def tls_fields(records):
    hellos = reassemble(records)
    result = []
    for hello in hellos:
        raw = bytes.fromhex(hello['record_hex'])
        parsed = decode(raw)
        summary = profile(raw)
        normalize = lambda value: 'GREASE' if grease(value) else value
        summary['key_shares'] = [
            [normalize(group), size] for group, size in summary['key_shares']
        ]
        extensions = dict(parsed['extensions'])
        signatures = extensions.get(13, b'\0\0')
        summary['signature_algorithms'] = [
            normalize(v[0]) for v in struct.iter_unpack('!H', signatures[2:])
        ]
        summary['supported_versions'] = [
            normalize(v[0])
            for v in struct.iter_unpack('!H', extensions.get(43, b'\0')[1:])
        ]
        alpn = extensions.get(16, b'\0\0')[2:]
        protocols = []
        while alpn:
            size = alpn[0]
            require(size > 0 and len(alpn) >= size + 1, 'Invalid offered ALPN')
            protocols.append(alpn[1 : 1 + size].hex())
            alpn = alpn[1 + size :]
        summary['alpn_hex'] = protocols
        summary['extensions'] = [
            {
                'type': 'GREASE' if grease(kind) else kind,
                'length': len(payload),
                'payload_hex': payload.hex(),
            }
            for kind, payload in parsed['extensions']
        ]
        result.append(
            dict(
                hello,
                fields=summary,
                handshake_sha256=digest(bytes.fromhex(hello['handshake_hex'])),
            )
        )
    return result


def certificate(directory):
    """Owned one-hour CA/leaf; verification stays enabled in library probes."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    issuer = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, 'Fingerprint capture CA')]
    )
    now = datetime.now(timezone.utc)

    def builder(subject, public_key):
        return (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(public_key)
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=1))
            .not_valid_after(now + timedelta(hours=1))
        )

    ca = (
        builder(issuer, ca_key.public_key())
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), True)
        .add_extension(
            x509.KeyUsage(False, False, False, False, False, True, True, False, False),
            True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), False
        )
        .sign(ca_key, hashes.SHA256())
    )
    leaf = (
        builder(
            x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'localhost')]),
            key.public_key(),
        )
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), True)
        .add_extension(
            x509.KeyUsage(True, False, True, False, False, False, False, False, False),
            True,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
            False,
        )
        .add_extension(
            x509.SubjectAlternativeName(
                [
                    x509.DNSName('localhost'),
                    x509.IPAddress(ipaddress.ip_address('127.0.0.1')),
                ]
            ),
            False,
        )
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), False)
        .sign(ca_key, hashes.SHA256())
    )
    paths = [directory / name for name in ('cert.pem', 'key.pem', 'ca.pem')]
    paths[0].write_bytes(leaf.public_bytes(serialization.Encoding.PEM))
    paths[1].touch(mode=0o600)
    paths[1].write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    paths[2].write_bytes(ca.public_bytes(serialization.Encoding.PEM))
    spki = key.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return (*paths, base64.b64encode(hashlib.sha256(spki).digest()).decode())


class Peer:
    """One owned accepted connection, with BIO and plaintext evidence taps."""

    def __init__(self, listener, context, deadline, expected_paths=('/', '/pixel.png')):
        self.listener = listener
        self.context = context
        self.deadline = deadline
        self.expected_paths = tuple(expected_paths)
        self.conn = None
        self.error = None
        self.stop = threading.Event()
        self.trace = H2Trace()
        self.buffers = {
            name: bytearray()
            for name in ('tls_client', 'tls_server', 'h2_client', 'h2_server')
        }
        self.negotiated = {}
        self.responses = []
        self.extra_connections = []
        self.thread = threading.Thread(
            target=self.run, name='fingerprint-peer', daemon=True
        )

    def run(self):
        incoming, outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
        connection = self.context.wrap_bio(incoming, outgoing, server_side=True)
        try:
            while True:
                self.listener.settimeout(remaining(self.deadline))
                self.conn, address = self.listener.accept()
                self.conn.settimeout(remaining(self.deadline))
                first = self.conn.recv(65536)
                if not first:
                    self.extra_connections.append(
                        {
                            'address': list(address),
                            'tls_client_hex': '',
                            'state': 'EOF before TLS',
                        }
                    )
                    self.conn.close()
                    self.conn = None
                    continue
                self.negotiated['address'] = list(address)
                append_bounded(self.buffers['tls_client'], first)
                incoming.write(first)
                break

            def drain():
                while outgoing.pending:
                    data = outgoing.read()
                    append_bounded(self.buffers['tls_server'], data)
                    self.conn.settimeout(remaining(self.deadline))
                    self.conn.sendall(data)

            def receive():
                self.conn.settimeout(remaining(self.deadline))
                data = self.conn.recv(65536)
                if not data:
                    incoming.write_eof()
                    return False
                append_bounded(self.buffers['tls_client'], data)
                incoming.write(data)
                return True

            def write(data):
                append_bounded(self.buffers['h2_server'], data)
                offset = 0
                while offset < len(data):
                    try:
                        offset += connection.write(data[offset:])
                    except ssl.SSLWantReadError:
                        drain()
                        require(receive(), 'EOF during TLS plaintext write')
                    drain()

            while True:
                try:
                    connection.do_handshake()
                    drain()
                    break
                except ssl.SSLWantReadError:
                    drain()
                    require(receive(), 'EOF during TLS handshake')
            self.negotiated.update(
                tls=connection.version(),
                alpn=connection.selected_alpn_protocol(),
                resumed=connection.session_reused,
                cipher=list(connection.cipher()),
            )
            require(
                self.negotiated['tls'] == 'TLSv1.3'
                and self.negotiated['alpn'] == 'h2'
                and not self.negotiated['resumed'],
                'Expected full TLS 1.3 and h2',
            )
            write(frame(4, 0, 0))
            encoder = Encoder()
            processed = 0
            while not self.stop.is_set():
                try:
                    data = connection.read(65536)
                except ssl.SSLWantReadError:
                    drain()
                    if not receive():
                        break
                    continue
                except (ssl.SSLZeroReturnError, ssl.SSLEOFError):
                    break
                if not data:
                    break
                append_bounded(self.buffers['h2_client'], data)
                requests = self.trace.feed(data)
                for item in self.trace.frames[processed:]:
                    if item['kind'] == 4 and not item['flags'] & 1:
                        for identifier, value in item['settings']:
                            if identifier == 1:
                                encoder.header_table_size = value
                        write(frame(4, 1, 0))
                    elif item['kind'] == 6 and not item['flags'] & 1:
                        write(frame(6, 1, 0, bytes.fromhex(item['payload_hex'])))
                processed = len(self.trace.frames)
                for request in requests:
                    pairs = [
                        (bytes.fromhex(k), bytes.fromhex(v))
                        for k, v in request['headers']
                    ]
                    path = next(
                        (v.decode('ascii') for k, v in pairs if k == b':path'), ''
                    )
                    require(
                        any(k == b':method' and v == b'GET' for k, v in pairs),
                        'Expected GET',
                    )
                    body = BODIES.get(path, b'not found')
                    headers = [
                        (b':status', b'200' if path in BODIES else b'404'),
                        (
                            b'content-type',
                            b'image/png' if path == '/pixel.png' else b'text/html',
                        ),
                        (b'content-length', str(len(body)).encode()),
                        (b'cache-control', b'no-store'),
                    ]
                    write(
                        frame(
                            1,
                            4,
                            request['stream'],
                            encoder.encode(headers, huffman=False),
                        )
                    )
                    write(frame(0, 1, request['stream'], body))
                    self.responses.append(
                        {
                            'stream': request['stream'],
                            'path': path,
                            'body_sha256': digest(body),
                        }
                    )
            self.trace.finish()
            require(
                [item['path'] for item in self.responses if item['path'] in BODIES]
                == list(self.expected_paths),
                'Unexpected completed request paths on one connection',
            )
        except Exception as error:
            if not self.stop.is_set() or not self.responses:
                self.error = '%s: %s' % (type(error).__name__, error)
        finally:
            if self.conn is not None:
                self.conn.close()

    def close(self):
        self.stop.set()
        if self.conn is not None:
            try:
                self.conn.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
        else:
            try:
                self.listener.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
        self.thread.join(5)
        require(not self.thread.is_alive(), 'Owned TLS peer survived cleanup')

    def evidence(self):
        result = {
            'negotiated': self.negotiated,
            'frames': self.trace.frames,
            'requests': self.trace.requests,
            'responses': self.responses,
            'peer_error': self.error,
            'peer_joined': not self.thread.is_alive(),
            'extra_connections': self.extra_connections,
        }
        for name, data in self.buffers.items():
            result[name + '_hex'] = data.hex()
            result[name + '_sha256'] = digest(data)
        try:
            result['hellos'] = tls_fields(bytes(self.buffers['tls_client']))
        except (
            ValueError,
            AssertionError,
            CaptureError,
            IndexError,
            struct.error,
        ) as error:
            result['hello_error'] = str(error)
        return result


PROBE_SOURCE = r'''
import asyncio, hashlib, json, pathlib, sys
from importlib.metadata import version
import ja3requests
from ja3requests import AsyncConnectionPool, AsyncSession, Session, TlsConfig
from ja3requests.pool import ConnectionPool

inputs=json.loads(sys.argv[1])
root=pathlib.Path(ja3requests.__file__).resolve().parent
assert root.is_relative_to(pathlib.Path(sys.prefix).resolve())
assert 'site-packages' in root.parts
actual={'ja3requests/'+p.relative_to(root).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
        for p in root.rglob('*.py')}
assert actual == inputs['module_hashes'], 'Installed module hashes differ from wheel'
family,major=inputs['profile'].split(':')
config=TlsConfig.from_browser(family,int(major))
assert config.verify_cert is True
for name,value in inputs['overrides'].items():
    assert isinstance(getattr(type(config),name,None),property), 'Unsupported public option: '+name
    setattr(config,name,value)
results=[]
def check(response,path):
    assert response.status_code == 200
    assert hashlib.sha256(response.content).hexdigest() == inputs['bodies'][path]
    results.append({'path':path,'status':response.status_code,'body_sha256':hashlib.sha256(response.content).hexdigest()})
async def native():
    async with AsyncConnectionPool() as pool:
        async with AsyncSession(tls_config=config,pool=pool) as session:
            session.tls_config.session_cache=None
            for index,(path,headers) in enumerate(inputs['requests']):
                options={'h2_headers_priority': inputs['headers_priorities'][index]} if 'headers_priorities' in inputs else {}
                response=await session.get(inputs['origin']+path,headers=dict(headers),timeout=10,**options)
                check(response,path)
if inputs['kind']=='preflight':
    config.session_cache=None
elif inputs['kind']=='async':
    asyncio.run(native())
else:
    with ConnectionPool() as pool, Session(tls_config=config,pool=pool) as session:
        session.tls_config.session_cache=None
        for index,(path,headers) in enumerate(inputs['requests']):
            options={'h2_headers_priority': inputs['headers_priorities'][index]} if 'headers_priorities' in inputs else {}
            response=session.get(inputs['origin']+path,headers=dict(headers),timeout=10,**options)
            check(response,path)
print(json.dumps({'version':version('ja3requests'),'origin':str(root),'module_hashes':actual,
                  'dependencies':{name:version(name) for name in ('cryptography','brotli')},
                  'verified_certificates':config.verify_cert,'session_cache_disabled':config.session_cache is None,
                  'responses':results}))
'''


def artifact_input(wheel, expected, report_path=None):
    require(wheel.is_file() and wheel.suffix == '.whl', 'Missing wheel input')
    require(bool(re.fullmatch('[0-9a-f]{64}', expected)), 'Invalid expected SHA-256')
    raw = wheel.read_bytes()
    require(digest(raw) == expected, 'Wheel SHA-256 mismatch')
    with zipfile.ZipFile(wheel) as archive:
        names = archive.namelist()
        require(len(names) == len(set(names)), 'Duplicate wheel member')
        modules = {
            name: digest(archive.read(name))
            for name in names
            if name.startswith('ja3requests/') and name.endswith('.py')
        }
        metadata_names = [
            name for name in names if name.endswith('.dist-info/METADATA')
        ]
        require(modules and len(metadata_names) == 1, 'Invalid package wheel')
        metadata = BytesParser().parsebytes(archive.read(metadata_names[0]))
        require(metadata['Name'] == 'ja3requests', 'Wrong wheel package')
    identity = {
        'wheel': wheel.name,
        'wheel_sha256': expected,
        'version': metadata['Version'],
        'module_hashes': modules,
        'source_kind': 'explicit-wheel',
    }
    if report_path is not None:
        report_bytes = report_path.read_bytes()
        report = json.loads(report_bytes)
        require(report.get('status') == 'passed', 'Artifact report did not pass')
        require(
            report.get('artifacts', {}).get(wheel.name, {}).get('sha256') == expected,
            'Report/wheel digest mismatch',
        )
        require(report.get('source_hashes') == modules, 'Report/wheel source mismatch')
        require(
            report.get('contract', {}).get('version') == metadata['Version'],
            'Report version mismatch',
        )
        require(
            report.get('source', {}).get('source_kind')
            in ('commit', 'worktree-snapshot'),
            'Missing report source identity',
        )
        identity.update(
            source=report['source'],
            source_kind=report['source']['source_kind'],
            artifact_report_sha256=digest(report_bytes),
        )
    return identity


def environment():
    result = {
        key: value
        for key, value in os.environ.items()
        if not key.startswith(('PYTHON', 'PIP_', 'PYTEST_', 'COVERAGE_', 'MYPY'))
        and key not in ('VIRTUAL_ENV', '__PYVENV_LAUNCHER__')
    }
    result.update(
        PIP_CONFIG_FILE=os.devnull,
        PIP_INDEX_URL='https://pypi.org/simple',
        PIP_NO_INPUT='1',
        PIP_DISABLE_PIP_VERSION_CHECK='1',
    )
    return result


def stop_group(process):
    """Only a process launched with start_new_session=True is accepted here."""
    if process.poll() is None:
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        os.killpg(process.pid, signal.SIGKILL)
        process.wait(timeout=5)
    # Descendants can outlive their leader; terminate the owned group as well.
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    deadline = time.monotonic() + 5
    while True:
        try:
            os.killpg(process.pid, 0)
        except ProcessLookupError:
            return {
                'pid': process.pid,
                'returncode': process.returncode,
                'group_gone': True,
            }
        require(time.monotonic() < deadline, 'Owned process group survived cleanup')
        threading.Event().wait(0.05)


class OwnedProcesses:
    """Track this child's identities and Chrome processes using its private profile.

    Creation times protect against PID reuse. Profile discovery also sees a
    detached crash handler after its original parent exits; unrelated profiles
    are never selected or signalled.
    """

    def __init__(self, process, arguments):
        self.process = process
        self.profile = next(
            (
                value.split('=', 1)[1]
                for value in arguments
                if value.startswith('--user-data-dir=')
            ),
            None,
        )
        self.known = {}
        try:
            root = psutil.Process(process.pid)
            self.known[(root.pid, root.create_time())] = root
        except psutil.NoSuchProcess:
            pass
        self.stop = threading.Event()
        self.error = None
        self.scan()
        self.thread = threading.Thread(
            target=self.watch, name='fingerprint-processes', daemon=True
        )
        self.thread.start()

    def scan(self):
        candidates = list(
            psutil.process_iter(['pid', 'ppid', 'create_time', 'cmdline'])
        )
        owned = {
            process.info['pid']
            for process in candidates
            if (process.info['pid'], process.info['create_time']) in self.known
        }
        changed = True
        while changed:
            changed = False
            for process in candidates:
                info = process.info
                profile_owned = self.profile is not None and any(
                    value.endswith('=' + self.profile)
                    or ('=' + self.profile + '/') in value
                    for value in info['cmdline'] or []
                )
                if info['pid'] in owned or info['ppid'] in owned or profile_owned:
                    if info['pid'] not in owned:
                        owned.add(info['pid'])
                        changed = True
                    self.known[(info['pid'], info['create_time'])] = process

    def watch(self):
        try:
            while not self.stop.wait(0.02):
                self.scan()
        except Exception as error:
            self.error = str(error)

    def close(self):
        self.stop.set()
        self.thread.join(5)
        require(
            not self.thread.is_alive() and self.error is None,
            'Owned descendant observation failed: ' + str(self.error),
        )
        self.scan()
        result = stop_group(self.process)
        for process in self.known.values():
            try:
                process.kill()
            except psutil.NoSuchProcess:
                pass
        _, alive = psutil.wait_procs(list(self.known.values()), timeout=5)
        alive = [
            process
            for process in alive
            if process.is_running() and process.status() != psutil.STATUS_ZOMBIE
        ]
        require(not alive, 'Owned descendants survived cleanup')
        result.update(
            descendants_gone=True,
            observed_processes=[
                {'pid': pid, 'created': created} for pid, created in sorted(self.known)
            ],
        )
        return result


def subprocess_checked(arguments, cwd, env, log, timeout=600):
    with log.open('wb') as stream:
        process = subprocess.Popen(
            arguments,
            cwd=cwd,
            env=env,
            stdout=stream,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
        try:
            process.wait(timeout=timeout)
            require(process.returncode == 0, 'Subprocess failed: see ' + str(log))
        finally:
            stop_group(process)


def drain_preconnections(listener):
    """After the client is reaped, preserve and close its unused queued sockets."""
    extra = []
    listener.setblocking(False)
    try:
        for _ in range(16):
            try:
                conn, address = listener.accept()
            except BlockingIOError:
                return extra
            data = bytearray()
            state = 'EOF after client reaped; no server handshake'
            with conn:
                conn.settimeout(0.5)
                try:
                    while True:
                        piece = conn.recv(65536)
                        if not piece:
                            break
                        append_bounded(data, piece)
                except (TimeoutError, ConnectionResetError):
                    state = 'Unused preconnection closed after client reaped'
            extra.append(
                {
                    'address': list(address),
                    'tls_client_hex': data.hex(),
                    'tls_client_sha256': digest(data),
                    'state': state,
                    'calibration_connection': False,
                }
            )
        raise CaptureError('Too many queued preconnections')
    finally:
        listener.setblocking(True)


def run_case(
    label,
    arguments,
    listener,
    context,
    output,
    env,
    cwd,
    deadline_seconds=30,
    validate=None,
    expected_paths=('/', '/pixel.png'),
):
    started = datetime.now(timezone.utc).isoformat()
    deadline = time.monotonic() + deadline_seconds
    peer = Peer(listener, context, deadline, expected_paths=expected_paths)
    result = {'case': label, 'started_at': started, 'status': 'failed'}
    process = None
    owner = None
    try:
        with (output / (label + '.stdout.log')).open('wb') as stdout, (
            output / (label + '.stderr.log')
        ).open('wb') as stderr:
            peer.thread.start()
            process = subprocess.Popen(
                arguments,
                env=env,
                cwd=cwd,
                stdout=stdout,
                stderr=stderr,
                start_new_session=True,
            )
            owner = OwnedProcesses(process, arguments)
            process.wait(timeout=remaining(deadline))
            peer.thread.join(timeout=remaining(deadline))
            require(process.returncode == 0, 'Client process failed: ' + label)
            require(
                not peer.thread.is_alive(), 'Client exited but TLS peer did not finish'
            )
            require(peer.error is None, peer.error or '')
            if validate is not None:
                result.update(validate())
            result['status'] = 'passed'
    except Exception as error:
        result['error'] = '%s: %s' % (type(error).__name__, error)
    finally:
        try:
            try:
                if process is not None:
                    result['process_cleanup'] = (
                        owner.close() if owner is not None else stop_group(process)
                    )
            finally:
                peer.close()
                peer.extra_connections.extend(drain_preconnections(listener))
        except Exception as error:
            result['status'] = 'failed'
            result['cleanup_error'] = str(error)
        result.update(peer.evidence())
        if 'hello_error' in result:
            result['status'] = 'failed'
        result['elapsed_seconds'] = (
            datetime.now(timezone.utc) - datetime.fromisoformat(started)
        ).total_seconds()
        save_json(output / (label + '.json'), result)
    require(
        result['status'] == 'passed',
        result.get('error', result.get('cleanup_error', label + ' failed')),
    )
    return result


def validate_browser(output, label):
    dom = (output / (label + '.stdout.log')).read_text()
    require('data-complete="yes"' in dom, 'Browser image-load DOM marker missing')
    return {'dom_complete': True, 'dom_sha256': digest(dom.encode())}


def validate_probe(output, label, identity):
    probe = json.loads((output / (label + '.stdout.log')).read_text())
    require(
        probe['version'] == identity['version']
        and probe['verified_certificates']
        and probe['session_cache_disabled'],
        'Probe package/verification state mismatch',
    )
    require(
        probe['module_hashes'] == identity['module_hashes'],
        'Installed source identity mismatch',
    )
    return {'installed': probe, 'trust': 'verified owned CA via child SSL_CERT_FILE'}


def browser_inputs(capture):
    overrides = {}
    settings = next(
        item['settings']
        for item in capture['frames']
        if item['kind'] == 4 and not item['flags'] & 1
    )
    overrides['h2_settings'] = settings
    windows = [
        item['increment']
        for item in capture['frames']
        if item['kind'] == 8 and item['stream'] == 0
    ]
    overrides['h2_window_update'] = windows[0] if windows else 0
    requests = []
    for request in capture['requests']:
        pairs = [
            (bytes.fromhex(k).decode('ascii'), bytes.fromhex(v).decode('ascii'))
            for k, v in request['headers']
        ]
        path = next(value for name, value in pairs if name == ':path')
        if path in BODIES:
            pseudo = [name for name, _ in pairs if name.startswith(':')]
            overrides.setdefault('h2_pseudo_header_order', pseudo)
            regular = [
                [name, value] for name, value in pairs if not name.startswith(':')
            ]
            require(
                len({name for name, _ in regular}) == len(regular),
                'Probe mapping cannot express duplicate regular headers',
            )
            requests.append([path, regular])
    require(
        [path for path, _ in requests] == ['/', '/pixel.png'],
        'Missing browser scenario',
    )
    return overrides, requests


def compare(captures):
    """Compare all browser samples; variability never becomes a missing feature."""
    browsers = [case for case in captures if case['case'].startswith('browser')]
    require(browsers, 'Missing browser comparison samples')
    rows = []

    def row(client, name, select, mismatch):
        values = [select(browser) for browser in browsers]
        actual = select(client)
        stable = all(value == values[0] for value in values)
        status = (
            ('matched' if actual == values[0] else mismatch)
            if stable
            else 'variable/undetermined'
        )
        rows.append(
            {
                'case': client['case'],
                'field': name,
                'status': status,
                'browser_stable': stable,
                'browser_samples': values,
                'client': actual,
            }
        )

    for client in captures:
        if client['case'].startswith('browser'):
            continue
        for name in (
            'ciphers',
            'extension_types',
            'groups',
            'key_shares',
            'signature_algorithms',
            'supported_versions',
            'session_id_length',
            'compression',
            'point_formats',
            'version',
            'alpn_hex',
        ):
            mismatch = (
                'missing functioning negotiation'
                if name in ('ciphers', 'groups', 'key_shares')
                else 'variable/undetermined'
            )
            row(
                client,
                'tls.' + name,
                lambda case, name=name: case['hellos'][0]['fields'][name],
                mismatch,
            )
        row(
            client,
            'tls.hello_count',
            lambda case: len(case['hellos']),
            'variable/undetermined',
        )
        row(
            client,
            'tls.record_versions',
            lambda case: case['hellos'][0]['record_versions'],
            'configurable difference',
        )
        kinds = sorted(
            {
                extension['type']
                for case in browsers + [client]
                for extension in case['hellos'][0]['fields']['extensions']
            },
            key=str,
        )
        for kind in kinds:

            def content(case, kind=kind):
                fields = case['hellos'][0]['fields']
                result = []
                for extension in fields['extensions']:
                    if extension['type'] != kind:
                        continue
                    shape = {'length': extension['length']}
                    if kind in (10, 13, 43, 51):
                        field = {
                            10: 'groups',
                            13: 'signature_algorithms',
                            43: 'supported_versions',
                            51: 'key_shares',
                        }[kind]
                        shape['normalized'] = fields[field]
                    elif kind != 'GREASE':
                        shape['payload_hex'] = extension['payload_hex']
                    result.append(shape)
                return result

            missing = not content(client) or any(not content(case) for case in browsers)
            row(
                client,
                'tls.extension.' + str(kind),
                content,
                'missing control' if missing else 'variable/undetermined',
            )
        for name, select in (
            ('preface', lambda c: c['h2_client_hex'].startswith(PREFACE.hex())),
            (
                'settings',
                lambda c: [
                    f['settings']
                    for f in c['frames']
                    if f['kind'] == 4 and not f['flags'] & 1
                ],
            ),
            (
                'window',
                lambda c: [
                    f['increment']
                    for f in c['frames']
                    if f['kind'] == 8 and f['stream'] == 0
                ],
            ),
            (
                'priority',
                lambda c: [
                    [f['stream'], f['priority']] for f in c['frames'] if f['kind'] == 2
                ],
            ),
        ):
            row(client, 'h2.' + name, select, 'configurable difference')
        row(
            client,
            'h2.request_count',
            lambda case: len(case['requests']),
            'variable/undetermined',
        )
        require(
            all(len(case['requests']) == len(client['requests']) for case in browsers),
            'Unequal request counts cannot be compared by position',
        )
        for index in range(len(client['requests'])):
            row(
                client,
                'request%d.header_order' % (index + 1),
                lambda case, index=index: [
                    pair[0] for pair in case['requests'][index]['headers']
                ],
                'configurable difference',
            )
            for name in (
                'stream',
                'flags',
                'priority',
                'headers',
                'representations',
                'dynamic_entries_before',
                'dynamic_entries_after',
                'block_hex',
            ):
                row(
                    client,
                    'request%d.%s' % (index + 1, name),
                    lambda case, index=index, name=name: case['requests'][index][name],
                    (
                        'configurable difference'
                        if name == 'headers'
                        else 'missing control'
                    ),
                )
    return {
        'browser_cases': [case['case'] for case in browsers],
        'normalization': 'Random/session bytes are excluded from structure; GREASE slots and payload lengths retained; key-share groups/sizes retained; original bytes retained. Opaque extension payload differences remain undetermined.',
        'rows': rows,
        'full_browser_identity': False,
    }


def huffman_acceptance(captures):
    """Independent accepted-byte assertions for the selected F2 policy only."""
    browsers = [case for case in captures if case['case'].startswith('browser')]
    clients = [case for case in captures if case['case'] in ('sync', 'async')]
    require(
        len(browsers) == 3 and len(clients) == 2, 'F2 requires the full capture series'
    )
    encoder = HuffmanEncoder(REQUEST_CODES, REQUEST_CODES_LENGTH)
    counts = {}
    for client in clients:
        require(
            all(
                client['requests'][0]['block_hex']
                == browser['requests'][0]['block_hex']
                for browser in browsers
            ),
            'F2 first-request HPACK differs from browser',
        )
        checked = 0
        for request in client['requests']:
            representations = [
                item
                for item in request['representations']
                if item['kind'] != 'table-size'
            ]
            require(
                len(representations) == len(request['headers']),
                'HPACK representation/header association mismatch',
            )
            for representation, pair in zip(representations, request['headers']):
                for field, index in (('name', 0), ('value', 1)):
                    if field not in representation:
                        continue
                    raw = bytes.fromhex(pair[index])
                    encoded = encoder.encode(raw)
                    used = len(encoded) < len(raw)
                    require(
                        representation[field]
                        == {
                            'huffman': used,
                            'encoded_length': len(encoded) if used else len(raw),
                        },
                        'F2 literal does not follow the independently verified policy',
                    )
                    checked += 1
        counts[client['case']] = checked
    return {
        'status': 'passed',
        'first_request_exact': True,
        'literal_checks': counts,
        'scope': 'Benefit-based string encoding; indexing and HEADERS priority remain separate.',
    }


def capture(args):
    identity = artifact_input(args.wheel, args.wheel_sha256, args.artifact_report)
    huffman = getattr(args, 'h2_huffman', False)
    require(
        not huffman or (not args.browser_only and args.browser_samples == 3),
        'F2 Huffman acceptance requires the full capture series',
    )
    require(
        re.fullmatch('[a-z]+:[0-9]+', args.client_profile),
        'Explicit family:major profile required',
    )
    require(
        math.isfinite(args.deadline) and 0 < args.deadline <= 60,
        'Invalid case deadline',
    )
    version = subprocess.check_output(
        [str(args.chrome), '--version'], text=True, timeout=15
    ).strip()
    require(
        re.fullmatch(r'Google Chrome 155\.[0-9.]+', version),
        'Frozen target requires Chrome 155',
    )
    args.output.mkdir(parents=True, exist_ok=False)
    manifest = {
        'status': 'running',
        'browser': version,
        'platform': platform.platform(),
        'artifact': identity,
        'client_profile': args.client_profile,
        'python': sys.version,
        'openssl': ssl.OPENSSL_VERSION,
        'dependencies': {
            name: distribution_version(name)
            for name in ('hpack', 'cryptography', 'psutil')
        },
        'budgets': {
            'bytes_per_direction': CAPTURE_LIMIT,
            'decoded_headers': HEADER_LIMIT,
            'case_seconds': args.deadline,
        },
        'tool_hashes': {
            name: digest((ROOT / name).read_bytes())
            for name in (
                'tools/capture_fingerprint.py',
                'test/wire_client_hello.py',
                'requirements-capture.txt',
                'tools/tests/test_fingerprint_capture.py',
                'test/test_browser_capture.py',
            )
        },
        'probe_source_sha256': digest(PROBE_SOURCE.encode()),
        'cases': [],
        'cleanup': {},
    }
    save_json(args.output / 'manifest.json', manifest)
    source_directory = args.output / 'tool-source'
    source_directory.mkdir()
    for name, expected in manifest['tool_hashes'].items():
        raw = (ROOT / name).read_bytes()
        require(digest(raw) == expected, 'Tool source changed during snapshot')
        destination = source_directory / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(raw)
    staging_path = None
    captures = []
    try:
        with tempfile.TemporaryDirectory(
            prefix='ja3requests-fingerprint-'
        ) as directory:
            staging = Path(directory)
            staging_path = staging
            cert, key, ca, spki = certificate(staging)
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.minimum_version = context.maximum_version = ssl.TLSVersion.TLSv1_3
            context.set_alpn_protocols(['h2'])
            context.num_tickets = 0
            context.load_cert_chain(str(cert), str(key))
            with socket.socket() as listener:
                listener.bind(('127.0.0.1', 0))
                listener.listen(8)
                origin = 'https://localhost:%d' % listener.getsockname()[1]
                manifest.update(
                    origin=origin,
                    certificate_sha256=digest(cert.read_bytes()),
                    server_settings=[],
                    server_tickets=0,
                    bodies={path: digest(body) for path, body in BODIES.items()},
                )
                python = None
                if not args.browser_only:
                    probe_env = staging / 'probe-env'
                    subprocess_checked(
                        [sys.executable, '-m', 'venv', str(probe_env)],
                        staging,
                        environment(),
                        args.output / 'venv.log',
                    )
                    python = probe_env / 'bin' / 'python'
                    subprocess_checked(
                        [
                            str(python),
                            '-I',
                            '-m',
                            'pip',
                            'install',
                            '--index-url',
                            'https://pypi.org/simple',
                            str(args.wheel),
                        ],
                        staging,
                        environment(),
                        args.output / 'install.log',
                    )
                    preflight = dict(
                        module_hashes=identity['module_hashes'],
                        profile=args.client_profile,
                        kind='preflight',
                        overrides={'h2_huffman': True} if huffman else {},
                        requests=[],
                        origin=origin,
                        bodies={},
                    )
                    subprocess_checked(
                        [str(python), '-I', '-c', PROBE_SOURCE, json.dumps(preflight)],
                        staging,
                        environment(),
                        args.output / 'probe-preflight.log',
                        timeout=30,
                    )
                for number in range(1, args.browser_samples + 1):
                    require(
                        subprocess.check_output(
                            [str(args.chrome), '--version'], text=True, timeout=15
                        ).strip()
                        == version,
                        'Browser version changed during capture',
                    )
                    with tempfile.TemporaryDirectory(
                        prefix='chrome-', dir=staging
                    ) as profile_dir:
                        flags = [
                            '--headless',
                            '--disable-background-networking',
                            '--disable-component-update',
                            '--disable-sync',
                            '--no-first-run',
                            '--no-default-browser-check',
                            '--no-proxy-server',
                            '--disable-breakpad',
                            '--disable-crash-reporter',
                            '--user-data-dir=' + profile_dir,
                            '--ignore-certificate-errors-spki-list=' + spki,
                            '--dump-dom',
                            origin + '/',
                        ]
                        item = run_case(
                            'browser-%d' % number,
                            [str(args.chrome)] + flags,
                            listener,
                            context,
                            args.output,
                            environment(),
                            staging,
                            args.deadline,
                            validate=lambda: validate_browser(
                                args.output, 'browser-%d' % number
                            ),
                        )
                        item.update(
                            browser=version,
                            flags=[
                                flag
                                for flag in flags
                                if not flag.startswith('--user-data-dir=')
                            ],
                            trust='owned leaf SPKI exception',
                            dom_complete=True,
                            profile_removed=False,
                        )
                        save_json(args.output / ('browser-%d.json' % number), item)
                    item['profile_removed'] = not Path(profile_dir).exists()
                    save_json(args.output / ('browser-%d.json' % number), item)
                    captures.append(item)
                    manifest['cases'].append(item['case'])
                    save_json(args.output / 'manifest.json', manifest)
                if not args.browser_only:
                    overrides, requests = browser_inputs(captures[0])
                    if huffman:
                        overrides['h2_huffman'] = True
                    manifest.update(overrides=overrides, requests=requests)
                    inputs = dict(
                        module_hashes=identity['module_hashes'],
                        profile=args.client_profile,
                        overrides=overrides,
                        requests=requests,
                        origin=origin,
                        bodies=manifest['bodies'],
                    )
                    env = environment()
                    env['SSL_CERT_FILE'] = str(ca)
                    for kind in ('sync', 'async'):
                        item = run_case(
                            kind,
                            [
                                str(python),
                                '-I',
                                '-c',
                                PROBE_SOURCE,
                                json.dumps(dict(inputs, kind=kind)),
                            ],
                            listener,
                            context,
                            args.output,
                            env,
                            staging,
                            args.deadline,
                            validate=lambda: validate_probe(
                                args.output, kind, identity
                            ),
                        )
                        save_json(args.output / (kind + '.json'), item)
                        captures.append(item)
                        manifest['cases'].append(kind)
                    save_json(args.output / 'comparison.json', compare(captures))
                    if huffman:
                        manifest['huffman_acceptance'] = huffman_acceptance(captures)
                manifest['status'] = 'passed'
    except Exception as error:
        manifest.update(status='failed', error='%s: %s' % (type(error).__name__, error))
    finally:
        manifest['cleanup']['temporary_root_removed'] = (
            staging_path is not None and not staging_path.exists()
        )
        manifest['cleanup']['listener_closed'] = (
            'listener' in locals() and listener.fileno() == -1
        )
        if not all(manifest['cleanup'].values()):
            manifest['status'] = 'failed'
        save_json(args.output / 'manifest.json', manifest)
    require(
        manifest['status'] == 'passed',
        manifest.get('error', 'Capture cleanup incomplete'),
    )
    return manifest


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--chrome', type=Path, required=True)
    parser.add_argument('--wheel', type=Path, required=True)
    parser.add_argument('--wheel-sha256', required=True)
    parser.add_argument('--artifact-report', type=Path)
    parser.add_argument('--client-profile', required=True)
    parser.add_argument(
        '--h2-huffman',
        action='store_true',
        help='Select and independently accept the F2 benefit-based HPACK string policy',
    )
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--browser-samples', type=int, default=3, choices=(1, 3))
    parser.add_argument(
        '--browser-only', action='store_true', help='First S1 feasibility trial only'
    )
    parser.add_argument('--deadline', type=float, default=30)
    args = parser.parse_args(argv)
    args.wheel = args.wheel.resolve()
    args.chrome = args.chrome.resolve()
    args.output = args.output.absolute()
    try:
        result = capture(args)
        print(
            json.dumps(
                {
                    'status': result['status'],
                    'cases': result['cases'],
                    'output': str(args.output),
                }
            )
        )
        return 0
    except (CaptureError, OSError, ValueError, subprocess.SubprocessError) as error:
        print('%s: %s' % (type(error).__name__, error), file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
