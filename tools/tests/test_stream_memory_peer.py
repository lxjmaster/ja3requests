"""Small local checks for the bounded memory-acceptance peer, not benchmarks."""

import http.client
import socket
import ssl
import zlib

import brotli
import pytest

from bench.stream_memory_peer import MemoryPeer
from bench.test_protocol_performance import server_context, tls_config
from ja3requests import Session
from ja3requests.exceptions import ContentDecodingError
from test.integration.conftest import trusted_certificates  # noqa: F401


@pytest.mark.parametrize(
    'overrides',
    [
        {'body_bytes': 32768},
        {'body_bytes': True},
        {'prefix_bytes': 0},
        {'prefix_bytes': 32769},
        {'timeout': 0},
        {'timeout': float('inf')},
        {'encoding': 'unknown'},
        {'protocol': 'http/3'},
        {'protocol': 'h2'},
        {'chunked': 'yes'},
        {'context': object()},
    ],
)
def test_invalid_configuration_rejected_before_listener_creation(overrides):
    parameters = dict(context=None, protocol='http/1.1', body_bytes=131072, timeout=2)
    parameters.update(overrides)
    with pytest.raises(ValueError):
        MemoryPeer(**parameters)


@pytest.mark.parametrize('chunked', [False, True])
def test_plain_http_identity_is_gated_and_framed_on_the_wire(chunked):
    with MemoryPeer(None, 'http/1.1', 131072, 2, chunked=chunked) as peer:
        with socket.create_connection(('127.0.0.1', peer.port), timeout=2) as conn:
            conn.sendall(b'GET /payload HTTP/1.1\r\nHost: localhost\r\n\r\n')
            response = http.client.HTTPResponse(conn)
            response.begin()
            assert response.status == 200
            assert response.chunked is chunked
            prefix = response.read(peer.prefix_bytes)
            assert prefix == b'x' * peer.prefix_bytes
            assert peer.prefix_sent.wait(1)
            assert not peer.records
            conn.settimeout(0.05)
            with pytest.raises(socket.timeout):
                conn.recv(1)
            conn.settimeout(2)
            peer.release_tail()
            assert prefix + response.read() == b'x' * peer.body_bytes
        (record,) = peer.wait_for_records()
        assert record['encoded_body_bytes'] == record['decoded_bytes_sent'] == 131072
        assert record['gate_prefix_bytes_sent'] == 32768
        assert record['max_source_chunk_bytes'] <= 16384
        assert record['tail_released_before_complete'] is True
        assert peer.connections[0]['tls_version'] is None
    assert not peer._thread.is_alive()
    assert not any(worker.is_alive() for worker in peer._workers)


@pytest.mark.parametrize('encoding', ['gzip', 'deflate', 'br'])
def test_compressed_prefix_is_decodable_before_tail_and_sizes_are_separate(encoding):
    with MemoryPeer(None, 'http/1.1', 131072, 2, encoding=encoding) as peer:
        with socket.create_connection(('127.0.0.1', peer.port), timeout=2) as conn:
            conn.sendall(b'GET /payload HTTP/1.1\r\nHost: localhost\r\n\r\n')
            response = http.client.HTTPResponse(conn)
            response.begin()
            assert response.chunked
            assert response.getheader('Content-Encoding') == encoding
            decoder = (
                brotli.Decompressor()
                if encoding == 'br'
                else zlib.decompressobj(31 if encoding == 'gzip' else 15)
            )
            decode = decoder.process if encoding == 'br' else decoder.decompress
            decoded = b''
            encoded_bytes = 0
            while len(decoded) < 16384:
                encoded = response.read1(16384)
                assert encoded
                encoded_bytes += len(encoded)
                decoded += decode(encoded)
            assert peer.prefix_sent.wait(1)
            assert not peer.records
            assert decoded == b'x' * len(decoded)
            peer.release_tail()
            encoded = response.read()
            encoded_bytes += len(encoded)
            decoded += decode(encoded)
            assert decoded == b'x' * peer.body_bytes
            assert decoder.is_finished() if encoding == 'br' else decoder.eof
        (record,) = peer.wait_for_records()
        assert record['encoded_body_bytes'] == encoded_bytes < 131072
        assert record['decoded_bytes_sent'] == 131072
        assert record['tail_released_before_complete'] is True


@pytest.mark.parametrize('version', ['TLSv1.2', 'TLSv1.3'])
@pytest.mark.parametrize('protocol', ['http/1.1', 'h2'])
def test_real_tls_client_consumes_a_gated_body(
    trusted_certificates, monkeypatch, version, protocol
):
    monkeypatch.setenv('SSL_CERT_FILE', str(trusted_certificates.ca_path))
    context = server_context(trusted_certificates, version, protocol)
    with MemoryPeer(context, protocol, 131072, 3) as peer:
        with Session(tls_config=tls_config(version, protocol)) as session:
            with session.get(peer.url, stream=True, timeout=2) as response:
                chunks = response.iter_content(16384)
                first = next(chunks)
                assert first == b'x' * 16384
                assert peer.prefix_sent.wait(1)
                assert not peer.records
                peer.release_tail()
                assert first + b''.join(chunks) == b'x' * peer.body_bytes
        (record,) = peer.wait_for_records()
        assert record['decoded_bytes_sent'] == record['encoded_body_bytes'] == 131072
        assert record['gate_prefix_bytes_sent'] == 32768
        assert record['tail_released_before_complete']
        (connection,) = peer.connections
        assert connection['tls_version'] == version
        assert connection['alpn'] == protocol


@pytest.mark.parametrize(
    'encoding,chunked',
    [
        ('identity', False),
        ('identity', True),
        ('gzip', True),
        ('deflate', True),
        ('br', True),
    ],
)
def test_truncated_http_response_is_rejected_after_the_prefix(encoding, chunked):
    with MemoryPeer(
        None, 'http/1.1', 131072, 2, encoding=encoding, chunked=chunked, truncate=True
    ) as peer:
        with Session(use_pooling=False) as session:
            with session.get(peer.url, stream=True, timeout=1) as response:
                chunks = response.iter_content(16384)
                first = next(chunks)
                assert 0 < len(first) <= 16384 and first == b'x' * len(first)
                peer.release_tail()
                with pytest.raises((ConnectionError, ContentDecodingError)):
                    list(chunks)
        (record,) = peer.wait_for_records()
        assert record['truncated']
        assert record['decoded_bytes_sent'] == 32768 < record['body_bytes']


def test_truncated_h2_response_ends_without_end_stream(
    trusted_certificates, monkeypatch
):
    monkeypatch.setenv('SSL_CERT_FILE', str(trusted_certificates.ca_path))
    context = server_context(trusted_certificates, 'TLSv1.3', 'h2')
    with MemoryPeer(context, 'h2', 131072, 3, truncate=True) as peer:
        with Session(tls_config=tls_config('TLSv1.3', 'h2')) as session:
            with session.get(peer.url, stream=True, timeout=2) as response:
                chunks = response.iter_content(16384)
                assert next(chunks) == b'x' * 16384
                peer.release_tail()
                with pytest.raises((ConnectionError, EOFError)):
                    list(chunks)
        (record,) = peer.wait_for_records()
        assert record['truncated']
        assert record['decoded_bytes_sent'] == 32768


def test_cleanup_wakes_an_unreleased_gate_without_claiming_release():
    with MemoryPeer(None, 'http/1.1', 131072, 2) as peer:
        with socket.create_connection(('127.0.0.1', peer.port), timeout=2) as conn:
            conn.sendall(b'GET /payload HTTP/1.1\r\nHost: localhost\r\n\r\n')
            assert peer.prefix_sent.wait(1)
    assert not peer._release_requested
    assert not peer.records
    assert not peer._thread.is_alive()
    assert not any(worker.is_alive() for worker in peer._workers)


def test_h2_rejects_compression_chunking_and_unaligned_prefix():
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    for options in ({'encoding': 'gzip'}, {'chunked': True}, {'prefix_bytes': 17000}):
        with pytest.raises(ValueError, match='H2 requires'):
            MemoryPeer(context, 'h2', 131072, 2, **options)
