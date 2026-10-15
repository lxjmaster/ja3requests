"""Independent vectors and actual lifetime/failure boundaries for the collector."""

import json
from pathlib import Path
import subprocess
import socket
import ssl
import struct
import sys
import time
import zipfile

from hpack import Encoder
import pytest

from test.wire_client_hello import decode, reassemble
from tools import capture_fingerprint as capture


ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture
def wheel(tmp_path):
    path = tmp_path / 'ja3requests-2.3.0-py3-none-any.whl'
    with zipfile.ZipFile(path, 'w') as archive:
        archive.writestr('ja3requests/__init__.py', b'VALUE = 1\n')
        archive.writestr(
            'ja3requests-2.3.0.dist-info/METADATA',
            'Name: ja3requests\nVersion: 2.3.0\n',
        )
    return path


def test_artifact_identity_and_report_disagreement(wheel, tmp_path):
    sha = capture.digest(wheel.read_bytes())
    actual = capture.artifact_input(wheel, sha)
    report = {
        'status': 'passed',
        'artifacts': {wheel.name: {'sha256': sha}},
        'source_hashes': actual['module_hashes'],
        'contract': {'version': '2.3.0'},
        'source': {
            'source_kind': 'worktree-snapshot',
            'files': {
                'ja3requests/__init__.py': actual['module_hashes'][
                    'ja3requests/__init__.py'
                ]
            },
        },
    }
    path = tmp_path / 'verification.json'
    path.write_text(json.dumps(report))
    assert (
        capture.artifact_input(wheel, sha, path)['source_kind'] == 'worktree-snapshot'
    )
    for field, value in [
        ('status', 'failed'),
        ('source_hashes', {}),
        ('source', {}),
        ('contract', {'version': '2.4.0'}),
    ]:
        bad = dict(report, **{field: value})
        path.write_text(json.dumps(bad))
        with pytest.raises(capture.CaptureError):
            capture.artifact_input(wheel, sha, path)
    with pytest.raises(capture.CaptureError, match='SHA-256 mismatch'):
        capture.artifact_input(wheel, '0' * 64)


def test_client_hello_reassembly_preserves_original_record_api():
    sample = json.loads((ROOT / 'test/fixtures/chrome154_macos_hello.json').read_text())
    raw = bytes.fromhex(sample['record_hex'])
    body = raw[5:]
    records = b''.join(
        b'\x16\x03\x01' + len(piece).to_bytes(2, 'big') + piece
        for piece in (body[:2], body[2:41], body[41:])
    )
    result = reassemble(records)
    assert result[0]['handshake_hex'] == body.hex()
    assert result[0]['record_versions'] == ['0301'] * 3
    assert decode(bytes.fromhex(result[0]['record_hex'])) == decode(raw)
    for invalid in (records[:-1], records[:4], b'\x16\x03\x01\x00\x02' + body[:2]):
        with pytest.raises(ValueError, match='Truncated'):
            reassemble(invalid)


def test_rfc7541_dynamic_table_vectors_across_fragmented_requests():
    # RFC 7541 C.3.1/C.3.2: static indexes, literal authority, then reused authority.
    first = bytes.fromhex('828684410f7777772e6578616d706c652e636f6d')
    second = bytes.fromhex('828684be58086e6f2d6361636865')
    parser = capture.H2Trace()
    wire = capture.PREFACE + capture.frame(
        4, 0, 0, struct.pack('!HIHI', 1, 4096, 1, 4096)
    )
    wire += capture.frame(1, 5, 1, first) + capture.frame(1, 5, 3, second)
    complete = []
    for byte in wire:
        complete.extend(parser.feed(bytes([byte])))
    parser.finish()
    assert parser.frames[0]['settings'] == [[1, 4096], [1, 4096]]
    headers = [
        [(bytes.fromhex(k), bytes.fromhex(v)) for k, v in r['headers']]
        for r in complete
    ]
    assert headers[0] == [
        (b':method', b'GET'),
        (b':scheme', b'http'),
        (b':path', b'/'),
        (b':authority', b'www.example.com'),
    ]
    assert headers[1] == headers[0] + [(b'cache-control', b'no-cache')]
    assert complete[0]['dynamic_entries_before'] == 0
    assert complete[1]['dynamic_entries_before'] == 1
    assert complete[1]['representations'][3] == {'kind': 'indexed', 'index': 62}


def test_continuation_padding_priority_and_huffman():
    block = Encoder().encode([(b':method', b'GET'), (b':path', b'/pixel.png')])
    parser = capture.H2Trace()
    parser.feed(capture.PREFACE)
    assert (
        parser.feed(
            capture.frame(
                1,
                8 | 32 | 1,
                5,
                b'\x02' + struct.pack('!IB', 0x80000003, 200) + block[:1] + b'\0\0',
            )
        )
        == []
    )
    result = parser.feed(capture.frame(9, 4, 5, block[1:]))
    parser.finish()
    assert result[0]['priority'] == [3, 201, True]
    assert bytes.fromhex(result[0]['headers'][1][1]) == b'/pixel.png'
    assert result[0]['representations'][1]['value']['huffman'] is True


@pytest.mark.parametrize(
    'ending', [capture.frame(6, 0, 0, b'12345678'), capture.frame(9, 4, 3, b'\x82')]
)
def test_rejects_interleaved_or_wrong_stream_continuation(ending):
    parser = capture.H2Trace()
    parser.feed(capture.PREFACE + capture.frame(1, 1, 1, b'\x82'))
    with pytest.raises(capture.CaptureError, match='Interleaved CONTINUATION'):
        parser.feed(ending)


def test_partial_trace_and_budget_are_failures():
    parser = capture.H2Trace()
    parser.feed(capture.PREFACE + b'\0')
    with pytest.raises(capture.CaptureError, match='Truncated'):
        parser.finish()
    with pytest.raises(capture.CaptureError, match='budget'):
        capture.append_bounded(bytearray(capture.CAPTURE_LIMIT), b'x')
    with pytest.raises(capture.CaptureError, match='deadline'):
        capture.remaining(time.monotonic() - 1)
    with pytest.raises(capture.CaptureError, match='Truncated HPACK'):
        capture.representations(b'\x40')


@pytest.fixture
def peer_context(tmp_path):
    cert, key, ca, _ = capture.certificate(tmp_path)
    server = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server.minimum_version = server.maximum_version = ssl.TLSVersion.TLSv1_3
    server.set_alpn_protocols(['h2'])
    server.num_tickets = 0
    server.load_cert_chain(str(cert), str(key))
    client = ssl.create_default_context(cafile=str(ca))
    client.set_alpn_protocols(['h2'])
    return server, client


@pytest.mark.parametrize('fragment', [None, 2])
def test_bio_peer_skips_closed_empty_preconnection_and_completes_reuse(
    peer_context, fragment
):
    server_context, client_context = peer_context
    with socket.socket() as listener:
        listener.bind(('127.0.0.1', 0))
        listener.listen(4)
        empty = socket.create_connection(listener.getsockname())
        empty.close()

        class FragmentedSocket:
            def __init__(self, wrapped):
                self.wrapped = wrapped

            def __getattr__(self, name):
                return getattr(self.wrapped, name)

            def recv(self, size):
                return self.wrapped.recv(min(size, fragment))

            def sendall(self, data):
                for index in range(0, len(data), fragment):
                    self.wrapped.sendall(data[index : index + fragment])

            def accept(self):
                connection, address = self.wrapped.accept()
                return FragmentedSocket(connection), address

        peer = capture.Peer(
            FragmentedSocket(listener) if fragment else listener,
            server_context,
            time.monotonic() + 5,
        )
        peer.thread.start()
        try:
            with socket.create_connection(listener.getsockname()) as raw:
                with client_context.wrap_socket(
                    raw, server_hostname='localhost'
                ) as connection:
                    connection.settimeout(3)
                    encoder = Encoder()
                    connection.sendall(capture.PREFACE + capture.frame(4, 0, 0))

                    def read_exact(size):
                        data = b''
                        while len(data) < size:
                            data += connection.recv(size - len(data))
                        return data

                    for stream, path in ((1, '/'), (3, '/pixel.png')):
                        block = encoder.encode(
                            [
                                (b':method', b'GET'),
                                (b':scheme', b'https'),
                                (b':authority', b'localhost'),
                                (b':path', path.encode()),
                            ]
                        )
                        # Hand over application frames in tiny writes, not one prebuilt batch.
                        for byte in capture.frame(1, 5, stream, block):
                            connection.sendall(bytes([byte]))
                        body = b''
                        while True:
                            header = read_exact(9)
                            kind, flags, actual = struct.unpack('!BBI', header[3:])
                            payload = read_exact(int.from_bytes(header[:3], 'big'))
                            if kind == 0 and actual == stream:
                                body += payload
                                if flags & 1:
                                    break
                        assert body == capture.BODIES[path]
            peer.thread.join(4)
            assert not peer.thread.is_alive()
            assert peer.error is None
            assert len(peer.trace.requests) == 2
            assert len(peer.extra_connections) == 1
            assert peer.negotiated['resumed'] is False
            assert peer.evidence()['hellos'][0]['fields']['supported_versions']
        finally:
            peer.close()


def test_client_exit_without_handshake_reaps_peer_and_retains_failed_evidence(
    peer_context, tmp_path
):
    server, _ = peer_context
    with socket.socket() as listener:
        listener.bind(('127.0.0.1', 0))
        listener.listen(1)
        with pytest.raises(capture.CaptureError):
            capture.run_case(
                'failed',
                [sys.executable, '-c', 'raise SystemExit(2)'],
                listener,
                server,
                tmp_path,
                capture.environment(),
                tmp_path,
                deadline_seconds=0.2,
            )
    evidence = json.loads((tmp_path / 'failed.json').read_text())
    assert evidence['status'] == 'failed'
    assert evidence['peer_joined'] is True
    assert evidence['process_cleanup']['group_gone'] is True


def test_browser_marker_failure_cannot_be_a_passed_capture(tmp_path):
    (tmp_path / 'browser.stdout.log').write_text('<body data-complete="no"></body>')
    with pytest.raises(capture.CaptureError, match='DOM marker'):
        capture.validate_browser(tmp_path, 'browser')


def test_queued_unused_client_hello_is_retained_and_cannot_pollute_next_case():
    raw = bytes.fromhex(
        json.loads((ROOT / 'test/fixtures/chrome154_macos_hello.json').read_text())[
            'record_hex'
        ]
    )
    with socket.socket() as listener:
        listener.bind(('127.0.0.1', 0))
        listener.listen(4)
        with socket.create_connection(listener.getsockname()) as connection:
            connection.sendall(raw)
        extra = capture.drain_preconnections(listener)
        assert len(extra) == 1
        assert extra[0]['tls_client_hex'] == raw.hex()
        assert extra[0]['calibration_connection'] is False
        assert capture.drain_preconnections(listener) == []


def test_detached_owned_profile_descendant_is_reaped_without_touching_other_process(
    tmp_path,
):
    profile = tmp_path / 'owned-profile'
    child = 'import time; time.sleep(30)'
    unrelated = subprocess.Popen([sys.executable, '-c', child], start_new_session=True)
    parent_code = (
        'import subprocess,sys; '
        'p=subprocess.Popen([sys.executable,"-c",sys.argv[1],sys.argv[2]],start_new_session=True,stdout=subprocess.DEVNULL); '
        'print(p.pid,flush=True); input()'
    )
    arguments = [
        sys.executable,
        '-c',
        parent_code,
        child,
        '--user-data-dir=' + str(profile),
    ]
    process = subprocess.Popen(
        arguments,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        text=True,
        start_new_session=True,
    )
    owner = capture.OwnedProcesses(process, arguments)
    pid = int(process.stdout.readline())
    try:
        process.communicate('\n', timeout=5)
        result = owner.close()
        assert result['descendants_gone'] is True
        assert pid in [item['pid'] for item in result['observed_processes']]
        assert unrelated.poll() is None
    finally:
        if owner.thread.is_alive():
            owner.close()
        unrelated.kill()
        unrelated.wait(5)
        for tracked in owner.known.values():
            try:
                tracked.kill()
            except capture.psutil.NoSuchProcess:
                pass


def test_decoded_header_limit_is_a_failure():
    parser = capture.H2Trace()
    block = Encoder().encode([(b'x-size', b'x' * capture.HEADER_LIMIT)])
    wire = capture.PREFACE
    for offset in range(0, len(block), 16000):
        part = block[offset : offset + 16000]
        flags = 4 if offset + len(part) == len(block) else 0
        wire += capture.frame(1 if offset == 0 else 9, flags, 1, part)
    from hpack.exceptions import OversizedHeaderListError

    with pytest.raises(OversizedHeaderListError):
        parser.feed(wire)


def test_retained_fixture_redecodes_independently_and_reports_material_differences():
    fixture = json.loads(
        (ROOT / 'test/fixtures/chrome155_macos_tls_h2.json').read_text()
    )
    for case in fixture['cases']:
        assert (
            capture.tls_fields(bytes.fromhex(case['tls_client_hex'])) == case['hellos']
        )
        parser = capture.H2Trace()
        wire = bytes.fromhex(case['h2_client_hex'])
        for offset in range(0, len(wire), 13):
            parser.feed(wire[offset : offset + 13])
        parser.finish()
        assert parser.frames == case['frames']
        assert parser.requests == case['requests']
        assert case['process_cleanup']['descendants_gone'] is True
    comparison = capture.compare(fixture['cases'])
    summary = [
        {key: row[key] for key in ('case', 'field', 'status', 'browser_stable')}
        for row in comparison['rows']
    ]
    assert summary == fixture['comparison_summary']
    rows = {row['field']: row for row in comparison['rows'] if row['case'] == 'sync'}
    assert rows['request1.priority']['status'] == 'missing control'
    assert rows['request1.flags']['status'] == 'missing control'
    assert rows['tls.extension_types']['status'] == 'variable/undetermined'
    assert rows['request1.headers']['status'] == 'matched'
    assert rows['h2.settings']['status'] == 'matched'


def test_comparison_rejects_extra_requests_instead_of_silently_zipping():
    import copy

    fixture = json.loads(
        (ROOT / 'test/fixtures/chrome155_macos_tls_h2.json').read_text()
    )
    cases = copy.deepcopy(fixture['cases'])
    cases[-1]['requests'].append(cases[-1]['requests'][0])
    with pytest.raises(capture.CaptureError, match='Unequal request counts'):
        capture.compare(cases)


def test_outbound_huffman_all_octets_matches_independent_encoder():
    from hpack.huffman import HuffmanEncoder
    from hpack.huffman_constants import REQUEST_CODES, REQUEST_CODES_LENGTH
    from ja3requests.protocol.h2.huffman import huffman_encode

    independent = HuffmanEncoder(REQUEST_CODES, REQUEST_CODES_LENGTH)
    for raw in (b'', bytes(range(256)), bytes(range(256)) * 256):
        assert huffman_encode(raw) == independent.encode(raw)


def test_huffman_acceptance_rejects_raw_baseline():
    fixture = json.loads(
        (ROOT / 'test/fixtures/chrome155_macos_tls_h2.json').read_text()
    )
    with pytest.raises(capture.CaptureError, match='first-request HPACK'):
        capture.huffman_acceptance(fixture['cases'])
