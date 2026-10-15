"""Independent tool acceptance assertions using retained raw capture inputs."""

import copy
import json
import struct

import pytest

from ja3requests import TlsConfig
from ja3requests.protocol.tls import TLS
from tools import capture_fingerprint as capture
from tools.verify_h2_controls import check_controls


def recorded_case():
    fixture = json.loads(
        (capture.ROOT / 'test/fixtures/chrome155_macos_tls_h2.json').read_bytes()
    )
    reference = fixture['cases'][0]
    case = copy.deepcopy(reference)
    third = copy.deepcopy(case['requests'][1])
    third.update(
        stream=5, priority=None, dynamic_entries_before=20, dynamic_entries_after=20
    )
    case['requests'].append(third)
    return case, reference


def test_retained_priority_path_and_table_acceptance():
    case, reference = recorded_case()
    result = check_controls(case, True, reference)
    assert result['stream_reuse'] == [1, 3, 5]
    assert result['path_representations'] == ['indexed', 'without', 'without']
    assert result['table_entries_after_second'] == 20


def test_peer_keeps_legacy_paths_and_snapshots_explicit_paths():
    assert capture.Peer(None, None, 1).expected_paths == ('/', '/pixel.png')
    paths = ['/', '/pixel.png', '/pixel.png']
    peer = capture.Peer(None, None, 1, expected_paths=paths)
    paths.clear()
    assert peer.expected_paths == ('/', '/pixel.png', '/pixel.png')


@pytest.mark.parametrize(
    'field', ['priority', 'stream', 'entries', 'continuity', 'path', 'count']
)
def test_mismatched_control_evidence_fails(field):
    case, reference = recorded_case()
    if field == 'priority':
        case['requests'][1]['priority'][1] = 256
    elif field == 'stream':
        case['requests'][2]['stream'] = 1
    elif field == 'entries':
        case['requests'][1]['dynamic_entries_after'] = 21
    elif field == 'continuity':
        case['requests'][2]['dynamic_entries_before'] = 0
    elif field == 'count':
        case['requests'].pop()
    else:
        representations = [
            item
            for item in case['requests'][1]['representations']
            if item['kind'] != 'table-size'
        ]
        for pair, representation in zip(
            case['requests'][1]['headers'], representations
        ):
            if bytes.fromhex(pair[0]) == b':path':
                representation['kind'] = 'incremental'
    with pytest.raises(capture.CaptureError):
        check_controls(case, True, reference)


def profile_case():
    case, reference = recorded_case()
    tls = TLS(None, server_host='localhost')
    tls.set_payload(TlsConfig.from_browser('chrome', 155))
    case['hellos'] = capture.tls_fields(tls.body.message)
    case['requests'][2]['flags'] = 5
    return case, reference


def test_profile_defaults_accepts_received_subset_and_third_stream():
    case, reference = profile_case()
    result = capture.check_profile_defaults(case, reference)
    assert result['status'] == 'passed'
    assert result['connection_overrides'] == {}
    assert result['reused_streams'] == [1, 3, 5]
    assert result['literal_checks'] > 0


def profile_series():
    fixture = json.loads(
        (capture.ROOT / 'test/fixtures/chrome155_macos_tls_h2.json').read_bytes()
    )
    browsers = [case for case in fixture['cases'] if case['case'].startswith('browser')]
    case, _ = profile_case()
    case['requests'] = case['requests'][:2]
    return browsers + [
        dict(copy.deepcopy(case), case=kind) for kind in ('sync', 'async')
    ]


def test_profile_defaults_accepts_all_browser_samples_and_random_extension_order():
    result = capture.profile_defaults_acceptance(profile_series())
    assert result['status'] == 'passed'
    for checks in result['clients'].values():
        assert set(checks) == {'browser-1', 'browser-2', 'browser-3'}


@pytest.mark.parametrize('browser_index', [0, 1, 2])
@pytest.mark.parametrize('field', ['settings', 'window', 'versions'])
def test_profile_defaults_rejects_browser_wire_drift(browser_index, field):
    cases = profile_series()
    browser = cases[browser_index]
    if field == 'versions':
        original = bytes.fromhex(browser['hellos'][0]['record_hex'])
        raw = original
        payload = dict(capture.decode(raw)['extensions'])[43]
        assert payload[-2:] == b'\x03\x03'
        encoded = struct.pack('!HH', 43, len(payload)) + payload
        assert raw.count(encoded) == 1
        raw = raw.replace(encoded, encoded[:-2] + b'\x03\x02', 1)
        browser['hellos'] = capture.tls_fields(raw)
        tls_client = bytes.fromhex(browser['tls_client_hex'])
        assert tls_client.count(original) == 1
        tls_client = tls_client.replace(original, raw, 1)
        browser['tls_client_hex'] = tls_client.hex()
        browser['tls_client_sha256'] = capture.digest(tls_client)
        assert browser['hellos'][0]['fields']['supported_versions'] == [
            'GREASE',
            772,
            770,
        ]
    else:
        raw = bytearray.fromhex(browser['h2_client_hex'])
        offset = len(capture.PREFACE)
        while offset + 9 <= len(raw):
            size = int.from_bytes(raw[offset : offset + 3], 'big')
            kind, flags = raw[offset + 3 : offset + 5]
            payload = offset + 9
            if field == 'settings' and kind == 4 and not flags & 1:
                assert raw[payload : payload + 6] == b'\x00\x01\x00\x01\x00\x00'
                raw[payload + 2 : payload + 6] = (4096).to_bytes(4, 'big')
                break
            if field == 'window' and kind == 8:
                assert int.from_bytes(raw[payload : payload + 4], 'big') == 15663105
                raw[payload : payload + 4] = (1).to_bytes(4, 'big')
                break
            offset += 9 + size
        else:
            pytest.fail('Missing captured startup frame')
        trace = capture.H2Trace()
        trace.feed(bytes(raw))
        trace.finish()
        browser['h2_client_hex'] = raw.hex()
        browser['h2_client_sha256'] = capture.digest(raw)
        browser['frames'], browser['requests'] = trace.frames, trace.requests
    with pytest.raises(capture.CaptureError):
        capture.profile_defaults_acceptance(cases)


@pytest.mark.parametrize('side', ['client', 'browser'])
@pytest.mark.parametrize(
    'field',
    [
        'settings',
        'window',
        'pseudo_order',
        'ciphers',
        'groups',
        'versions',
        'signatures',
        'extensions',
        'record_version',
        'payload',
        'priority',
        'path',
        'table',
        'stream',
        'flags',
        'huffman',
        'headers',
        'authority',
    ],
)
def test_profile_defaults_rejects_wrong_declared_fields(field, side):
    case, reference = profile_case()
    changed = case if side == 'client' else reference
    hello = changed['hellos'][0]
    request = changed['requests'][1]
    if field == 'settings':
        changed['frames'][0]['settings'][0][1] = 4096
    elif field == 'window':
        changed['frames'][1]['increment'] = 1
    elif field == 'pseudo_order':
        request['headers'][0:2] = reversed(request['headers'][0:2])
    elif field in ('ciphers', 'groups', 'versions', 'signatures', 'extensions'):
        key = {
            'versions': 'supported_versions',
            'signatures': 'signature_algorithms',
            'extensions': 'extension_types',
        }.get(field, field)
        if field == 'extensions' and side == 'browser':
            hello['fields'][key].remove(45)
        else:
            hello['fields'][key].reverse()
    elif field == 'record_version':
        hello['record_versions'] = ['0303']
    elif field == 'payload':
        next(item for item in hello['fields']['extensions'] if item['type'] == 5)[
            'payload_hex'
        ] = ''
    elif field == 'priority':
        request['priority'][1] = 256
    elif field == 'table':
        changed['requests'][-1]['dynamic_entries_before'] = 0
    elif field == 'stream':
        changed['requests'][-1]['stream'] = 1
    elif field == 'flags':
        request['flags'] = 5
    elif field in ('headers', 'authority'):
        name = b':authority' if field == 'authority' else b'user-agent'
        pair = next(
            pair for pair in request['headers'] if bytes.fromhex(pair[0]) == name
        )
        pair[1] = b'wrong:1234'.hex()
    else:
        reps = [
            item for item in request['representations'] if item['kind'] != 'table-size'
        ]
        if field == 'path':
            next(
                rep
                for pair, rep in zip(request['headers'], reps)
                if bytes.fromhex(pair[0]) == b':path'
            )['kind'] = 'incremental'
        else:
            literal = next(rep['value'] for rep in reps if 'value' in rep)
            literal['huffman'] = not literal['huffman']
    with pytest.raises(capture.CaptureError):
        capture.check_profile_defaults(case, reference)
