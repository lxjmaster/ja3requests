"""Independent tool acceptance assertions using retained raw capture inputs."""

import copy
import json

import pytest

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
