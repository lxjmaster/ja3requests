"""Capture evidence for the explicit Chrome 154 supported subset."""

import hashlib
import json
from pathlib import Path

from ja3requests import TlsConfig
from ja3requests.protocol.tls import TLS
from test.wire_client_hello import decode, grease, profile


def test_chrome154_capture_calibration():
    capture = json.loads(
        (Path(__file__).parent / 'fixtures/chrome154_macos_hello.json').read_text()
    )
    record = bytes.fromhex(capture['record_hex'])
    assert hashlib.sha256(record).hexdigest() == capture['sha256']
    assert capture['browser'] == 'Google Chrome 154.0.8037.95'
    actual = decode(record)
    config = TlsConfig.from_browser('chrome', 154)
    tls = TLS(None, server_host='localhost')
    tls.set_payload(config)
    subset = decode(tls.body.message)
    actual_types = [k for k, _ in actual['extensions'] if not grease(k)]
    subset_types = [k for k, _ in subset['extensions']]
    assert subset_types == [k for k in actual_types if k in subset_types]
    assert set(actual_types) - set(subset_types) == {65037, 51764, 18, 27, 17613}
    assert [
        x for x in actual['ciphers'] if not grease(x) and x not in (52393, 52392)
    ] == [x for x in subset['ciphers'] if not grease(x)]
    assert len(actual['session_id']) == len(subset['session_id']) == 32
    assert actual['compression'] == subset['compression'] == [0]
    aext, sext = dict(actual['extensions']), dict(subset['extensions'])
    for kind in (0, 5, 11, 16, 23, 35, 45, 65281):
        assert aext[kind] == sext[kind]
    assert profile(record)['groups'] == ['GREASE', 4588, 29, 23, 24]
    assert profile(tls.body.message)['groups'] == [29, 23, 24]
    assert profile(tls.body.message)['key_shares'] == [[29, 32]]
    # Deliberately different, not a fake success based on matching five fields.
    assert profile(record)['ja3'] != profile(tls.body.message)['ja3']


def test_existing_implicit_browser_selection_stays_pinned():
    a = TlsConfig.from_browser('chrome')
    b = TlsConfig.from_browser('chrome', 124)
    assert a.get_ja3_string('localhost') == b.get_ja3_string('localhost')


def test_preset_extensions_are_not_shared():
    a = TlsConfig.from_browser('chrome', 154)
    b = TlsConfig.from_browser('chrome', 154)
    a.extensions[2].formats.append(1)
    assert b.extensions[2].formats == [0]
