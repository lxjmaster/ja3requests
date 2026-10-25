"""Acceptance/failure controls for the isolated streaming-memory controller."""

from copy import deepcopy
from types import SimpleNamespace
import subprocess
import sys
import time

import pytest

from bench import stream_memory as memory
from test.integration.conftest import trusted_certificates  # noqa: F401


def config(client='sync', case='http-chunked', size=131072):
    tls, protocol, encoding, chunked = memory.CASES[case]
    return dict(
        client=client,
        case=case,
        tls=tls,
        protocol=protocol,
        encoding=encoding,
        chunked=chunked,
        body_bytes=size,
        chunk_size=16384,
        timeout=5,
        sample_interval=0.01,
    )


def response(cached=None):
    return SimpleNamespace(_body=cached, response=SimpleNamespace(fp=None))


@pytest.mark.parametrize(
    'chunk,cached,error',
    [
        (b'x' * 16385, None, 'Oversized'),
        (b'wrong', None, 'Incorrect'),
        ('text', None, 'Non-byte'),
        (b'x', b'whole response', 'cache'),
        (b'x', b'', 'cache'),
    ],
)
def test_consumer_rejects_bad_data_and_cached_responses(chunk, cached, error):
    consumer = memory.Consumer(config(), memory.ProtocolProbe())
    with pytest.raises(ValueError, match=error):
        consumer.accept(response(cached), chunk)


def test_consumer_requires_complete_body_and_keeps_only_fixed_checkpoints(monkeypatch):
    events = []
    monkeypatch.setattr(
        memory, 'emit', lambda event, **values: events.append((event, values))
    )
    consumer = memory.Consumer(config(size=100000), memory.ProtocolProbe())
    item = response()
    consumer.accept(item, b'x')
    with pytest.raises(ValueError, match='Incomplete'):
        consumer.finish(item)
    for _ in range(99999):
        consumer.accept(item, b'x')
    result = consumer.finish(item)
    assert len(events) == 5
    assert events[0][0] == 'first_chunk'
    assert all(event == 'progress' for event, _ in events[1:])
    assert result['received_bytes'] == result['chunk_count'] == 100000
    assert result['max_chunk_bytes'] == 1
    assert not result['body_cached']


def test_probe_rejects_protocol_budget_overflow_and_restores_hooks():
    from ja3requests.response import _ContentDecoder
    from ja3requests.protocol.h2.stream_state import H2StreamState

    feed, dispatch = _ContentDecoder.feed, H2StreamState._dispatch_frame
    probe = memory.ProtocolProbe()
    with pytest.raises(ValueError, match='budget'):
        with probe.installed():
            assert _ContentDecoder.feed is not feed
            probe.observe('h2_data_queue', 65536, 65535)
    assert _ContentDecoder.feed is feed
    assert H2StreamState._dispatch_frame is dispatch


def good_row(size=131072):
    return dict(
        config=config(size=size),
        status='measured',
        received_bytes=size,
        max_chunk_bytes=16384,
        body_cached=False,
        rss_increase_bytes=1000000,
        python_peak_increase_bytes=100000,
        first_chunk_received=True,
        rss_samples=10,
        cleanup=dict(client_exited=True, reader_joined=True, peer_threads_stopped=True),
        child_exit_code=0,
        peer_connections=[dict(tls_version=None, alpn=None)],
        peer_responses=[
            dict(
                gate_reached=True,
                tail_released_before_complete=True,
                decoded_bytes_sent=size,
            )
        ],
        protocol_limits_bytes={'http1_pending': 65536},
        protocol_observed_max_bytes={
            'http1_pending': 4096,
            'response_cache': 0,
            'decoder_output': 16384,
        },
    )


@pytest.mark.parametrize(
    'field,value',
    [
        ('status', 'failed'),
        ('received_bytes', 0),
        ('max_chunk_bytes', 16385),
        ('body_cached', True),
        ('first_chunk_received', False),
        ('rss_samples', 0),
        ('child_exit_code', 1),
        ('peer_connections', []),
        ('peer_responses', []),
        ('rss_increase_bytes', memory.BUDGETS['rss_increase_bytes'] + 1),
        (
            'python_peak_increase_bytes',
            memory.BUDGETS['python_peak_increase_bytes'] + 1,
        ),
    ],
)
def test_report_acceptance_rejects_invalid_evidence(field, value):
    row = good_row()
    assert memory.assess_case(row) == []
    row[field] = value
    assert memory.assess_case(row)


def test_report_acceptance_rejects_wrong_negotiation_queue_and_unreleased_tail():
    for mutate in (
        lambda row: row['cleanup'].update(client_exited=False),
        lambda row: row['peer_responses'][0].update(
            tail_released_before_complete=False
        ),
        lambda row: row['protocol_observed_max_bytes'].update(http1_pending=65537),
        lambda row: row['config'].update(tls='TLSv1.3'),
        lambda row: row['cleanup'].clear(),
        lambda row: row['protocol_observed_max_bytes'].pop('decoder_output'),
    ):
        row = good_row()
        mutate(row)
        assert memory.assess_case(row)


def test_cross_size_budget_is_fixed_and_requires_both_passing_sizes():
    small, large = good_row(100000), good_row(1000000)
    small['status'] = large['status'] = 'passed'
    assert memory.compare_sizes([small, large])[0]['status'] == 'passed'
    for field, budget in [
        ('rss_increase_bytes', 'rss_growth_bytes'),
        ('python_peak_increase_bytes', 'python_growth_bytes'),
    ]:
        bad = deepcopy(large)
        bad[field] = small[field] + memory.BUDGETS[budget] + 1
        assert memory.compare_sizes([small, bad])[0]['status'] == 'failed'
    assert memory.compare_sizes([small])[0]['status'] == 'failed'
    large['status'] = 'failed'
    assert memory.compare_sizes([small, large])[0]['status'] == 'failed'


@pytest.mark.parametrize('client', ['sync', 'async'])
@pytest.mark.parametrize('case', ['http-chunked', 'tls13-h2', 'br'])
def test_actual_isolated_client_and_gate(trusted_certificates, client, case):
    row = memory.run_case(config(client, case), trusted_certificates)
    assert memory.assess_case(row) == [], row
    assert 0 < row['max_chunk_bytes'] <= 16384
    assert row['python_peak_increase_bytes'] > 0
    assert row['rss_baseline_bytes'] > 0
    assert len(row['checkpoints']) <= 4
    assert row['peer_responses'][0]['encoded_body_bytes'] > 0


@pytest.mark.parametrize('client', ['sync', 'async'])
@pytest.mark.parametrize('case', ['http-chunked', 'tls13-h2'])
def test_truncated_response_cannot_be_accepted(trusted_certificates, client, case):
    row = memory.run_case(config(client, case), trusted_certificates, truncate=True)
    assert row['status'] == 'failed', row
    assert row['child_exit_code'] != 0
    assert memory.assess_case(row)
    assert all(row['cleanup'].values()), row


@pytest.mark.parametrize(
    'program,timeout,error',
    [
        ('raise RuntimeError("deliberate child failure")', 5, 'complete'),
        ('import time; time.sleep(10)', 0.3, 'deadline'),
    ],
)
def test_child_failure_or_deadline_reaps_owned_process_and_peer(
    trusted_certificates, monkeypatch, program, timeout, error
):
    original = subprocess.Popen
    children = []

    def replaced(_command, **kwargs):
        process = original([sys.executable, '-c', program], **kwargs)
        children.append(process)
        return process

    monkeypatch.setattr(memory.subprocess, 'Popen', replaced)
    options = config()
    options['timeout'] = timeout
    started = time.monotonic()
    row = memory.run_case(options, trusted_certificates)
    assert row['status'] == 'failed' and error in row['error'], row
    assert all(row['cleanup'].values()), row
    assert children[0].poll() is not None
    assert time.monotonic() - started < 5


def test_invalid_cli_does_not_create_output(tmp_path):
    output = tmp_path / 'uncreated'
    result = subprocess.run(
        [
            sys.executable,
            '-m',
            'bench.stream_memory',
            '--output',
            str(output),
            '--body-bytes',
            '100000',
            '100000',
        ],
        capture_output=True,
    )
    assert result.returncode == 2
    assert not output.exists()
