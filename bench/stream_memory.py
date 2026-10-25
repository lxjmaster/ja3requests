"""Explicit isolated-client streaming memory checks; Python >=3.12 tooling.

Run ``python -m bench.stream_memory --help``. Never publishes or modifies the
runtime library. The independent peer and RSS sampler live outside the client.
"""

from __future__ import annotations

import argparse
import asyncio
from contextlib import contextmanager
from datetime import datetime, timezone
import gc
import hashlib
from importlib.metadata import version
import json
import math
import os
from pathlib import Path
import platform
import queue
import resource
import subprocess
import sys
import tempfile
import threading
import time
import tracemalloc
from types import SimpleNamespace

import psutil


ROOT = Path(__file__).resolve().parents[1]
MIB = 1024 * 1024
BUDGETS = {
    'rss_increase_bytes': 64 * MIB,
    'python_peak_increase_bytes': 16 * MIB,
    'rss_growth_bytes': 8 * MIB,
    'python_growth_bytes': MIB,
}
CASES = {
    'http-chunked': ('plain', 'http/1.1', 'identity', True),
    'tls12-http1': ('TLSv1.2', 'http/1.1', 'identity', False),
    'tls13-http1': ('TLSv1.3', 'http/1.1', 'identity', False),
    'tls13-h2': ('TLSv1.3', 'h2', 'identity', False),
    'gzip': ('plain', 'http/1.1', 'gzip', True),
    'deflate': ('plain', 'http/1.1', 'deflate', True),
    'br': ('plain', 'http/1.1', 'br', True),
}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def lifetime_rss():
    """OS process-lifetime high water, not a transfer-only sampled peak."""
    value = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    return int(value if sys.platform == 'darwin' else value * 1024)


def emit(event, **values):
    print(json.dumps(dict(event=event, **values)), flush=True)


class ProtocolProbe:
    """Observe Python payload state; never infer native bytes by subtraction."""

    def __init__(self):
        self.maxima = {}
        self.limits = {}

    def observe(self, name, size, limit=None):
        self.maxima[name] = max(self.maxima.get(name, 0), size)
        if limit is not None:
            self.limits[name] = limit
            require(size <= limit, '%s exceeded its observed-state budget' % name)

    def decoder(self, decoder):
        for name in ('prefix', 'deflate_probe'):
            self.observe('decoder_' + name, len(getattr(decoder, name)), 65536)
        # zlib exposes input tails, but not its native history window.
        for name in ('unconsumed_tail', 'unused_data'):
            value = getattr(decoder.decoder, name, None)
            if isinstance(value, bytes):
                self.observe('decoder_' + name, len(value), 65536)

    def response(self, response):
        self.observe('response_cache', len(response._body or b''), 0)
        require(response._body is None, 'Streaming response acquired a body cache')
        if hasattr(response, '_buffer'):
            self.observe('http1_pending', len(response._buffer), 65536)
            transport = response._transport
            if transport is None and response._h2 is not None:
                transport = getattr(response._h2._recv_func, '__self__', None)
            if transport is not None:
                for name in ('_pending', '_plaintext'):
                    value = getattr(transport, name, None)
                    if value is not None:
                        self.observe('transport' + name, len(value), 65536)
        else:
            reader = getattr(response.response.fp, 'raw', None)
            if hasattr(reader, 'pending'):
                self.observe('sync_reader_pending', len(reader.pending), 65536)

    @contextmanager
    def installed(self):
        from ja3requests.response import _ContentDecoder
        from ja3requests.protocol.h2.stream_state import H2StreamState

        original_feed = _ContentDecoder.feed
        original_dispatch = H2StreamState._dispatch_frame
        probe = self

        def feed(decoder, data):
            iterator = original_feed(decoder, data)
            try:
                for output in iterator:
                    probe.decoder(decoder)
                    probe.observe('decoder_output', len(output), decoder.chunk_size)
                    yield output
            finally:
                iterator.close()

        def dispatch(connection, frame):
            original_dispatch(connection, frame)
            # Sync dispatch holds its condition lock; async dispatch is on-loop.
            probe.observe(
                'h2_data_queue',
                connection._buffered_bytes,
                connection.receive_buffer_limit,
            )
            for stream in connection._streams.values():
                probe.observe(
                    'h2_stream_body', len(stream.body), connection._local_settings[4]
                )
            probe.observe('h2_frame_pending', len(connection._recv_buffer))

        _ContentDecoder.feed = feed
        H2StreamState._dispatch_frame = dispatch
        try:
            yield self
        finally:
            _ContentDecoder.feed = original_feed
            H2StreamState._dispatch_frame = original_dispatch


class Consumer:
    """Fixed-size bookkeeping; no retained response chunks or timing arrays."""

    def __init__(self, config, probe):
        self.config = config
        self.probe = probe
        self.total = 0
        self.count = 0
        self.maximum = 0
        self.next_checkpoint = 1

    def accept(self, response, chunk):
        require(isinstance(chunk, bytes), 'Non-byte output')
        require(len(chunk) <= self.config['chunk_size'], 'Oversized application chunk')
        require(chunk.count(b'x') == len(chunk), 'Incorrect response payload')
        self.probe.response(response)
        if not chunk:
            return
        self.total += len(chunk)
        self.count += 1
        self.maximum = max(self.maximum, len(chunk))
        if self.count == 1:
            emit('first_chunk', bytes=len(chunk))
        # At most four points, independent of body size or run duration.
        if (
            self.next_checkpoint <= 4
            and self.total * 4 >= self.config['body_bytes'] * self.next_checkpoint
        ):
            current, peak = tracemalloc.get_traced_memory()
            emit(
                'progress',
                received_bytes=self.total,
                python_current_bytes=current,
                python_peak_bytes=peak,
            )
            self.next_checkpoint += 1

    def finish(self, response):
        self.probe.response(response)
        require(self.total == self.config['body_bytes'], 'Incomplete decoded response')
        require(self.count > 0, 'No application chunks')
        return {
            'received_bytes': self.total,
            'chunk_count': self.count,
            'max_chunk_bytes': self.maximum,
            'body_cached': False,
            'protocol_observed_max_bytes': self.probe.maxima,
            'protocol_limits_bytes': self.probe.limits,
        }


def client_config(config):
    from ja3requests import TlsConfig

    result = TlsConfig.secure()
    result.tls_version = 0x0303 if config['tls'] == 'TLSv1.2' else 0x0304
    result.cipher_suites = [0xC02F] if config['tls'] == 'TLSv1.2' else [0x1302]
    result.alpn_protocols = [config['protocol']]
    return result


def ready():
    gc.collect()
    tracemalloc.start()
    emit('ready', pid=os.getpid(), lifetime_rss_bytes=lifetime_rss())
    require(sys.stdin.readline().strip() == 'start', 'Missing parent start signal')
    tracemalloc.reset_peak()
    return tracemalloc.get_traced_memory()[0]


def request_options(config):
    return dict(
        stream=True,
        allow_redirects=False,
        timeout=config['timeout'],
        headers={'Accept-Encoding': config['encoding']},
    )


def consume_sync(config, probe):
    from ja3requests import Session

    with Session(tls_config=client_config(config)) as session:
        baseline = ready()
        consumer = Consumer(config, probe)
        with session.get(config['url'], **request_options(config)) as response:
            require(response.status_code == 200, 'Unexpected response status')
            probe.response(response)
            for chunk in response.iter_content(config['chunk_size']):
                consumer.accept(response, chunk)
            result = consumer.finish(response)
    return baseline, result


async def consume_async(config, probe):
    from ja3requests import AsyncSession

    async with AsyncSession(tls_config=client_config(config)) as session:
        baseline = ready()
        consumer = Consumer(config, probe)
        response = await session.get(config['url'], **request_options(config))
        try:
            require(response.status_code == 200, 'Unexpected response status')
            require(
                response.protocol_version
                == ('HTTP/2' if config['protocol'] == 'h2' else 'HTTP/1.1'),
                'Unexpected client protocol',
            )
            probe.response(response)
            async for chunk in response.aiter_content(config['chunk_size']):
                consumer.accept(response, chunk)
            result = consumer.finish(response)
        finally:
            await response.aclose()
    return baseline, result


def child(config):
    import ja3requests

    require(
        Path(ja3requests.__file__).resolve() == ROOT / 'ja3requests/__init__.py',
        'Client imported a different package',
    )
    with ProtocolProbe().installed() as probe:
        if config['client'] == 'async':
            baseline, result = asyncio.run(consume_async(config, probe))
        else:
            baseline, result = consume_sync(config, probe)
        current, peak = tracemalloc.get_traced_memory()
        result.update(
            python_baseline_bytes=baseline,
            python_current_bytes=current,
            python_peak_bytes=peak,
            python_peak_increase_bytes=max(0, peak - baseline),
            lifetime_rss_bytes=lifetime_rss(),
        )
        tracemalloc.stop()
    emit('result', **result)
    require(sys.stdin.readline().strip() == 'finish', 'Missing parent finish signal')


def child_environment(ca_path):
    from tools.verify_release import clean_environment

    result = clean_environment()
    result['SSL_CERT_FILE'] = str(ca_path)
    result['JA3_DEBUG'] = '0'
    return result


def run_case(config, certificates, *, truncate=False):
    """Own a peer and one child; retain O(1) RSS statistics and <=4 points."""
    from bench.stream_memory_peer import MemoryPeer
    from bench.test_protocol_performance import server_context

    context = (
        None
        if config['tls'] == 'plain'
        else server_context(certificates, config['tls'], config['protocol'])
    )
    row = dict(
        config=config,
        status='failed',
        controller_pid=os.getpid(),
        checkpoints=[],
        cleanup={},
    )
    process = reader = None
    events = queue.Queue(maxsize=16)
    peer = MemoryPeer(
        context,
        config['protocol'],
        config['body_bytes'],
        config['timeout'],
        encoding=config['encoding'],
        chunked=config['chunked'],
        truncate=truncate,
    )
    started = time.monotonic()
    deadline = started + config['timeout']
    rss_peak = samples = 0
    max_gap = 0.0
    last_sample = None
    measured = False

    with tempfile.TemporaryFile(mode='w+', encoding='utf-8') as errors:
        try:
            with peer:
                options = dict(config, url=peer.url)
                process = subprocess.Popen(
                    [
                        sys.executable,
                        '-m',
                        'bench.stream_memory',
                        '--child',
                        json.dumps(options),
                    ],
                    cwd=ROOT,
                    env=child_environment(certificates.ca_path),
                    stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE,
                    stderr=errors,
                    text=True,
                )
                client_process = psutil.Process(process.pid)
                row['client_pid'] = process.pid

                def read_events():
                    try:
                        for line in process.stdout:
                            events.put(json.loads(line))
                    except Exception as error:
                        events.put({'event': 'reader_error', 'error': repr(error)})
                    finally:
                        events.put({'event': 'eof'})

                reader = threading.Thread(target=read_events, daemon=True)
                reader.start()
                while True:
                    require(
                        time.monotonic() < deadline,
                        'Client measurement deadline exceeded',
                    )
                    if measured and process.poll() is None:
                        now = time.monotonic()
                        try:
                            rss_peak = max(rss_peak, client_process.memory_info().rss)
                            samples += 1
                            if last_sample is not None:
                                max_gap = max(max_gap, now - last_sample)
                            last_sample = now
                        except psutil.NoSuchProcess:
                            pass
                    try:
                        event = events.get(timeout=config['sample_interval'])
                    except queue.Empty:
                        require(
                            process.poll() is None, 'Client exited without a result'
                        )
                        continue
                    kind = event.pop('event')
                    if kind == 'ready':
                        require(
                            not measured and event['pid'] == process.pid,
                            'Invalid ready event',
                        )
                        row['rss_baseline_bytes'] = client_process.memory_info().rss
                        row['baseline_lifetime_rss_bytes'] = event['lifetime_rss_bytes']
                        rss_peak = row['rss_baseline_bytes']
                        measured = True
                        process.stdin.write('start\n')
                        process.stdin.flush()
                    elif kind == 'first_chunk':
                        require(
                            measured and not row.get('first_chunk_received'),
                            'Invalid first-chunk event',
                        )
                        row['first_chunk_received'] = True
                        peer.release_tail()
                    elif kind == 'progress':
                        require(
                            len(row['checkpoints']) < 4, 'Unbounded progress output'
                        )
                        row['checkpoints'].append(event)
                    elif kind == 'result':
                        require(
                            row.get('first_chunk_received'),
                            'Missing first application chunk',
                        )
                        row.update(event)
                        process.stdin.write('finish\n')
                        process.stdin.flush()
                        process.wait(timeout=max(0.01, deadline - time.monotonic()))
                        require(
                            process.returncode == 0,
                            'Client failed after reporting result',
                        )
                        row['peer_responses'] = peer.wait_for_records()
                        row['peer_connections'] = list(peer.connections)
                        row['status'] = 'measured'
                        break
                    else:
                        raise ValueError(
                            'Client did not complete: %s %s' % (kind, event)
                        )
        except Exception as error:
            row['status'] = 'failed'
            row['error'] = repr(error)
        finally:
            if process is not None:
                if process.poll() is None:
                    process.terminate()
                    try:
                        process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait(timeout=5)
                row['child_exit_code'] = process.returncode
                process.stdin.close()
                if reader is not None:
                    reader.join(timeout=5)
                process.stdout.close()
                row['cleanup']['client_exited'] = process.poll() is not None
                row['cleanup']['reader_joined'] = (
                    reader is None or not reader.is_alive()
                )
            row['cleanup'][
                'peer_threads_stopped'
            ] = not peer._thread.is_alive() and not any(
                worker.is_alive() for worker in peer._workers
            )
            row.setdefault('peer_responses', list(peer.records))
            row.setdefault('peer_connections', list(peer.connections))
            row['peer_errors'] = list(peer.errors)
            errors.seek(0)
            row['stderr'] = errors.read(16384)
    row.update(
        rss_peak_sampled_bytes=rss_peak,
        rss_samples=samples,
        rss_max_sample_gap_seconds=max_gap,
        elapsed_seconds=time.monotonic() - started,
    )
    row['rss_increase_bytes'] = max(
        0, rss_peak - row.get('rss_baseline_bytes', rss_peak)
    )
    return row


def assess_case(row):
    problems = []
    if row['status'] != 'measured':
        return [row.get('error', 'Measurement did not complete')]
    config = row['config']
    if row['received_bytes'] != config['body_bytes']:
        problems.append('Decoded byte count mismatch')
    if row['body_cached'] or row['max_chunk_bytes'] > config['chunk_size']:
        problems.append('Application body cache/chunk bound failed')
    for name in ('rss_increase_bytes', 'python_peak_increase_bytes'):
        if row[name] > BUDGETS[name]:
            problems.append(name + ' exceeds fixed scenario budget')
    if not row.get('first_chunk_received') or row['rss_samples'] < 2:
        problems.append('Missing gated streaming or RSS observations')
    if (
        not all(
            row['cleanup'].get(name)
            for name in ('client_exited', 'reader_joined', 'peer_threads_stopped')
        )
        or row['child_exit_code'] != 0
    ):
        problems.append('Incomplete process/thread cleanup')
    connections = row['peer_connections']
    if len(connections) != 1:
        problems.append('Expected one observed connection')
    elif config['tls'] != 'plain' and (
        connections[0]['tls_version'] != config['tls']
        or connections[0]['alpn'] != config['protocol']
    ):
        problems.append('Negotiated protocol differs from requested path')
    if len(row['peer_responses']) != 1:
        problems.append('Expected one completed peer response')
    else:
        peer = row['peer_responses'][0]
        if (
            not peer['gate_reached']
            or not peer['tail_released_before_complete']
            or peer['decoded_bytes_sent'] != config['body_bytes']
        ):
            problems.append('Peer gate/body evidence failed')
    for name, limit in row['protocol_limits_bytes'].items():
        if row['protocol_observed_max_bytes'][name] > limit:
            problems.append(name + ' exceeded explicit protocol budget')
    required = {'response_cache', 'decoder_output'}
    if config['protocol'] == 'h2':
        required.update(('h2_data_queue', 'h2_stream_body'))
    if config['encoding'] != 'identity':
        required.update(('decoder_prefix', 'decoder_deflate_probe'))
    if not required.issubset(row['protocol_observed_max_bytes']):
        problems.append('Required protocol/decoder observations are missing')
    return problems


def compare_sizes(rows):
    comparisons = []
    keys = {(row['config']['client'], row['config']['case']) for row in rows}
    for client, case in sorted(keys):
        selected = sorted(
            (
                row
                for row in rows
                if row['config']['client'] == client and row['config']['case'] == case
            ),
            key=lambda row: row['config']['body_bytes'],
        )
        if len(selected) != 2 or any(row['status'] != 'passed' for row in selected):
            comparisons.append(
                dict(
                    client=client,
                    case=case,
                    status='failed',
                    error='Two passing sizes required',
                )
            )
            continue
        small, large = selected
        rss_growth = max(0, large['rss_increase_bytes'] - small['rss_increase_bytes'])
        python_growth = max(
            0, large['python_peak_increase_bytes'] - small['python_peak_increase_bytes']
        )
        comparisons.append(
            dict(
                client=client,
                case=case,
                rss_growth_bytes=rss_growth,
                python_growth_bytes=python_growth,
                status=(
                    'passed'
                    if rss_growth <= BUDGETS['rss_growth_bytes']
                    and python_growth <= BUDGETS['python_growth_bytes']
                    else 'failed'
                ),
            )
        )
    return comparisons


def tool_identity():
    names = [
        'bench/stream_memory.py',
        'bench/stream_memory_peer.py',
        'bench/peers.py',
        'bench/test_protocol_performance.py',
        'bench/http1_baseline.py',
        'bench/requirements.txt',
        'test/integration/conftest.py',
        'test/mock_servers/local.py',
        'tools/verify_release.py',
    ]
    return {
        name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest() for name in names
    }


def measure(args):
    from bench.http1_baseline import git_identity, source_identity
    from test.integration.conftest import trusted_certificates

    args.output.mkdir(parents=True, exist_ok=False)
    report = dict(
        status='running',
        started_at_utc=datetime.now(timezone.utc).isoformat(),
        scope='local checkout, not published-artifact acceptance',
        body_sizes=args.body_bytes,
        clients=args.clients,
        selected_cases=args.cases,
        chunk_size=args.chunk_size,
        budgets=dict(BUDGETS),
        python=sys.version,
        platform=platform.platform(),
        git=git_identity(),
        dependencies={
            name: version(name) for name in ('psutil', 'cryptography', 'brotli')
        },
        source_before=source_identity(),
        tools_before=tool_identity(),
        cases=[],
        comparisons=[],
    )
    staging = None
    try:
        with tempfile.TemporaryDirectory(
            prefix='ja3requests-stream-memory-'
        ) as temporary:
            staging = Path(temporary)
            factory = SimpleNamespace(mktemp=lambda _: staging)
            with contextmanager(trusted_certificates.__wrapped__)(
                factory
            ) as certificates:
                for client in args.clients:
                    for name in args.cases:
                        tls, protocol, encoding, chunked = CASES[name]
                        for size in args.body_bytes:
                            config = dict(
                                client=client,
                                case=name,
                                tls=tls,
                                protocol=protocol,
                                encoding=encoding,
                                chunked=chunked,
                                body_bytes=size,
                                chunk_size=args.chunk_size,
                                timeout=args.timeout,
                                sample_interval=args.sample_interval,
                            )
                            row = run_case(config, certificates)
                            row['problems'] = assess_case(row)
                            row['status'] = (
                                'passed' if not row['problems'] else 'failed'
                            )
                            report['cases'].append(row)
                            print(
                                '%s %s %d: %s; RSS delta %d, Python peak delta %s'
                                % (
                                    client,
                                    name,
                                    size,
                                    row['status'],
                                    row['rss_increase_bytes'],
                                    row.get('python_peak_increase_bytes'),
                                ),
                                flush=True,
                            )
                            if row['problems']:
                                raise ValueError(row['problems'])
        report['comparisons'] = compare_sizes(report['cases'])
        require(
            all(item['status'] == 'passed' for item in report['comparisons']),
            'Cross-size growth budget failed',
        )
        report['status'] = 'passed'
    except Exception as error:
        report['status'] = 'failed'
        report['error'] = repr(error)
    finally:
        report['source_stable'] = report['source_before'] == source_identity()
        report['finished_at_utc'] = datetime.now(timezone.utc).isoformat()
        report['tools_stable'] = report['tools_before'] == tool_identity()
        report['temporary_removed'] = staging is None or not staging.exists()
        if not all(
            report[key]
            for key in ('source_stable', 'tools_stable', 'temporary_removed')
        ):
            report['status'] = 'failed'
        (args.output / 'measurement.json').write_text(
            json.dumps(report, indent=2, sort_keys=True) + '\n'
        )
    return 0 if report['status'] == 'passed' else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--child', help=argparse.SUPPRESS)
    parser.add_argument('--output', type=Path)
    parser.add_argument(
        '--clients', nargs='+', choices=['sync', 'async'], default=['sync', 'async']
    )
    parser.add_argument(
        '--cases', nargs='+', choices=sorted(CASES), default=list(CASES)
    )
    parser.add_argument(
        '--body-bytes', nargs=2, type=int, default=[100_000_000, 1_000_000_000]
    )
    parser.add_argument('--chunk-size', type=int, default=16384)
    parser.add_argument('--timeout', type=float, default=180)
    parser.add_argument('--sample-interval', type=float, default=0.01)
    args = parser.parse_args()
    if args.child:
        child(json.loads(args.child))
        return 0
    if sys.platform not in ('darwin', 'linux'):
        parser.error('Supported tooling platforms are macOS/Linux')
    if args.output is None:
        parser.error('--output is required and must not exist')
    if args.output.exists():
        parser.error('--output must not exist')
    if not (32768 < args.body_bytes[0] < args.body_bytes[1]):
        parser.error(
            'Provide two increasing sizes above the gated prefix (32768 bytes)'
        )
    if not 0 < args.chunk_size <= 16384:
        parser.error('--chunk-size must be between 1 and 16384 for the gated peer')
    if any(
        not math.isfinite(value) or value <= 0
        for value in (args.timeout, args.sample_interval)
    ):
        parser.error('Timeout and sample interval must be finite and positive')
    return measure(args)


if __name__ == '__main__':
    raise SystemExit(main())
