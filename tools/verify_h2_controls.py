"""Independent installed-wheel H2 checks using retained browser request vectors.

Python >=3.12 tooling. Reuses the existing TLS peer and independent hpack parser;
no browser, package build, publication, or library runtime dependency is added.
"""

from __future__ import annotations

import argparse
from importlib.metadata import version
import json
from pathlib import Path
import socket
import ssl
import sys
import tempfile

from tools import capture_fingerprint as capture


def check_controls(case, excluded, reference):
    requests = case['requests']
    capture.require(len(requests) == 3, 'Expected three reused request streams')
    capture.require(
        [item['stream'] for item in requests] == [1, 3, 5], 'Connection reuse failed'
    )
    capture.require(
        [item['priority'] for item in requests]
        == [
            reference['requests'][0]['priority'],
            reference['requests'][1]['priority'],
            None,
        ],
        'HEADERS priority differs from retained vectors',
    )
    kinds = []
    for request in requests:
        representations = [
            item for item in request['representations'] if item['kind'] != 'table-size'
        ]
        capture.require(
            len(representations) == len(request['headers']),
            'Representation/header count mismatch',
        )
        fields = [
            (bytes.fromhex(name), bytes.fromhex(value))
            for name, value in request['headers']
        ]
        path = next(
            rep for rep, pair in zip(representations, fields) if pair[0] == b':path'
        )
        kinds.append(path['kind'])
    capture.require(
        kinds
        == (
            ['indexed', 'without', 'without']
            if excluded
            else ['indexed', 'incremental', 'indexed']
        ),
        'Unexpected path insertion/reference choices',
    )
    target = reference['requests'][1]['dynamic_entries_after'] + (0 if excluded else 1)
    capture.require(
        requests[1]['dynamic_entries_after'] == target,
        'Retained dynamic table difference not reproduced',
    )
    capture.require(
        requests[2]['dynamic_entries_before']
        == target
        == requests[2]['dynamic_entries_after'],
        'Dynamic table continuity failed',
    )
    return {
        'priority': 'retained vectors',
        'path_representations': kinds,
        'table_entries_after_second': target,
        'stream_reuse': [1, 3, 5],
    }


def verify(args):
    profile_defaults = getattr(args, 'profile_defaults', False)
    capture.require(
        not profile_defaults or args.client_profile == 'chrome:155',
        'Profile-default acceptance requires chrome:155',
    )
    identity = capture.artifact_input(
        args.wheel, args.wheel_sha256, args.artifact_report
    )
    fixture_path = capture.ROOT / 'test/fixtures/chrome155_macos_tls_h2.json'
    fixture = json.loads(fixture_path.read_bytes())
    reference = fixture['cases'][0]
    overrides, requests = capture.browser_inputs(reference)
    requests.append(requests[-1])
    priorities = [
        [item['priority'][1], item['priority'][2]] for item in reference['requests'][:2]
    ] + [None]
    args.output.mkdir(parents=True, exist_ok=False)
    report = {
        'status': 'running',
        'artifact': identity,
        'client_profile': args.client_profile,
        'mode': 'profile-defaults' if profile_defaults else 'configured-controls',
        'target': 'retained Chrome 155/macOS HEADERS/path/table vectors only',
        'python': sys.version,
        'openssl': ssl.OPENSSL_VERSION,
        'dependencies': {
            name: version(name) for name in ('hpack', 'cryptography', 'psutil')
        },
        'fixture_sha256': capture.digest(fixture_path.read_bytes()),
        'probe_source_sha256': capture.digest(capture.PROBE_SOURCE.encode()),
        'tool_hashes': {},
        'cases': [],
        'cleanup': {},
    }
    for name in (
        'tools/verify_h2_controls.py',
        'tools/capture_fingerprint.py',
        'test/wire_client_hello.py',
        'requirements-capture.txt',
        'test/fixtures/chrome155_macos_tls_h2.json',
    ):
        raw = (capture.ROOT / name).read_bytes()
        report['tool_hashes'][name] = capture.digest(raw)
        destination = args.output / 'tool-source' / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(raw)
    staging = listener = None
    try:
        with tempfile.TemporaryDirectory(
            prefix='ja3requests-h2-controls-'
        ) as directory:
            staging = Path(directory)
            cert, key, ca, _ = capture.certificate(staging)
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.minimum_version = context.maximum_version = ssl.TLSVersion.TLSv1_3
            context.set_alpn_protocols(['h2'])
            context.num_tickets = 0
            context.load_cert_chain(str(cert), str(key))
            probe_env = staging / 'installed'
            capture.subprocess_checked(
                [sys.executable, '-m', 'venv', str(probe_env)],
                staging,
                capture.environment(),
                args.output / 'venv.log',
            )
            python = probe_env / 'bin/python'
            capture.subprocess_checked(
                [
                    str(python),
                    '-I',
                    '-m',
                    'pip',
                    'install',
                    '--index-url',
                    'https://pypi.org/simple',
                    str(args.wheel.resolve()),
                ],
                staging,
                capture.environment(),
                args.output / 'install.log',
            )
            env = capture.environment()
            env['SSL_CERT_FILE'] = str(ca)
            with socket.socket() as listener:
                listener.bind(('127.0.0.1', 0))
                listener.listen(8)
                origin = 'https://localhost:%d' % listener.getsockname()[1]
                variants = (
                    [(True, True)]
                    if profile_defaults
                    else [
                        (huffman, excluded)
                        for huffman in (False, True)
                        for excluded in (False, True)
                    ]
                )
                for huffman, excluded in variants:
                    for kind in ('sync', 'async'):
                        label = (
                            '%s-profile-defaults' % kind
                            if profile_defaults
                            else '%s-huffman-%d-excluded-%d'
                            % (
                                kind,
                                int(huffman),
                                int(excluded),
                            )
                        )
                        inputs = dict(
                            module_hashes=identity['module_hashes'],
                            profile=args.client_profile,
                            kind=kind,
                            overrides=(
                                {}
                                if profile_defaults
                                else dict(
                                    overrides,
                                    h2_huffman=huffman,
                                    h2_indexing_exclusions=(
                                        [':path'] if excluded else []
                                    ),
                                )
                            ),
                            requests=requests,
                            headers_priorities=priorities,
                            origin=origin,
                            bodies={
                                path: capture.digest(body)
                                for path, body in capture.BODIES.items()
                            },
                        )
                        capture.save_json(
                            args.output / (label + '-inputs.json'), inputs
                        )
                        case = capture.run_case(
                            label,
                            [
                                str(python),
                                '-I',
                                '-c',
                                capture.PROBE_SOURCE,
                                json.dumps(inputs),
                            ],
                            listener,
                            context,
                            args.output,
                            env,
                            staging,
                            validate=lambda: capture.validate_probe(
                                args.output, label, identity
                            ),
                            expected_paths=[path for path, _ in requests],
                        )
                        try:
                            case['controls'] = (
                                capture.check_profile_defaults(case, reference)
                                if profile_defaults
                                else check_controls(case, excluded, reference)
                            )
                        except Exception as error:
                            case.update(
                                status='failed',
                                error='%s: %s' % (type(error).__name__, error),
                            )
                            capture.save_json(args.output / (label + '.json'), case)
                            raise
                        capture.save_json(args.output / (label + '.json'), case)
                        report['cases'].append(
                            {
                                'case': label,
                                'status': case['status'],
                                'controls': case['controls'],
                            }
                        )
                report['status'] = 'passed'
    except Exception as error:
        report.update(status='failed', error='%s: %s' % (type(error).__name__, error))
    finally:
        report['cleanup'] = {
            'temporary_root_removed': staging is None or not staging.exists(),
            'listener_closed': listener is None or listener.fileno() == -1,
        }
        if not all(report['cleanup'].values()):
            report['status'] = 'failed'
        capture.save_json(args.output / 'verification.json', report)
    capture.require(report['status'] == 'passed', report.get('error', 'Cleanup failed'))
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--wheel', type=Path, required=True)
    parser.add_argument('--wheel-sha256', required=True)
    parser.add_argument('--artifact-report', type=Path, required=True)
    parser.add_argument('--client-profile', required=True)
    parser.add_argument(
        '--profile-defaults',
        action='store_true',
        help='Assert Chrome 155 defaults without connection overrides',
    )
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args(argv)
    args.output = args.output.resolve()
    report = verify(args)
    print(
        'PASS: %d installed sync/async H2 cases, verified TLS, independent frame/HPACK bytes'
        % len(report['cases'])
    )


if __name__ == '__main__':
    main()
