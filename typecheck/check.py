"""Check positive and negative consumers outside the repository.

Run with the typing-tool environment, passing an independently installed wheel
environment with --python. --allow-source is an explicitly weaker development
precheck and must not be used for the installed-package acceptance.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile


PROBE = '''
import builtins
import json
from pathlib import Path
import sys

original_import = builtins.__import__
def checked_import(name, globals=None, locals=None, fromlist=(), level=0):
    caller = (globals or {}).get('__name__', '')
    if name == 'typing_extensions' and caller.startswith('ja3requests'):
        raise AssertionError('ja3requests imported typing_extensions at runtime')
    return original_import(name, globals, locals, fromlist, level)
builtins.__import__ = checked_import
import ja3requests
origin = Path(ja3requests.__file__).resolve()
assert origin.with_name('py.typed').is_file(), 'py.typed is missing from package'
assert ja3requests.TlsConfig.secure().verify_cert is True
assert ja3requests.Response().content == b''
print(json.dumps({'package': str(origin), 'runtime': sys.version.split()[0]}))
'''


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        '--python',
        default=sys.executable,
        help='Interpreter containing the installed wheel',
    )
    parser.add_argument(
        '--allow-source',
        action='store_true',
        help='Permit a source checkout for a development precheck only',
    )
    args = parser.parse_args()
    examples = Path(__file__).resolve().parent
    repository = examples.parent
    environment = os.environ.copy()
    environment.pop('PYTHONPATH', None)
    environment.pop('MYPYPATH', None)

    with tempfile.TemporaryDirectory(prefix='ja3requests-type-consumer-') as temporary:
        directory = Path(temporary)
        probe = subprocess.run(
            [args.python, '-I', '-c', PROBE],
            cwd=directory,
            env=environment,
            text=True,
            capture_output=True,
            check=False,
        )
        if probe.returncode:
            print(probe.stdout + probe.stderr, end='')
            return 1
        metadata = json.loads(probe.stdout)
        origin = Path(metadata['package'])
        if not args.allow_source and (
            repository in origin.parents
            or not any(
                part in ('site-packages', 'dist-packages') for part in origin.parts
            )
        ):
            raise SystemExit(
                'Installed-wheel check refused source/editable package: ' + str(origin)
            )
        if args.allow_source:
            environment['MYPYPATH'] = str(repository)
        print(
            json.dumps(
                dict(
                    metadata,
                    mode='source-precheck' if args.allow_source else 'installed-wheel',
                ),
                sort_keys=True,
            )
        )

        for filename in ('valid.py', 'invalid.py', 'consumer.ini'):
            shutil.copyfile(examples / filename, directory / filename)
        command = [
            sys.executable,
            '-m',
            'mypy',
            '--config-file',
            'consumer.ini',
            '--python-executable',
            args.python,
        ]
        valid = subprocess.run(
            command + ['valid.py'],
            cwd=directory,
            env=environment,
            text=True,
            capture_output=True,
            check=False,
        )
        print(valid.stdout + valid.stderr, end='')
        if valid.returncode:
            return 1
        invalid = subprocess.run(
            command + ['invalid.py'],
            cwd=directory,
            env=environment,
            text=True,
            capture_output=True,
            check=False,
        )
        print('Expected negative-consumer diagnostics:')
        print(invalid.stdout + invalid.stderr, end='')
        expected = {
            number: match.group(1)
            for number, line in enumerate(
                (directory / 'invalid.py').read_text().splitlines(), 1
            )
            for match in [re.search(r'# E: ([a-z-]+)', line)]
            if match
        }
        actual = {}
        for match in re.finditer(
            r'^invalid\.py:(\d+): error: .*\[([a-z-]+)\]$', invalid.stdout, re.MULTILINE
        ):
            actual.setdefault(int(match.group(1)), set()).add(match.group(2))
        missing = {
            line: code
            for line, code in expected.items()
            if code not in actual.get(line, set())
        }
        unexpected = sorted(set(actual) - set(expected))
        if invalid.returncode != 1 or missing or unexpected:
            print(
                'Negative-consumer mismatch:',
                {
                    'missing': missing,
                    'unmarked_error_lines': unexpected,
                    'exit': invalid.returncode,
                },
            )
            return 1
        print(
            'PASS: valid consumer and all %d negative diagnostic markers'
            % len(expected)
        )
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
