"""Verify local ja3requests artifacts from an explicit immutable source; never publish.

Tool interpreter: Python >=3.12. The library's Python >=3.7 contract is unchanged.
See tools/README.md for dependencies, provenance, retained evidence and limits.
"""

from __future__ import annotations

import argparse
import ast
import base64
import csv
from email.parser import BytesParser
import hashlib
import io
import json
import math
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import signal
import subprocess
import sys
import tarfile
import tempfile
import time
import xml.etree.ElementTree as ET
import zipfile

from packaging.requirements import Requirement
from packaging.utils import (
    canonicalize_name,
    parse_sdist_filename,
    parse_wheel_filename,
)
from packaging.version import Version


REQUIRED_SDIST = (
    'setup.py',
    'pyproject.toml',
    'MANIFEST.in',
    'README.md',
    'README-zh.md',
    'requirements.txt',
    'requirements-dev.txt',
    'requirements-typing.txt',
    'LICENSE',
    'CHANGELOG.md',
    'ja3requests/py.typed',
    'test/fixtures/wire_baseline.json',
    'test/fixtures/chrome154_macos_hello.json',
    'test/test_wire_review_boundaries.py',
    'docs/tls_wire_control.md',
    'docs/async.md',
    'test/test_async_redirect_review.py',
    'test/test_sync_redirect_review.py',
    'test/integration/test_async_tls.py',
    'test/integration/test_async_h2_network.py',
    'test/test_async_transport.py',
    'test/test_tls12_finished.py',
    'test/integration/test_local_tls12_finished.py',
    'typecheck/valid.py',
    'typecheck/invalid.py',
    'typecheck/check.py',
    'typecheck/consumer.ini',
)


class VerificationError(RuntimeError):
    """A required verification step did not pass."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise VerificationError(message)


def digest(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def clean_environment() -> dict[str, str]:
    environment = {
        key: value
        for key, value in os.environ.items()
        if not key.startswith(('PYTHON', 'PIP_', 'PYTEST_', 'COVERAGE_', 'MYPY'))
        and key
        not in (
            'VIRTUAL_ENV',
            '__PYVENV_LAUNCHER__',
            'GIT_DIR',
            'GIT_WORK_TREE',
            'GIT_INDEX_FILE',
            'GIT_COMMON_DIR',
            'GIT_OBJECT_DIRECTORY',
            'GIT_ALTERNATE_OBJECT_DIRECTORIES',
        )
    }
    environment.update(
        PIP_CONFIG_FILE=os.devnull,
        PIP_INDEX_URL='https://pypi.org/simple',
        PIP_NO_INPUT='1',
        PIP_DISABLE_PIP_VERSION_CHECK='1',
        PYTHONDONTWRITEBYTECODE='1',
        PYTHONNOUSERSITE='1',
    )
    return environment


def safe_path(name: str) -> bool:
    path = PurePosixPath(name)
    return (
        bool(name)
        and not path.is_absolute()
        and not any(part in ('', '.', '..') for part in name.split('/'))
        and '\\' not in name
    )


def excluded(name: str) -> bool:
    parts = PurePosixPath(name).parts
    return (
        any(
            part
            in (
                '.git',
                '.idea',
                '.DS_Store',
                '.venv',
                'venv',
                '__pycache__',
                'dist',
                'build',
                '.pytest_cache',
                '.mypy_cache',
                '.pypirc',
                '.netrc',
            )
            or part == '.env'
            or part.startswith('.env.')
            for part in parts
        )
        or name.endswith(('.pem', '.key', '.pyc', '.pyo'))
        or name.startswith('issues/release_')
        or name == 'compare_hello.py'
        or (name.startswith('test_') and '/' not in name)
    )


def git(repo: Path, *args: str) -> bytes:
    try:
        result = subprocess.run(
            ['git', '--no-replace-objects', '-C', str(repo), *args],
            env=clean_environment(),
            capture_output=True,
            timeout=60,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise VerificationError(
            'Git source inspection failed: ' + str(error)
        ) from error
    require(
        result.returncode == 0,
        'Git source inspection failed: ' + result.stderr.decode(errors='replace'),
    )
    return result.stdout


def resolve_commit(repo: Path, ref: str) -> str:
    commit = (
        git(repo, 'rev-parse', '--verify', '--end-of-options', ref + '^{commit}')
        .decode()
        .strip()
    )
    require(
        bool(re.fullmatch(r'[0-9a-f]{40}|[0-9a-f]{64}', commit)),
        'Expected a full commit identity',
    )
    return commit


def file_manifest(root: Path) -> dict[str, str]:
    result = {}
    for path in sorted(root.rglob('*')):
        require(not path.is_symlink(), 'Source symlink is not supported: ' + str(path))
        if path.is_file():
            result[path.relative_to(root).as_posix()] = digest(path.read_bytes())
    return result


def commit_blobs(repo: Path, commit: str) -> dict[str, str]:
    """Read original object IDs independently of git archive's attributes."""
    result = {}
    for entry in git(repo, 'ls-tree', '-rz', '--full-tree', commit).split(b'\0'):
        if not entry:
            continue
        metadata, raw_name = entry.split(b'\t', 1)
        mode, kind, object_id = metadata.decode('ascii').split()
        name = raw_name.decode('utf-8')
        require(safe_path(name), 'Unsafe commit tree path: ' + name)
        require(
            kind == 'blob' and mode in ('100644', '100755'),
            'Non-regular commit tree member: ' + name,
        )
        if not excluded(name):
            result[name] = object_id
    return result


def freeze_commit(repo: Path, ref: str, destination: Path) -> dict:
    commit = resolve_commit(repo, ref)
    blobs = commit_blobs(repo, commit)
    destination.mkdir(parents=True, exist_ok=False)
    # Archive the resolved object, not a moving symbolic ref. No repository writes.
    archive_bytes = git(repo, 'archive', '--format=tar', commit)
    with tarfile.open(fileobj=io.BytesIO(archive_bytes)) as archive:
        for member in archive.getmembers():
            name = member.name.rstrip('/')
            require(safe_path(name), 'Unsafe source archive path: ' + member.name)
            require(
                member.isfile() or member.isdir(),
                'Non-regular source archive member: ' + name,
            )
            if member.isdir() or excluded(name):
                continue
            target = destination / name
            require(not target.exists(), 'Duplicate source archive member: ' + name)
            target.parent.mkdir(parents=True, exist_ok=True)
            content = archive.extractfile(member)
            require(content is not None, 'Unreadable source archive member: ' + name)
            target.write_bytes(content.read())
    manifest = file_manifest(destination)
    require(
        set(manifest) == set(blobs),
        'Commit archive inventory differs from original tree; check export-ignore attributes',
    )
    for name, object_id in blobs.items():
        content = (destination / name).read_bytes()
        header = b'blob ' + str(len(content)).encode('ascii') + b'\0'
        algorithm = 'sha1' if len(object_id) == 40 else 'sha256'
        require(
            hashlib.new(algorithm, header + content).hexdigest() == object_id,
            'Commit archive bytes differ from original blob: ' + name,
        )
    return {
        'source_kind': 'commit',
        'commit': commit,
        'files': manifest,
    }


def worktree_inputs(repo: Path, extras: list[str]) -> dict[str, str]:
    tracked = set(git(repo, 'ls-files', '--cached', '-z').decode().split('\0')) - {''}
    extra = set(extras)
    for name in tracked | extra:
        require(safe_path(name), 'Expected a repository-relative file path: ' + name)
    for name in extra:
        require(name not in tracked, '--include must name an untracked file: ' + name)
        require(not excluded(name), 'Excluded snapshot input: ' + name)
        require((repo / name).is_file(), 'Missing explicit snapshot file: ' + name)
    result = {}
    for name in sorted(tracked | extra):
        if excluded(name):
            continue
        path = repo / name
        # Do not follow a symlink through any parent, even if it points in-repo.
        require(
            not any(
                p.is_symlink() for p in (path, *path.parents) if p.is_relative_to(repo)
            ),
            'Snapshot symlink is not supported: ' + name,
        )
        require(
            path.resolve().is_relative_to(repo.resolve()),
            'Input escapes repository: ' + name,
        )
        if not path.exists() and name in tracked:
            continue  # A stable tracked deletion belongs to the current snapshot.
        require(path.is_file(), 'Non-regular snapshot input: ' + name)
        result[name] = digest(path.read_bytes())
    return result


def freeze_worktree(repo: Path, extras: list[str], destination: Path) -> dict:
    base = resolve_commit(repo, 'HEAD')
    index_before = git(repo, 'ls-files', '--cached', '-z')
    before = worktree_inputs(repo, extras)
    destination.mkdir(parents=True, exist_ok=False)
    for name in before:
        target = destination / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(repo / name, target)
    after = worktree_inputs(repo, extras)
    require(
        before == after == file_manifest(destination),
        'Source drift while freezing worktree snapshot',
    )
    require(
        index_before == git(repo, 'ls-files', '--cached', '-z')
        and base == resolve_commit(repo, 'HEAD'),
        'Repository identity drift while freezing worktree snapshot',
    )
    return {
        'source_kind': 'worktree-snapshot',
        'base_commit': base,
        'explicit_new_files': sorted(extras),
        'files': before,
    }


def normalized_requirements(values: list[str]) -> list[str]:
    result = []
    for value in values:
        requirement = Requirement(value)
        require(
            requirement.url is None,
            'Direct dependency URLs are outside this compatibility contract',
        )
        result.append(
            str(
                Requirement(
                    canonicalize_name(requirement.name)
                    + str(requirement)[len(requirement.name) :]
                )
            )
        )
    return sorted(result)


def frozen_contract(source: Path) -> dict:
    # Parse data without importing the project or running setup.py in the tool.
    about = {}
    for node in ast.parse((source / 'ja3requests/__version__.py').read_bytes()).body:
        if (
            isinstance(node, ast.Assign)
            and len(node.targets) == 1
            and isinstance(node.targets[0], ast.Name)
        ):
            about[node.targets[0].id] = ast.literal_eval(node.value)
    tree = ast.parse((source / 'setup.py').read_bytes())
    setup_calls = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == 'setup'
    ]
    require(len(setup_calls) == 1, 'Expected exactly one setup() contract')
    keywords = {keyword.arg: keyword.value for keyword in setup_calls[0].keywords}
    requires_python = ast.literal_eval(keywords['python_requires'])
    dependencies = normalized_requirements(
        [
            line.strip()
            for line in (source / 'requirements.txt').read_text().splitlines()
            if line.strip() and not line.lstrip().startswith('#')
        ]
    )
    require(about['__title__'] == 'ja3requests', 'Unexpected project identity')
    require(requires_python == '>=3.7', 'Library minimum-Python contract changed')
    require(
        dependencies
        == normalized_requirements(['brotli>=1.2.0', 'cryptography>=42.0.0']),
        'Runtime dependency contract changed',
    )
    require('Apache' in about['__license__'], 'License contract changed')
    return {
        'name': about['__title__'],
        'version': str(Version(about['__version__'])),
        'requires_python': requires_python,
        'requires_dist': dependencies,
        'license': about['__license__'],
    }


def validate_metadata(content: bytes, expected: dict) -> None:
    metadata = BytesParser().parsebytes(content)
    for field, key in (
        ('Name', 'name'),
        ('Version', 'version'),
        ('Requires-Python', 'requires_python'),
        ('License', 'license'),
    ):
        require(
            metadata.get_all(field) == [expected[key]],
            'Metadata/source mismatch: ' + field,
        )
    require(
        normalized_requirements(metadata.get_all('Requires-Dist', []))
        == expected['requires_dist'],
        'Metadata/source mismatch: Requires-Dist',
    )


def read_sdist(path: Path, expected_prefix: str | None = None) -> dict[str, bytes]:
    result = {}
    with tarfile.open(path) as archive:
        roots = set()
        for member in archive.getmembers():
            name = member.name.rstrip('/')
            require(safe_path(name), 'Unsafe sdist path: ' + member.name)
            require(
                member.isfile() or member.isdir(), 'Non-regular sdist member: ' + name
            )
            parts = PurePosixPath(name).parts
            roots.add(parts[0])
            if member.isdir():
                continue
            require(len(parts) > 1, 'sdist file is outside archive prefix')
            relative = '/'.join(parts[1:])
            require(relative not in result, 'Duplicate sdist member: ' + relative)
            content = archive.extractfile(member)
            require(content is not None, 'Unreadable sdist member: ' + relative)
            result[relative] = content.read()
        require(len(roots) == 1, 'Expected one sdist archive prefix')
        if expected_prefix is not None:
            require(roots == {expected_prefix}, 'sdist archive prefix/source mismatch')
    return result


def read_wheel(path: Path) -> dict[str, bytes]:
    result = {}
    with zipfile.ZipFile(path) as archive:
        for entry in archive.infolist():
            name = entry.filename.rstrip('/')
            require(safe_path(name), 'Unsafe wheel path: ' + entry.filename)
            require(
                (entry.external_attr >> 16) & 0o170000 != 0o120000,
                'Wheel symlink: ' + name,
            )
            if entry.is_dir():
                continue
            require(name not in result, 'Duplicate wheel member: ' + name)
            result[name] = archive.read(entry)
    return result


def validate_record(files: dict[str, bytes], record: str) -> None:
    rows = list(csv.reader(io.StringIO(files[record].decode())))
    entries = {}
    for row in rows:
        require(
            len(row) == 3 and row[0] not in entries,
            'Invalid or duplicate wheel RECORD row',
        )
        entries[row[0]] = row[1:]
    require(set(entries) == set(files), 'Wheel RECORD inventory mismatch')
    for name, content in files.items():
        if name == record:
            require(entries[name] == ['', ''], 'RECORD must not hash itself')
            continue
        encoded = (
            base64.urlsafe_b64encode(hashlib.sha256(content).digest())
            .rstrip(b'=')
            .decode()
        )
        require(
            entries[name] == ['sha256=' + encoded, str(len(content))],
            'Wheel RECORD hash/size mismatch: ' + name,
        )


def validate_artifacts(source: Path, wheel: Path, sdist: Path) -> dict:
    expected = frozen_contract(source)
    wheel_name, wheel_version, _, tags = parse_wheel_filename(wheel.name)
    sdist_name, sdist_version = parse_sdist_filename(sdist.name)
    require(
        wheel_name == sdist_name == canonicalize_name(expected['name'])
        and wheel_version == sdist_version == Version(expected['version']),
        'Artifact filename/source mismatch',
    )
    require(
        {str(tag) for tag in tags} == {'py3-none-any'}, 'Expected a pure Python 3 wheel'
    )
    files = read_sdist(sdist, expected['name'] + '-' + expected['version'])
    wheel_files = read_wheel(wheel)
    source_files = {
        name: (source / name).read_bytes() for name in file_manifest(source)
    }
    modules = {
        name: content
        for name, content in source_files.items()
        if name.startswith('ja3requests/') and name.endswith('.py')
    }
    require(bool(modules), 'No frozen package modules')
    for label, inventory in (('sdist', files), ('wheel', wheel_files)):
        packaged = {
            name: content
            for name, content in inventory.items()
            if name.startswith('ja3requests/') and name.endswith('.py')
        }
        require(
            packaged == modules, label + ' package/source bytes or inventory mismatch'
        )
        require(
            inventory.get('ja3requests/py.typed') == b'',
            label + ' requires empty py.typed',
        )
        for name, content in inventory.items():
            require(not excluded(name), 'Excluded artifact content: ' + name)
            if name.startswith(('ja3requests/', 'test/')):
                require(
                    name in source_files,
                    label + ' package/test entry absent from frozen source: ' + name,
                )
            if name in source_files:
                require(
                    content == source_files[name],
                    label + ' source byte mismatch: ' + name,
                )
    required = set(REQUIRED_SDIST) | {
        name
        for name in source_files
        if (
            name.startswith('test/')
            and name.endswith(('.py', '.md', '.json'))
            or name.startswith('typecheck/')
            and name.endswith(('.py', '.ini', '.md'))
            or name.startswith('docs/')
            and name.endswith('.md')
        )
    }
    for name in required:
        require(
            name in source_files
            and name in files
            and files[name] == source_files[name],
            'Missing or changed required sdist/source file: ' + name,
        )
    require(
        source_files.get('ja3requests/py.typed') == b'',
        'Frozen source requires empty py.typed',
    )
    metadata_paths = [
        name for name in wheel_files if name.endswith('.dist-info/METADATA')
    ]
    require(len(metadata_paths) == 1, 'Expected one wheel metadata directory')
    dist_info = metadata_paths[0].rsplit('/', 1)[0]
    require(
        dist_info
        == expected['name'].replace('-', '_')
        + '-'
        + expected['version']
        + '.dist-info',
        'Wheel metadata directory/source mismatch',
    )
    require(
        all(name.startswith(('ja3requests/', dist_info + '/')) for name in wheel_files),
        'Unexpected wheel inventory outside package/metadata',
    )
    require(
        dist_info + '/RECORD' in wheel_files and dist_info + '/WHEEL' in wheel_files,
        'Missing wheel RECORD/WHEEL',
    )
    validate_metadata(wheel_files[metadata_paths[0]], expected)
    require('PKG-INFO' in files, 'Missing sdist metadata')
    validate_metadata(files['PKG-INFO'], expected)
    licenses = [
        content for name, content in wheel_files.items() if name.endswith('/LICENSE')
    ]
    require(licenses == [source_files['LICENSE']], 'Wheel/source license mismatch')
    validate_record(wheel_files, dist_info + '/RECORD')
    for name, content in modules.items():
        ast.parse(content, filename=name, feature_version=(3, 7))
    return {
        'contract': expected,
        'artifacts': {
            path.name: {
                'sha256': digest(path.read_bytes()),
                'size': path.stat().st_size,
            }
            for path in (wheel, sdist)
        },
        'source_hashes': {name: digest(content) for name, content in modules.items()},
        'inventories': {'wheel': sorted(wheel_files), 'sdist': sorted(files)},
        'python_3_7_grammar': 'passed; runtime matrix is separate CI evidence',
        'negative_type_markers': sum(
            bool(re.search(r'# E: ([a-z-]+)', line))
            for line in files['typecheck/invalid.py'].decode().splitlines()
        ),
    }


class Run:
    """Fresh output ownership and bounded subprocess evidence."""

    def __init__(self, output: Path, timeout: float):
        require(
            math.isfinite(timeout) and timeout > 0,
            'Command timeout must be finite and positive',
        )
        output.mkdir(parents=True, exist_ok=False)
        self.output = output.resolve()
        self.timeout = timeout
        self.report = {'status': 'running', 'checks': {}, 'tool_python': sys.version}
        self.save()

    def save(self) -> None:
        (self.output / 'verification.json').write_text(
            json.dumps(self.report, indent=2) + '\n'
        )

    def command(self, label: str, args: list, cwd: Path) -> str:
        require(
            bool(re.fullmatch(r'[a-z0-9-]+', label))
            and label not in self.report['checks'],
            'Command labels must be unique and safe',
        )
        log_path = self.output / (label + '.log')
        command = [str(arg) for arg in args]
        check = {
            'command': command,
            'cwd': str(cwd),
            'status': 'running',
            'log': log_path.name,
        }
        self.report['checks'][label] = check
        self.save()
        started = time.monotonic()
        temporary_path = None
        try:
            # Child tools such as build, pip and the typing checker create their
            # own temporary trees. Keep them under a root the parent can reclaim
            # even when killing the process group bypasses the child's finally.
            with tempfile.TemporaryDirectory(
                prefix='command-tmp-', dir=self.output
            ) as temporary:
                temporary_path = Path(temporary)
                check['temporary_directory'] = temporary
                self.save()
                environment = clean_environment()
                environment.update(TMPDIR=temporary, TEMP=temporary, TMP=temporary)
                with log_path.open('w') as log:
                    with subprocess.Popen(
                        command,
                        cwd=cwd,
                        env=environment,
                        stdout=log,
                        stderr=subprocess.STDOUT,
                        start_new_session=(os.name == 'posix'),
                    ) as process:
                        try:
                            code = process.wait(timeout=self.timeout)
                        except BaseException as error:
                            # Reap the child before reclaiming its temporary tree.
                            try:
                                if os.name == 'posix':
                                    os.killpg(process.pid, signal.SIGKILL)
                                else:
                                    process.kill()
                            except ProcessLookupError:
                                pass
                            process.wait()
                            check.update(
                                status=(
                                    'timeout'
                                    if isinstance(error, subprocess.TimeoutExpired)
                                    else 'failed'
                                ),
                                returncode=process.returncode,
                            )
                            if isinstance(error, subprocess.TimeoutExpired):
                                raise VerificationError(
                                    label + ' timed out; see ' + str(log_path)
                                ) from error
                            raise
            check.update(status='passed' if code == 0 else 'failed', returncode=code)
            require(code == 0, label + ' failed; see ' + str(log_path))
        except BaseException as error:
            if check['status'] == 'running':
                check.update(status='failed', error_type=type(error).__name__)
            self.report['status'] = 'failed'
            raise
        finally:
            if temporary_path is not None:
                check['temporary_cleaned'] = not temporary_path.exists()
            check['seconds'] = round(time.monotonic() - started, 3)
            self.save()
            print(label + ': ' + check['status'], flush=True)
        return log_path.read_text(errors='replace')


SMOKE = r'''
import hashlib
from importlib.metadata import version
import json
from pathlib import Path
import sys
import ja3requests
from ja3requests.__version__ import __version__
from ja3requests.protocol.h2.connection import H2Connection
from ja3requests.protocol.h2.frame import CONNECTION_PREFACE

expected = json.loads(Path(sys.argv[1]).read_text())
assert version('ja3requests') == __version__ == expected['contract']['version']
package = Path(ja3requests.__file__).resolve().parent
assert 'site-packages' in package.parts or 'dist-packages' in package.parts
assert package.is_relative_to(Path(sys.prefix).resolve())
actual = {'ja3requests/' + p.relative_to(package).as_posix():
          hashlib.sha256(p.read_bytes()).hexdigest() for p in package.rglob('*.py')}
assert actual == expected['source_hashes']
assert (package / 'py.typed').read_bytes() == b''
assert ja3requests.TlsConfig().verify_cert is True
assert ja3requests.TlsConfig.secure().verify_cert is True
assert all(getattr(ja3requests, name) for name in (
    'AsyncSession', 'AsyncResponse', 'AsyncConnectionPool'))
sent = []
connection = H2Connection(sent.append, lambda size: b'')
connection.initiate()
assert connection.send_request('GET', 'example.com', '/') == 1
assert sent[0] == CONNECTION_PREFACE and len(sent) == 3
print(json.dumps({'version': version('ja3requests'), 'origin': str(package),
                  'python': sys.version, 'module_count': len(actual),
                  'source_hashes': 'matched', 'secure_defaults': 'passed',
                  'async_exports': 'passed', 'h2_framing': 'passed'}))
'''


def test_summary(junit: Path, output: str) -> dict:
    suites = ET.parse(junit).getroot().iter('testsuite')
    summary = {key: 0 for key in ('tests', 'failures', 'errors', 'skipped')}
    for suite in suites:
        for key in summary:
            summary[key] += int(suite.attrib.get(key, '0'))
    # Pytest reports successful subtests separately from ordinary test cases.
    for pattern, key in (
        (r'(\d+) subtests passed', 'subtests_passed'),
        (r'(\d+) warnings?', 'warnings'),
        (r'(\d+) passed', 'passed'),
    ):
        matches = re.findall(pattern, output)
        summary[key] = int(matches[-1]) if matches else 0
    require(
        summary['tests'] > 0 and summary['failures'] == summary['errors'] == 0,
        'Empty or failed installed test report',
    )
    return summary


def verify_pipeline(args: argparse.Namespace, run: Run, staging: Path) -> None:
    source = staging / 'source'
    identity = (
        freeze_commit(args.repo, args.ref, source)
        if args.ref is not None
        else freeze_worktree(args.repo, args.include, source)
    )
    run.report['source'] = identity
    run.save()
    (run.output / 'source-manifest.json').write_text(
        json.dumps(identity, indent=2) + '\n'
    )
    run.report['contract'] = frozen_contract(source)
    artifacts = run.output / 'artifacts'
    artifacts.mkdir()
    # Build hooks write metadata/caches; never let them redefine the source used
    # for comparison. The frozen tree remains separate from the build workspace.
    build_source = staging / 'build-source'
    shutil.copytree(source, build_source)
    # PyPA build's default is sdist, then wheel from that sdist (not the checkout).
    run.command(
        'build', [sys.executable, '-m', 'build', '--outdir', artifacts], build_source
    )
    wheels, sdists = list(artifacts.glob('*.whl')), list(artifacts.glob('*.tar.gz'))
    require(
        len(wheels) == len(sdists) == 1 and len(list(artifacts.iterdir())) == 2,
        'Expected exactly one sdist and its wheel',
    )
    wheel, sdist = wheels[0], sdists[0]
    run.command(
        'metadata',
        [sys.executable, '-m', 'twine', 'check', '--strict', wheel, sdist],
        staging,
    )
    run.report.update(validate_artifacts(source, wheel, sdist))
    # No additions, deletions or rewrites may redefine the accepted source.
    require(
        file_manifest(source) == identity['files'],
        'Frozen source changed during build',
    )
    run.save()
    installed = staging / 'installed'
    run.command('venv', [sys.executable, '-m', 'venv', installed], staging)
    python = installed / ('Scripts/python.exe' if os.name == 'nt' else 'bin/python')
    run.command(
        'install',
        [
            python,
            '-m',
            'pip',
            'install',
            '--index-url',
            'https://pypi.org/simple',
            wheel,
            'pytest',
            'pytest-cov',
        ],
        staging,
    )
    run.command('dependencies', [python, '-m', 'pip', 'check'], staging)
    smoke = run.command(
        'smoke', [python, '-I', '-c', SMOKE, run.output / 'verification.json'], staging
    )
    run.report['installed'] = json.loads(smoke)
    run.command('freeze', [python, '-m', 'pip', 'freeze', '--all'], staging)
    run.command(
        'tool-versions',
        [sys.executable, '-m', 'pip', 'show', 'build', 'twine', 'mypy', 'packaging'],
        staging,
    )
    run.command(
        'typing',
        [sys.executable, '-B', source / 'typecheck/check.py', '--python', python],
        staging,
    )
    destination = staging / 'run'
    destination.mkdir()
    for name, content in read_sdist(sdist).items():
        if name.startswith('test/'):
            target = destination / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(content)
    require(
        not (destination / 'ja3requests').exists(),
        'Installed test directory contains package source',
    )
    output = run.command(
        'pytest',
        [
            python,
            '-B',
            '-m',
            'pytest',
            'test',
            '--ignore=test/test_session.py',
            '--cov=ja3requests',
            '--cov-report=term',
            '--cov-report=json:' + str(run.output / 'coverage.json'),
            '--cov-fail-under=85',
            '--junitxml=' + str(run.output / 'installed.xml'),
            '--basetemp=' + str(staging / 'pytest-tmp'),
            '-p',
            'no:cacheprovider',
            '-q',
        ],
        destination,
    )
    run.report['coverage'] = json.loads((run.output / 'coverage.json').read_text())[
        'totals'
    ]
    require(
        run.report['coverage']['percent_covered'] >= 85,
        'Installed coverage is below 85%',
    )
    run.report['tests'] = test_summary(run.output / 'installed.xml', output)


def run_verification(args: argparse.Namespace) -> int:
    # Refuse output conflicts before any builds, and never replace prior evidence.
    run = Run(args.output, args.timeout)
    try:
        with tempfile.TemporaryDirectory(prefix='ja3requests-verify-') as temporary:
            staging = Path(temporary)
            run.report['staging'] = str(staging)
            run.save()
            try:
                verify_pipeline(args, run, staging)
            finally:
                source = staging / 'source'
                if source.exists() and 'source' not in run.report:
                    # Preserve partial collector evidence even when freezing fails.
                    run.report['partial_source_hashes'] = file_manifest(source)
        run.report['status'] = 'passed'
        run.report['staging_cleaned'] = True
        return 0
    except BaseException as error:
        run.report.update(
            status='failed', error_type=type(error).__name__, error=str(error)
        )
        run.report['staging_cleaned'] = not Path(run.report.get('staging', '')).exists()
        print(type(error).__name__ + ': ' + str(error), file=sys.stderr)
        if isinstance(error, (KeyboardInterrupt, SystemExit)):
            raise
        return 1
    finally:
        run.save()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repo', type=Path, default=Path.cwd())
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument('--ref', help='Commit/ref to resolve and archive')
    source.add_argument(
        '--worktree-snapshot', action='store_true', help='Freeze tracked current bytes'
    )
    parser.add_argument(
        '--include',
        action='append',
        default=[],
        metavar='RELATIVE_FILE',
        help='Explicit new snapshot file; repeat per file, never auto-include untracked files',
    )
    parser.add_argument(
        '--output',
        type=Path,
        required=True,
        help='New evidence directory (must not exist)',
    )
    parser.add_argument(
        '--timeout', type=float, default=600, help='Per-command timeout in seconds'
    )
    args = parser.parse_args(argv)
    if sys.version_info < (3, 12):
        parser.error(
            'The verifier needs Python >=3.12; the library still supports >=3.7'
        )
    if args.include and not args.worktree_snapshot:
        parser.error('--include requires --worktree-snapshot')
    if not math.isfinite(args.timeout) or args.timeout <= 0:
        parser.error('--timeout must be finite and positive')
    args.repo = args.repo.resolve()
    args.output = args.output.absolute()
    try:
        require(
            Path(
                git(args.repo, 'rev-parse', '--show-toplevel').decode().strip()
            ).resolve()
            == args.repo,
            '--repo must be the Git repository root',
        )
        return run_verification(args)
    except (OSError, VerificationError) as error:
        print(type(error).__name__ + ': ' + str(error), file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
