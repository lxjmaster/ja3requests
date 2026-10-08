"""Focused, offline boundary tests for the local artifact verifier."""

import argparse
import base64
import csv
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import zipfile

import pytest


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "verify_release", ROOT / "tools" / "verify_release.py"
)
assert SPEC is not None and SPEC.loader is not None
verify = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = verify
SPEC.loader.exec_module(verify)


def write_file(root, name, content):
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content)
    return path


def git(repo, *arguments):
    return subprocess.check_output(
        ["git", "-C", str(repo), *arguments], stderr=subprocess.STDOUT, text=True
    ).strip()


def hashes(root):
    return {
        path.relative_to(root).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in root.rglob("*")
        if path.is_file()
    }


@pytest.fixture
def repository(tmp_path):
    repo = tmp_path / "repository"
    repo.mkdir()
    git(repo, "-c", "init.templateDir=", "init", "-q")
    git(repo, "config", "user.name", "Verifier test fixture")
    git(repo, "config", "user.email", "verifier-fixture@example.invalid")
    write_file(repo, "README.md", b"Committed readme\n")
    write_file(repo, "ja3requests/__init__.py", b"VALUE = 'committed'\n")
    git(repo, "add", "README.md", "ja3requests/__init__.py")
    git(repo, "commit", "-qm", "Create isolated verifier fixture")
    return repo


def test_commit_freezes_exact_ref_not_dirty_worktree(repository, tmp_path):
    expected_commit = git(repository, "rev-parse", "HEAD")
    write_file(repository, "README.md", b"Uncommitted edit\n")
    write_file(repository, "docs/untracked.md", b"Untracked\n")
    destination = tmp_path / "source"

    identity = verify.freeze_commit(repository, "HEAD", destination)

    assert identity["source_kind"] == "commit"
    assert identity["commit"] == expected_commit
    assert len(identity["commit"]) == 40
    assert identity["files"] == hashes(destination)
    assert (destination / "README.md").read_bytes() == b"Committed readme\n"
    assert not (destination / "docs/untracked.md").exists()
    assert not (destination / ".git").exists()
    assert (repository / "README.md").read_bytes() == b"Uncommitted edit\n"


def test_commit_ignores_commit_replacement_without_changing_repository(
    repository, tmp_path
):
    original = git(repository, "rev-parse", "HEAD")
    expected_files = {
        "README.md": b"Committed readme\n",
        "ja3requests/__init__.py": b"VALUE = 'committed'\n",
    }
    write_file(repository, "README.md", b"Replacement commit readme\n")
    write_file(repository, "ja3requests/replacement.py", b"REPLACED = True\n")
    git(repository, "add", "README.md", "ja3requests/replacement.py")
    git(repository, "commit", "-qm", "Create replacement commit")
    replacement = git(repository, "rev-parse", "HEAD")
    git(repository, "replace", original, replacement)
    assert git(repository, "show", original + ":README.md") == (
        "Replacement commit readme"
    )
    destination = tmp_path / "source"

    identity = verify.freeze_commit(repository, original, destination)

    assert identity["commit"] == original
    assert identity["files"] == {
        name: hashlib.sha256(content).hexdigest()
        for name, content in expected_files.items()
    }
    assert {
        name: (destination / name).read_bytes() for name in identity["files"]
    } == expected_files
    assert not (destination / "ja3requests/replacement.py").exists()
    assert git(repository, "replace", "-l") == original
    assert git(repository, "rev-parse", "HEAD") == replacement


def test_commit_ignores_blob_replacement(repository, tmp_path):
    commit = git(repository, "rev-parse", "HEAD")
    original_blob = git(repository, "rev-parse", "HEAD:README.md")
    replacement_file = write_file(
        tmp_path, "replacement-readme.md", b"Replacement blob readme\n"
    )
    replacement_blob = git(repository, "hash-object", "-w", str(replacement_file))
    git(repository, "replace", original_blob, replacement_blob)
    assert git(repository, "cat-file", "blob", original_blob) == (
        "Replacement blob readme"
    )
    destination = tmp_path / "source"

    identity = verify.freeze_commit(repository, commit, destination)

    assert identity["commit"] == commit
    assert (destination / "README.md").read_bytes() == b"Committed readme\n"
    assert identity["files"] == hashes(destination)
    assert git(repository, "replace", "-l") == original_blob


def test_commit_rejects_local_export_ignore(repository, tmp_path):
    write_file(repository, ".git/info/attributes", b"README.md export-ignore\n")

    with pytest.raises(verify.VerificationError, match="(?i)archive|source|commit"):
        verify.freeze_commit(repository, "HEAD", tmp_path / "source")

    assert (repository / "README.md").read_bytes() == b"Committed readme\n"


def test_commit_rejects_local_export_substitution(repository, tmp_path):
    original = b"Commit: $Format:%H$\n"
    write_file(repository, "README.md", original)
    git(repository, "add", "README.md")
    git(repository, "commit", "-qm", "Add an archive substitution placeholder")
    write_file(repository, ".git/info/attributes", b"README.md export-subst\n")

    with pytest.raises(verify.VerificationError, match="(?i)archive|source|commit"):
        verify.freeze_commit(repository, "HEAD", tmp_path / "source")

    assert (repository / "README.md").read_bytes() == original


@pytest.mark.parametrize("ref", ["nonexistent-verifier-ref", "f" * 40])
def test_commit_rejects_unknown_ref(repository, tmp_path, ref):
    with pytest.raises(verify.VerificationError):
        verify.freeze_commit(repository, ref, tmp_path / "source")


def test_snapshot_uses_current_tracked_bytes_and_only_explicit_extras(
    repository, tmp_path
):
    expected_base = git(repository, "rev-parse", "HEAD")
    write_file(repository, "ja3requests/__init__.py", b"VALUE = 'candidate'\n")
    write_file(repository, "docs/candidate.md", b"Explicit candidate file\n")
    write_file(repository, "docs/unselected.md", b"Not selected\n")
    write_file(repository, ".pypirc", b"Private fixture, not a real credential\n")
    write_file(repository, ".idea/workspace.xml", b"Local IDE data\n")
    write_file(repository, "dist/old.whl", b"Local build output\n")
    destination = tmp_path / "source"

    identity = verify.freeze_worktree(repository, ["docs/candidate.md"], destination)

    assert identity["source_kind"] == "worktree-snapshot"
    assert identity["base_commit"] == expected_base
    assert not identity.get("commit")
    assert identity["files"] == hashes(destination)
    assert set(identity["files"]) == {
        "README.md",
        "ja3requests/__init__.py",
        "docs/candidate.md",
    }
    assert (destination / "ja3requests/__init__.py").read_bytes() == (
        b"VALUE = 'candidate'\n"
    )
    assert git(repository, "rev-parse", "HEAD") == expected_base


@pytest.mark.parametrize("change", ["edit", "delete", "add-tracked"])
def test_snapshot_rejects_source_drift_during_copy(
    repository, tmp_path, monkeypatch, change
):
    original_copy = verify.shutil.copyfile
    changed = False

    def drifting_copy(source, destination, *args, **kwargs):
        nonlocal changed
        result = original_copy(source, destination, *args, **kwargs)
        if not changed:
            changed = True
            if change == "edit":
                write_file(repository, "README.md", b"Changed during collection\n")
            elif change == "delete":
                (repository / "README.md").unlink()
            else:
                write_file(repository, "docs/newly-tracked.md", b"New tracked input\n")
                git(repository, "add", "docs/newly-tracked.md")
        return result

    monkeypatch.setattr(verify.shutil, "copyfile", drifting_copy)
    with pytest.raises(verify.VerificationError):
        verify.freeze_worktree(repository, [], tmp_path / "source")
    assert changed


@pytest.mark.parametrize(
    "extra",
    [".pypirc", ".idea/workspace.xml", "dist/local.whl", "issues/release_local.md"],
)
def test_snapshot_rejects_explicit_excluded_inputs(repository, tmp_path, extra):
    write_file(repository, extra, b"Excluded local input\n")
    with pytest.raises(verify.VerificationError):
        verify.freeze_worktree(repository, [extra], tmp_path / "source")


def test_snapshot_rejects_extra_outside_repository(repository, tmp_path):
    write_file(tmp_path, "outside.py", b"Not a repository input\n")
    with pytest.raises(verify.VerificationError):
        verify.freeze_worktree(repository, ["../outside.py"], tmp_path / "source")


def test_snapshot_preserves_stable_tracked_deletion(repository, tmp_path):
    (repository / "README.md").unlink()
    destination = tmp_path / "source"

    identity = verify.freeze_worktree(repository, [], destination)

    assert identity["files"] == hashes(destination)
    assert set(identity["files"]) == {"ja3requests/__init__.py"}
    assert not (repository / "README.md").exists()


def test_snapshot_rejects_symlink_input(repository, tmp_path):
    target = write_file(tmp_path, "external.md", b"External source\n")
    (repository / "linked.md").symlink_to(target)

    with pytest.raises(verify.VerificationError):
        verify.freeze_worktree(repository, ["linked.md"], tmp_path / "source")


def metadata(contract, **changes):
    fields = dict(contract)
    fields.update(changes)
    lines = [
        "Metadata-Version: 2.4",
        "Name: " + fields["name"],
        "Version: " + fields["version"],
        "Requires-Python: " + fields["requires_python"],
        "License: " + fields["license"],
    ]
    lines.extend("Requires-Dist: " + value for value in fields["requires_dist"])
    return ("\n".join(lines) + "\n\n").encode()


@pytest.fixture
def contract():
    return {
        "name": "ja3requests",
        "version": "7.8.9",
        "requires_python": ">=3.7",
        "requires_dist": ["brotli>=1.2.0", "cryptography>=42.0.0"],
        "license": "Apache-2.0 license",
    }


def test_metadata_matches_frozen_contract_with_dynamic_version(contract):
    verify.validate_metadata(metadata(contract), contract)


@pytest.mark.parametrize(
    "changes",
    [
        {"name": "different-project"},
        {"version": "7.8.10"},
        {"requires_python": ">=3.12"},
        {"requires_dist": ["brotli>=1.2.0"]},
        {"requires_dist": ["brotli>=1.2.0", "cryptography>=43.0.0"]},
        {"license": "MIT"},
    ],
)
def test_metadata_rejects_mismatch_with_source(contract, changes):
    with pytest.raises(verify.VerificationError):
        verify.validate_metadata(metadata(contract, **changes), contract)


@pytest.fixture
def artifact_source(tmp_path, contract):
    source = tmp_path / "artifact-source"
    source.mkdir()
    for relative in verify.REQUIRED_SDIST:
        if relative.endswith(".json"):
            content = b"{}\n"
        elif relative.endswith(".ini"):
            content = b"[mypy]\n"
        else:
            content = b"# Required artifact fixture\n"
        write_file(source, relative, content)
    write_file(source, "setup.py", (ROOT / "setup.py").read_bytes())
    write_file(source, "LICENSE", (ROOT / "LICENSE").read_bytes())
    write_file(source, "README.md", b"# ja3requests verifier fixture\n")
    write_file(
        source,
        "requirements.txt",
        ("\n".join(contract["requires_dist"]) + "\n").encode(),
    )
    write_file(source, "ja3requests/__init__.py", b"VALUE = 'frozen source'\n")
    write_file(
        source,
        "ja3requests/__version__.py",
        (
            "__title__ = 'ja3requests'\n"
            "__version__ = '7.8.9'\n"
            "__license__ = 'Apache-2.0 license'\n"
        ).encode(),
    )
    write_file(source, "ja3requests/py.typed", b"")
    write_file(
        source,
        "typecheck/invalid.py",
        b"first: int = 'bad'  # E: assignment\n" b"second: str = 1  # E: assignment\n",
    )
    return source


def wheel_record(files, record_name):
    stream = io.StringIO(newline="")
    writer = csv.writer(stream, lineterminator="\n")
    for name, content in sorted(files.items()):
        digest = base64.urlsafe_b64encode(hashlib.sha256(content).digest())
        writer.writerow([name, "sha256=" + digest.decode().rstrip("="), len(content)])
    writer.writerow([record_name, "", ""])
    return stream.getvalue().encode()


@pytest.fixture
def make_artifacts(artifact_source, tmp_path, contract):
    def build(
        wheel_changes=None, sdist_changes=None, record_change=None, sdist_prefix=None
    ):
        prefix = contract["name"] + "-" + contract["version"]
        dist_info = prefix + ".dist-info"
        wheel = tmp_path / (prefix + "-py3-none-any.whl")
        sdist = tmp_path / (prefix + ".tar.gz")
        source_files = {
            path.relative_to(artifact_source).as_posix(): path.read_bytes()
            for path in artifact_source.rglob("*")
            if path.is_file()
        }
        wheel_files = {
            name: content
            for name, content in source_files.items()
            if name.startswith("ja3requests/")
        }
        wheel_files.update(
            {
                dist_info + "/METADATA": metadata(contract),
                dist_info
                + "/WHEEL": (
                    b"Wheel-Version: 1.0\nGenerator: verifier-test-fixture\n"
                    b"Root-Is-Purelib: true\nTag: py3-none-any\n"
                ),
                dist_info + "/licenses/LICENSE": source_files["LICENSE"],
            }
        )
        sdist_files = dict(source_files, **{"PKG-INFO": metadata(contract)})
        for files, changes in (
            (wheel_files, wheel_changes or {}),
            (sdist_files, sdist_changes or {}),
        ):
            for name, content in changes.items():
                if content is None:
                    files.pop(name)
                else:
                    files[name] = content
        record_name = dist_info + "/RECORD"
        record = wheel_record(wheel_files, record_name)
        if record_change is not None:
            record = record_change(record)
        wheel_files[record_name] = record
        with zipfile.ZipFile(wheel, "w") as archive:
            for name, content in wheel_files.items():
                archive.writestr(name, content)
        with tarfile.open(sdist, "w:gz") as archive:
            for name, content in sdist_files.items():
                member = tarfile.TarInfo((sdist_prefix or prefix) + "/" + name)
                member.size = len(content)
                archive.addfile(member, io.BytesIO(content))
        return wheel, sdist

    return build


def test_artifacts_validate_against_dynamic_frozen_source(
    artifact_source, make_artifacts, contract
):
    wheel, sdist = make_artifacts()

    expected = verify.frozen_contract(artifact_source)
    result = verify.validate_artifacts(artifact_source, wheel, sdist)

    for key, value in contract.items():
        assert expected[key] == value
    assert result["contract"] == expected
    assert result["negative_type_markers"] == 2
    assert result["source_hashes"] == {
        name: value
        for name, value in hashes(artifact_source).items()
        if name.startswith("ja3requests/") and name.endswith(".py")
    }
    assert set(result["artifacts"]) == {wheel.name, sdist.name}
    for artifact in (wheel, sdist):
        assert result["artifacts"][artifact.name] == {
            "sha256": hashlib.sha256(artifact.read_bytes()).hexdigest(),
            "size": artifact.stat().st_size,
        }


@pytest.mark.parametrize("archive", ["wheel", "sdist"])
@pytest.mark.parametrize("content", [None, b"not an empty marker\n"])
def test_artifacts_require_empty_py_typed(
    artifact_source, make_artifacts, archive, content
):
    changes = {"ja3requests/py.typed": content}
    wheel, sdist = make_artifacts(**{archive + "_changes": changes})

    with pytest.raises(verify.VerificationError):
        verify.validate_artifacts(artifact_source, wheel, sdist)


def test_artifacts_require_sdist_test_contents(artifact_source, make_artifacts):
    required = next(name for name in verify.REQUIRED_SDIST if name.startswith("test/"))
    wheel, sdist = make_artifacts(sdist_changes={required: None})

    with pytest.raises(verify.VerificationError):
        verify.validate_artifacts(artifact_source, wheel, sdist)


@pytest.mark.parametrize(
    "relative, content",
    [
        (
            "test/conftest.py",
            b"def pytest_collection_modifyitems(items):\n    items.clear()\n",
        ),
        ("test/pytest.ini", b"[pytest]\npython_files = selected_only.py\n"),
        ("test/ja3requests/__init__.py", b"UNFROZEN_SHADOW_PACKAGE = True\n"),
    ],
)
def test_artifacts_reject_unfrozen_test_entries(
    artifact_source, make_artifacts, relative, content
):
    wheel, sdist = make_artifacts(sdist_changes={relative: content})

    with pytest.raises(verify.VerificationError):
        verify.validate_artifacts(artifact_source, wheel, sdist)


@pytest.mark.parametrize(
    "relative, content",
    [
        ("test/conftest.py", b"# Intentional frozen test configuration\n"),
        ("test/pytest.ini", b"[pytest]\naddopts = -ra\n"),
    ],
)
def test_artifacts_accept_test_hooks_matching_frozen_source(
    artifact_source, make_artifacts, relative, content
):
    write_file(artifact_source, relative, content)
    wheel, sdist = make_artifacts()

    result = verify.validate_artifacts(artifact_source, wheel, sdist)

    assert relative in result["inventories"]["sdist"]


@pytest.mark.parametrize("relative", ["test/conftest.py", "test/pytest.ini"])
def test_artifacts_reject_changed_frozen_test_hooks(
    artifact_source, make_artifacts, relative
):
    write_file(artifact_source, relative, b"# Frozen test configuration\n")
    wheel, sdist = make_artifacts(
        sdist_changes={relative: b"# Changed test configuration\n"}
    )

    with pytest.raises(verify.VerificationError):
        verify.validate_artifacts(artifact_source, wheel, sdist)


@pytest.mark.parametrize("archive", ["wheel", "sdist"])
def test_artifacts_detect_module_tamper_even_with_valid_wheel_record(
    artifact_source, make_artifacts, archive
):
    wheel, sdist = make_artifacts(
        **{archive + "_changes": {"ja3requests/__init__.py": b"VALUE = 'tampered'\n"}}
    )

    with pytest.raises(verify.VerificationError):
        verify.validate_artifacts(artifact_source, wheel, sdist)


def test_artifacts_compare_metadata_with_source_not_just_each_other(
    artifact_source, make_artifacts, contract
):
    wrong_metadata = metadata(contract, requires_python=">=3.12")
    wheel, sdist = make_artifacts(
        wheel_changes={"ja3requests-7.8.9.dist-info/METADATA": wrong_metadata},
        sdist_changes={"PKG-INFO": wrong_metadata},
    )

    with pytest.raises(verify.VerificationError):
        verify.validate_artifacts(artifact_source, wheel, sdist)


@pytest.mark.parametrize("field", ["hash", "size", "missing-row"])
def test_artifacts_reject_invalid_wheel_record(artifact_source, make_artifacts, field):
    def change_record(content):
        rows = list(csv.reader(io.StringIO(content.decode())))
        row = next(row for row in rows if row[0] == "ja3requests/__init__.py")
        if field == "hash":
            row[1] = "sha256=" + "A" * 43
        elif field == "size":
            row[2] = str(int(row[2]) + 1)
        else:
            rows.remove(row)
        output = io.StringIO(newline="")
        csv.writer(output, lineterminator="\n").writerows(rows)
        return output.getvalue().encode()

    wheel, sdist = make_artifacts(record_change=change_record)
    with pytest.raises(verify.VerificationError):
        verify.validate_artifacts(artifact_source, wheel, sdist)


def test_artifacts_detect_frozen_source_change(artifact_source, make_artifacts):
    wheel, sdist = make_artifacts()
    write_file(
        artifact_source, "ja3requests/__init__.py", b"VALUE = 'changed source'\n"
    )

    with pytest.raises(verify.VerificationError):
        verify.validate_artifacts(artifact_source, wheel, sdist)


def test_artifacts_reject_sdist_prefix_mismatch(artifact_source, make_artifacts):
    wheel, sdist = make_artifacts(sdist_prefix="different-project-0.0.1")

    with pytest.raises(verify.VerificationError):
        verify.validate_artifacts(artifact_source, wheel, sdist)


@pytest.mark.parametrize("archive", ["wheel", "sdist"])
def test_artifacts_reject_unexpected_package_binary(
    artifact_source, make_artifacts, archive
):
    wheel, sdist = make_artifacts(
        **{archive + "_changes": {"ja3requests/__init__.so": b"not frozen source"}}
    )

    with pytest.raises(verify.VerificationError):
        verify.validate_artifacts(artifact_source, wheel, sdist)


def test_build_generated_module_cannot_redefine_frozen_source(
    artifact_source, make_artifacts, tmp_path, monkeypatch
):
    staging = tmp_path / "staging"
    staging.mkdir()
    run = verify.Run(tmp_path / "evidence", timeout=5)
    expected_hashes = hashes(artifact_source)
    commands = []
    generated_name = "ja3requests/build_generated.py"
    generated_content = b"GENERATED_DURING_BUILD = True\n"

    def frozen_fixture(repo, ref, destination):
        assert repo == artifact_source
        assert ref == "HEAD"
        shutil.copytree(artifact_source, destination)
        return {
            "source_kind": "commit",
            "commit": "f" * 40,
            "files": expected_hashes,
        }

    def fake_command(label, arguments, cwd):
        commands.append(label)
        if label == "build":
            write_file(cwd, generated_name, generated_content)
            wheel, sdist = make_artifacts(
                wheel_changes={generated_name: generated_content},
                sdist_changes={generated_name: generated_content},
            )
            artifacts = Path(arguments[arguments.index("--outdir") + 1])
            for artifact in (wheel, sdist):
                shutil.copyfile(artifact, artifacts / artifact.name)
        else:
            assert (
                label == "metadata"
            ), "Unverified generated code must not be installed"
        return ""

    monkeypatch.setattr(verify, "freeze_commit", frozen_fixture)
    monkeypatch.setattr(run, "command", fake_command)
    arguments = argparse.Namespace(repo=artifact_source, ref="HEAD", include=[])

    with pytest.raises(verify.VerificationError, match="package/source"):
        verify.verify_pipeline(arguments, run, staging)

    assert commands == ["build", "metadata"]
    assert hashes(staging / "source") == expected_hashes
    assert not (staging / "source" / generated_name).exists()
    assert (staging / "build-source" / generated_name).read_bytes() == generated_content


def test_run_refuses_existing_output_without_overwrite(tmp_path):
    output = tmp_path / "evidence"
    output.mkdir()
    sentinel = write_file(output, "keep.txt", b"Prior evidence\n")

    with pytest.raises((FileExistsError, verify.VerificationError)):
        verify.Run(output, timeout=1)

    assert sentinel.read_bytes() == b"Prior evidence\n"
    assert list(output.iterdir()) == [sentinel]


def test_run_success_retains_output_and_does_not_complete_pipeline(tmp_path):
    run = verify.Run(tmp_path / "evidence", timeout=5)

    output = run.command(
        "successful-command",
        [sys.executable, "-c", "print('command evidence')"],
        tmp_path,
    )
    run.save()

    assert "command evidence" in output
    assert run.report["status"] == "running"
    report = json.loads((tmp_path / "evidence/verification.json").read_text())
    assert report["status"] == "running"
    assert report["checks"]["successful-command"]["status"] == "passed"
    assert report["checks"]["successful-command"]["returncode"] == 0
    assert (
        "command evidence" in (tmp_path / "evidence/successful-command.log").read_text()
    )


@pytest.mark.parametrize("failure", ["exit", "timeout"])
def test_run_failure_retains_evidence_and_never_passes(tmp_path, failure):
    run = verify.Run(tmp_path / "evidence", timeout=1)
    program = (
        "print('failure evidence', flush=True); raise SystemExit(7)"
        if failure == "exit"
        else "import time; print('timeout evidence', flush=True); time.sleep(10)"
    )

    with pytest.raises(verify.VerificationError):
        run.command(failure, [sys.executable, "-c", program], tmp_path)
    run.save()

    assert run.report["status"] == "failed"
    report = json.loads((tmp_path / "evidence/verification.json").read_text())
    assert report["status"] == "failed"
    assert report["checks"][failure]["status"] == (
        "failed" if failure == "exit" else "timeout"
    )
    if failure == "exit":
        assert report["checks"][failure]["returncode"] == 7
    else:
        assert report["checks"][failure]["returncode"] != 0
    assert "evidence" in (tmp_path / "evidence" / (failure + ".log")).read_text()


@pytest.mark.parametrize("outcome", ["success", "exit", "timeout"])
def test_run_cleans_child_temporary_directories_and_overrides_external_roots(
    tmp_path, monkeypatch, outcome
):
    external_roots = []
    for name in ("TMPDIR", "TEMP", "TMP"):
        external = tmp_path / ("external-" + name)
        external.mkdir()
        external_roots.append(external)
        monkeypatch.setenv(name, str(external))
    run = verify.Run(tmp_path / "evidence", timeout=1)
    program = (
        "import json, os, pathlib, tempfile, time; "
        "child = tempfile.TemporaryDirectory(prefix='child-owned-'); "
        "pathlib.Path(child.name, 'evidence.txt').write_text('owned child data'); "
        "print(json.dumps({'child': child.name, "
        "'environment': {name: os.environ[name] "
        "for name in ('TMPDIR', 'TEMP', 'TMP')}}), flush=True); "
    )
    if outcome == "timeout":
        program += "time.sleep(30)"
    else:
        # Bypass the child's own finalizers to exercise parent-owned cleanup.
        program += "os._exit(" + ("0" if outcome == "success" else "7") + ")"

    if outcome == "success":
        run.command(outcome, [sys.executable, "-c", program], tmp_path)
    else:
        with pytest.raises(verify.VerificationError):
            run.command(outcome, [sys.executable, "-c", program], tmp_path)

    report = json.loads((run.output / "verification.json").read_text())
    check = report["checks"][outcome]
    evidence = json.loads((run.output / (outcome + ".log")).read_text())
    owned_root = Path(check["temporary_directory"])
    child = Path(evidence["child"])
    assert owned_root.parent == run.output
    assert owned_root.name.startswith("command-tmp-")
    assert child.is_relative_to(owned_root)
    assert evidence["environment"] == {
        name: str(owned_root) for name in ("TMPDIR", "TEMP", "TMP")
    }
    assert check["temporary_cleaned"] is True
    assert not owned_root.exists()
    assert not child.exists()
    assert all(not list(external.iterdir()) for external in external_roots)
    assert (
        check["status"]
        == {
            "success": "passed",
            "exit": "failed",
            "timeout": "timeout",
        }[outcome]
    )
    assert report["status"] == ("running" if outcome == "success" else "failed")


def test_run_cleans_owned_temporary_directory_after_spawn_failure(
    tmp_path, monkeypatch
):
    captured_roots = []

    def failed_spawn(*_args, **kwargs):
        owned_root = Path(kwargs["env"]["TMPDIR"])
        captured_roots.append(owned_root)
        assert owned_root.is_dir()
        write_file(owned_root, "spawn-evidence.txt", b"Owned temporary data\n")
        raise OSError("Injected process creation failure")

    monkeypatch.setattr(verify.subprocess, "Popen", failed_spawn)
    run = verify.Run(tmp_path / "evidence", timeout=5)

    with pytest.raises(OSError, match="Injected process creation failure"):
        run.command("spawn-failed", ["mock-command"], tmp_path)

    report = json.loads((run.output / "verification.json").read_text())
    check = report["checks"]["spawn-failed"]
    assert captured_roots == [Path(check["temporary_directory"])]
    assert captured_roots[0].parent == run.output
    assert check["temporary_cleaned"] is True
    assert not captured_roots[0].exists()
    assert report["status"] == check["status"] == "failed"


def test_run_environment_ignores_source_and_dependency_overrides(tmp_path, monkeypatch):
    for name in (
        "PYTHONPATH",
        "MYPYPATH",
        "PIP_EXTRA_INDEX_URL",
        "PIP_FIND_LINKS",
        "PIP_TRUSTED_HOST",
        "PYTEST_ADDOPTS",
        "COVERAGE_PROCESS_START",
    ):
        monkeypatch.setenv(name, "not-a-real-source-or-index")
    run = verify.Run(tmp_path / "evidence", timeout=5)

    output = run.command(
        "environment",
        [sys.executable, "-c", "import os, json; print(json.dumps(dict(os.environ)))"],
        tmp_path,
    )

    environment = json.loads(output)
    assert environment["PIP_INDEX_URL"] == "https://pypi.org/simple"
    assert environment["PYTHONNOUSERSITE"] == "1"
    for name in (
        "PYTHONPATH",
        "MYPYPATH",
        "PIP_EXTRA_INDEX_URL",
        "PIP_FIND_LINKS",
        "PIP_TRUSTED_HOST",
        "PYTEST_ADDOPTS",
        "COVERAGE_PROCESS_START",
    ):
        assert name not in environment


def test_run_cancellation_terminates_and_reaps_owned_subprocess(tmp_path, monkeypatch):
    class CancelledProcess:
        pid = 12345
        returncode = None
        terminated = False
        reaped = False
        temporary_root = None

        def __enter__(self):
            return self

        def __exit__(self, *_arguments):
            assert self.terminated and self.reaped

        def wait(self, timeout=None):
            if timeout is not None:
                raise KeyboardInterrupt("Injected cancellation")
            assert self.terminated
            assert (self.temporary_root / "child-owned/evidence.txt").is_file()
            self.reaped = True
            self.returncode = -9
            return self.returncode

        def kill(self):
            self.terminated = True

    process = CancelledProcess()

    def kill_group(pid, signal):
        assert pid == process.pid
        assert signal == verify.signal.SIGKILL
        process.terminated = True

    def spawn(*_args, **kwargs):
        process.temporary_root = Path(kwargs["env"]["TMPDIR"])
        assert process.temporary_root.is_dir()
        write_file(
            process.temporary_root,
            "child-owned/evidence.txt",
            b"Owned temporary data\n",
        )
        return process

    monkeypatch.setattr(verify.subprocess, "Popen", spawn)
    monkeypatch.setattr(verify.os, "killpg", kill_group, raising=False)
    run = verify.Run(tmp_path / "evidence", timeout=5)

    with pytest.raises(KeyboardInterrupt, match="Injected cancellation"):
        run.command("cancelled-check", ["mock-command"], tmp_path)

    assert process.terminated and process.reaped
    report = json.loads((tmp_path / "evidence/verification.json").read_text())
    assert report["status"] == "failed"
    assert report["checks"]["cancelled-check"]["status"] == "failed"
    assert report["checks"]["cancelled-check"]["returncode"] == -9
    assert report["checks"]["cancelled-check"]["temporary_directory"] == str(
        process.temporary_root
    )
    assert report["checks"]["cancelled-check"]["temporary_cleaned"] is True
    assert not process.temporary_root.exists()


@pytest.mark.parametrize(
    "output, subtests, warnings",
    [
        ("4 passed, 1 skipped, 7 subtests passed, 3 warnings in 0.01s", 7, 3),
        ("4 passed, 1 skipped, 1 warning in 0.01s", 0, 1),
        ("4 passed, 1 skipped in 0.01s", 0, 0),
    ],
)
def test_test_summary_uses_actual_junit_and_terminal_counts(
    tmp_path, output, subtests, warnings
):
    junit = write_file(
        tmp_path,
        "installed.xml",
        b'<testsuites><testsuite tests="3" failures="0" errors="0" skipped="1"/>'
        b'<testsuite tests="2" failures="0" errors="0" skipped="0"/></testsuites>',
    )

    summary = verify.test_summary(junit, output)

    assert summary == {
        "tests": 5,
        "passed": 4,
        "failures": 0,
        "errors": 0,
        "skipped": 1,
        "subtests_passed": subtests,
        "warnings": warnings,
    }


@pytest.mark.parametrize("tests, failures, errors", [(0, 0, 0), (1, 1, 0), (1, 0, 1)])
def test_test_summary_rejects_empty_or_failed_junit(tmp_path, tests, failures, errors):
    junit = write_file(
        tmp_path,
        "installed.xml",
        (
            f'<testsuite tests="{tests}" failures="{failures}" errors="{errors}" '
            'skipped="0"/>'
        ).encode(),
    )

    with pytest.raises(verify.VerificationError):
        verify.test_summary(junit, "100 passed in 0.01s")


@pytest.mark.parametrize("failure", ["exit", "timeout", "validation"])
def test_pipeline_failure_saves_failed_report_and_cleans_staging(
    repository, tmp_path, monkeypatch, failure
):
    output = tmp_path / "evidence"
    staging_paths = []

    def failing_pipeline(args, run, staging):
        assert args.repo == repository
        staging_paths.append(staging)
        write_file(staging, "temporary-data.txt", b"Owned temporary data\n")
        if failure == "validation":
            raise verify.VerificationError("Artifact validation failed")
        program = (
            "raise SystemExit(5)"
            if failure == "exit"
            else "import time; time.sleep(10)"
        )
        run.command("required-check", [sys.executable, "-c", program], staging)

    monkeypatch.setattr(verify, "verify_pipeline", failing_pipeline)
    result = verify.main(
        [
            "--repo",
            str(repository),
            "--ref",
            "HEAD",
            "--output",
            str(output),
            "--timeout",
            "0.1" if failure == "timeout" else "5",
        ]
    )

    assert result == 1
    report = json.loads((output / "verification.json").read_text())
    assert report["status"] == "failed"
    assert report["error_type"] == "VerificationError"
    assert report["staging_cleaned"] is True
    assert staging_paths and all(not path.exists() for path in staging_paths)
    if failure != "validation":
        assert report["checks"]["required-check"]["status"] == (
            "failed" if failure == "exit" else "timeout"
        )


def test_cli_invalid_ref_preserves_failed_source_inspection_report(
    repository, tmp_path
):
    output = tmp_path / "evidence"

    result = verify.main(
        [
            "--repo",
            str(repository),
            "--ref",
            "nonexistent-verifier-ref",
            "--output",
            str(output),
        ]
    )

    assert result == 1
    report = json.loads((output / "verification.json").read_text())
    assert report["status"] == "failed"
    assert report["error_type"] == "VerificationError"
    assert report["staging_cleaned"] is True
    assert not report["checks"]


@pytest.mark.parametrize(
    "arguments",
    [
        [],
        ["--ref", "HEAD", "--worktree-snapshot"],
        ["--ref", "HEAD", "--include", "docs/new.md"],
    ],
)
def test_cli_rejects_ambiguous_or_incompatible_source_modes(tmp_path, arguments):
    output = tmp_path / "evidence"

    with pytest.raises(SystemExit) as error:
        verify.main(["--output", str(output), *arguments])

    assert error.value.code == 2
    assert not output.exists()
