"""Small pytest report integration for explicitly selected loopback benchmarks."""

import datetime
import hashlib
import importlib.metadata
import json
import math
import platform
import ssl
import sys
from pathlib import Path

import pytest
import ja3requests

from bench.http1_baseline import ROOT, git_identity, source_identity
from test.integration.conftest import trusted_certificates  # noqa: F401


# Keep the original 26-case suite stable; select the async module explicitly.
collect_ignore = ["test_async_performance.py"]


def pytest_addoption(parser):
    group = parser.getgroup("local performance measurements")
    group.addoption("--perf-repeat", type=int, default=3)
    group.addoption("--perf-requests", type=int, default=12)
    group.addoption("--perf-concurrency", type=int, default=4)
    group.addoption("--perf-body-bytes", type=int, default=65536)
    group.addoption("--perf-iterations", type=int, default=200)
    group.addoption("--perf-timeout", type=float, default=5.0)
    group.addoption("--perf-output", type=Path, default=None)


def tool_identity():
    paths = sorted((ROOT / "bench").glob("*.py"))
    paths += [
        ROOT / "bench/requirements.txt",
        ROOT / "test/integration/conftest.py",
        ROOT / "test/mock_servers/local.py",
    ]
    return {
        path.relative_to(ROOT).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in paths
    }


def pytest_configure(config):
    names = ("repeat", "requests", "concurrency", "body_bytes", "iterations", "timeout")
    parameters = {name: config.getoption("perf_" + name) for name in names}
    if any(value <= 0 or not math.isfinite(value) for value in parameters.values()):
        raise pytest.UsageError(
            "all --perf measurement parameters must be finite and positive"
        )
    if parameters["requests"] % parameters["concurrency"]:
        raise pytest.UsageError(
            "--perf-requests must be divisible by --perf-concurrency"
        )
    output = config.getoption("perf_output")
    if output is not None and (output.exists() or not output.parent.is_dir()):
        raise pytest.UsageError(
            "--perf-output must be a new file in an existing directory"
        )
    dependencies = {}
    for name in (
        "ja3requests",
        "cryptography",
        "brotli",
        "pytest",
        "pytest-benchmark",
        "requests",
    ):
        try:
            dependencies[name] = importlib.metadata.version(name)
        except importlib.metadata.PackageNotFoundError:
            dependencies[name] = None
    config._local_performance = {
        "schema_version": 1,
        "started_at_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "parameters": parameters,
        "environment": {
            "python": sys.version,
            "executable": sys.executable,
            "platform": platform.platform(),
            "machine": platform.machine(),
            "openssl_server": ssl.OPENSSL_VERSION,
            "dependencies": dependencies,
            "package_path": ja3requests.__file__,
        },
        "git_before": git_identity(),
        "source_before": source_identity(),
        "tools_before": tool_identity(),
        "measurements": [],
        "test_outcomes": [],
        "notes": [
            "Loopback only, ephemeral trusted CA, project-owned ja3requests TLS client.",
            "OpenSSL drives the independent server and the separately named requests comparison only.",
            "Timing samples exclude tracemalloc; separate memory samples include Python allocations in both peers.",
            "Python allocation peaks are not RSS or native memory measurements.",
            "Warmup and TCP/TLS observations identify full, resumed and reused paths explicitly.",
            "No speed thresholds; assertions check requested protocol, body, ownership and measurement paths.",
            "pytest-benchmark component JSON is a separate companion output when --benchmark-json is supplied.",
        ],
    }


@pytest.fixture(scope="session")
def perf_options(pytestconfig):
    return dict(pytestconfig._local_performance["parameters"])


@pytest.fixture
def record_measurement(pytestconfig, request):
    def record(row):
        row["test_id"] = request.node.nodeid
        pytestconfig._local_performance["measurements"].append(row)

    return record


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_makereport(item, call):
    del call
    result = yield
    outcome = result.get_result()
    if outcome.when == "call" or outcome.failed or outcome.skipped:
        item.config._local_performance["test_outcomes"].append(
            {
                "test_id": outcome.nodeid,
                "phase": outcome.when,
                "outcome": outcome.outcome,
                "reason": (
                    str(outcome.longrepr)[:1200]
                    if outcome.failed or outcome.skipped
                    else None
                ),
            }
        )


def pytest_sessionfinish(session, exitstatus):
    report = session.config._local_performance
    source_after = source_identity()
    report["source_after_sha256"] = source_after["sha256"]
    report["source_stable_during_run"] = report["source_before"] == source_after
    report["tools_after"] = tool_identity()
    report["tools_stable_during_run"] = report["tools_before"] == report["tools_after"]
    report["git_after"] = git_identity()
    report["pytest_exitstatus"] = int(exitstatus)
    report["finished_at_utc"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    output = session.config.getoption("perf_output")
    if output is not None:
        with output.open("x", encoding="utf-8") as destination:
            json.dump(report, destination, indent=2, sort_keys=True)
            destination.write("\n")


@pytest.hookimpl(optionalhook=True)
def pytest_benchmark_update_json(config, benchmarks, output_json):
    del benchmarks
    report = config._local_performance
    output_json["local_source_identity"] = report["source_before"]
    output_json["local_tool_identity"] = report["tools_before"]
    output_json["local_parameters"] = report["parameters"]
    output_json["source_stable_at_component_report"] = (
        report["source_before"] == source_identity()
    )


def pytest_terminal_summary(terminalreporter, exitstatus, config):
    del exitstatus
    report = config._local_performance
    terminalreporter.write_line(
        "Local performance: {} measurement records; source stable: {}; tools stable: {}".format(
            len(report["measurements"]),
            report.get("source_stable_during_run"),
            report.get("tools_stable_during_run"),
        )
    )
