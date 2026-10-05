"""pytest-benchmark microbenchmarks with separate allocation samples."""

import gc
import socket
import tracemalloc
from types import SimpleNamespace

import pytest

from ja3requests import TlsConfig
from ja3requests.cookies import Ja3RequestsCookieJar, get_cookie_header
from ja3requests.pool import ConnectionPool
from ja3requests.protocol.h2.hpack import HPACKDecoder, HPACKEncoder
from ja3requests.protocol.tls import TLS
from ja3requests.protocol.tls.client_hello_info import inspect_client_hello


def measure_component(benchmark, options, record, operation, validate, parameters):
    validate(operation())
    benchmark.extra_info.update(parameters)
    result = benchmark.pedantic(
        operation,
        rounds=options["repeat"],
        iterations=options["iterations"],
        warmup_rounds=1,
    )
    validate(result)
    gc.collect()
    tracemalloc.start()
    try:
        result = operation()
        peak = tracemalloc.get_traced_memory()[1]
    finally:
        tracemalloc.stop()
    validate(result)
    record(
        {
            "kind": "component",
            "parameters": parameters,
            "python_peak_bytes_one_operation": peak,
            "result_verified": True,
        }
    )


@pytest.mark.parametrize("table_state", ["cold", "warm"])
def test_hpack_round_trip(benchmark, perf_options, record_measurement, table_state):
    encoder, decoder = HPACKEncoder(), HPACKDecoder()
    headers = [
        (":method", "GET"),
        (":path", "/payload"),
        (":scheme", "https"),
        (":authority", "localhost"),
        ("user-agent", "local-benchmark"),
        ("accept", "*/*"),
    ]

    def operation():
        if table_state == "cold":
            return HPACKDecoder().decode_headers(HPACKEncoder().encode_headers(headers))
        return decoder.decode_headers(encoder.encode_headers(headers))

    def validate(result):
        assert result == headers

    measure_component(
        benchmark,
        perf_options,
        record_measurement,
        operation,
        validate,
        {
            "component": "hpack_" + table_state + "_table_round_trip",
            "headers": len(headers),
        },
    )


def test_pool_checkout_return(benchmark, perf_options, record_measurement):
    local, remote = socket.socketpair()
    pool = ConnectionPool(max_connections_per_host=1, max_pool_size=1)
    assert pool.put_connection("localhost", 443, "https", local)

    def operation():
        pooled = pool.get_connection("localhost", 443)
        assert pooled is not None and pooled.conn is local
        return pool.put_connection("localhost", 443, "https", local, pooled_conn=pooled)

    def validate(result):
        assert result is True

    try:
        measure_component(
            benchmark,
            perf_options,
            record_measurement,
            operation,
            validate,
            {
                "component": "pool_checkout_return",
                "socket": "local_socketpair",
                "health_probe_included": True,
            },
        )
    finally:
        pool.close_all()
        remote.close()


@pytest.mark.parametrize("count", [10, 100])
def test_cookie_selection(benchmark, perf_options, record_measurement, count):
    jar = Ja3RequestsCookieJar()
    for index in range(count):
        jar.set(
            "cookie{}".format(index),
            "value",
            domain="benchmark.example",
            path="/payload",
            secure=True,
        )
    request = SimpleNamespace(url="https://benchmark.example/payload", headers={})

    def validate(result):
        assert len(result.split("; ")) == count
        assert "cookie0=value" in result

    measure_component(
        benchmark,
        perf_options,
        record_measurement,
        lambda: get_cookie_header(jar, request),
        validate,
        {"component": "cookie_scope_and_header", "cookies": count},
    )


@pytest.mark.parametrize("mode", ["prepare_preview", "inspect_existing"])
def test_ja3(benchmark, perf_options, record_measurement, mode):
    config = TlsConfig.secure()
    tls = TLS(None, server_host="localhost")
    tls.set_payload(config)
    record = tls.body.message
    expected = inspect_client_hello(record)["ja3"]
    operation = (
        (lambda: config.get_ja3_string(server_name="localhost"))
        if mode == "prepare_preview"
        else (lambda: inspect_client_hello(record)["ja3"])
    )

    def validate(result):
        assert result == expected

    measure_component(
        benchmark,
        perf_options,
        record_measurement,
        operation,
        validate,
        {
            "component": "ja3_" + mode,
            "key_generation_included": mode == "prepare_preview",
            "record_bytes": len(record),
        },
    )
