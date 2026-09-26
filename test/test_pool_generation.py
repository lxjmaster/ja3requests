"""Checked-out connections must not corrupt accounting after pool reset."""

from unittest.mock import MagicMock

import pytest

from ja3requests.pool import ConnectionPool


def socket_stub():
    conn = MagicMock()
    conn.recv.side_effect = BlockingIOError
    return conn


@pytest.mark.parametrize("replace", [False, True])
def test_discard_after_close_all_preserves_current_count(replace):
    pool = ConnectionPool()
    old_socket = socket_stub()
    assert pool.put_connection("host", 443, "https", old_socket)
    borrowed = pool.get_connection("host", 443)
    pool.close_all()
    if replace:
        assert pool.put_connection("host", 443, "https", socket_stub())
    pool.discard_connection(borrowed)
    pool.discard_connection(borrowed)
    assert pool.get_stats()["total_connections"] == int(replace)
    old_socket.close.assert_called_once()
    pool.close_all()


def test_return_after_close_all_is_counted_again():
    pool = ConnectionPool(max_pool_size=1)
    conn = socket_stub()
    assert pool.put_connection("host", 443, "https", conn)
    borrowed = pool.get_connection("host", 443)
    pool.close_all()
    assert pool.put_connection("host", 443, "https", conn, pooled_conn=borrowed)
    assert pool.get_stats()["total_connections"] == 1
    assert not pool.put_connection("other", 443, "https", socket_stub())
    pool.close_all()
