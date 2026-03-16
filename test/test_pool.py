"""
Test cases for connection pooling (ja3requests.pool)
"""

import socket
import threading
import time
import unittest
from unittest.mock import MagicMock, patch

from ja3requests.pool import (
    ConnectionPool,
    PooledConnection,
    get_default_pool,
    set_default_pool,
    _pool_lock,
)


def _make_mock_conn(alive=True):
    """Create a mock socket connection"""
    conn = MagicMock()
    if alive:
        conn.recv.side_effect = BlockingIOError
    else:
        conn.recv.return_value = b''
    return conn


class TestPooledConnection(unittest.TestCase):
    """Tests for PooledConnection"""

    def test_init_defaults(self):
        conn = MagicMock()
        pc = PooledConnection(conn, "https", "example.com", 443)
        self.assertEqual(pc.conn, conn)
        self.assertEqual(pc.scheme, "https")
        self.assertEqual(pc.host, "example.com")
        self.assertEqual(pc.port, 443)
        self.assertIsNone(pc.tls)
        self.assertIsNotNone(pc.created_at)
        self.assertEqual(pc.created_at, pc.last_used_at)

    def test_init_custom_created_at(self):
        pc = PooledConnection(MagicMock(), "http", created_at=1000.0)  # keyword-only
        self.assertEqual(pc.created_at, 1000.0)

    def test_repr(self):
        pc = PooledConnection(None, "https", "example.com", 443)
        r = repr(pc)
        self.assertIn("PooledConnection", r)
        self.assertIn("example.com", r)
        self.assertIn("443", r)
        self.assertIn("alive=False", r)

    def test_is_expired_true(self):
        pc = PooledConnection(MagicMock(), "https")
        pc.last_used_at = time.time() - 120
        self.assertTrue(pc.is_expired(60.0))

    def test_is_expired_false(self):
        pc = PooledConnection(MagicMock(), "https")
        pc.last_used_at = time.time()
        self.assertFalse(pc.is_expired(60.0))

    def test_is_alive_none_conn(self):
        pc = PooledConnection(None, "https")
        self.assertFalse(pc.is_alive())

    def test_is_alive_socket_active(self):
        """Connection is alive when recv raises BlockingIOError (no data but connected)"""
        conn = _make_mock_conn(alive=True)
        pc = PooledConnection(conn, "https")
        self.assertTrue(pc.is_alive())
        conn.setblocking.assert_any_call(False)
        conn.setblocking.assert_any_call(True)

    def test_is_alive_socket_closed(self):
        """Connection is dead when recv returns empty bytes"""
        conn = _make_mock_conn(alive=False)
        pc = PooledConnection(conn, "https")
        self.assertFalse(pc.is_alive())

    def test_is_alive_oserror(self):
        """Connection is dead when recv raises OSError"""
        conn = MagicMock()
        conn.recv.side_effect = OSError("Connection refused")
        pc = PooledConnection(conn, "https")
        self.assertFalse(pc.is_alive())

    def test_is_alive_setblocking_exception(self):
        """is_alive returns False when setblocking itself raises"""
        conn = MagicMock()
        conn.setblocking.side_effect = OSError("broken")
        pc = PooledConnection(conn, "https")
        self.assertFalse(pc.is_alive())

    def test_touch(self):
        pc = PooledConnection(MagicMock(), "https")
        old_time = pc.last_used_at
        time.sleep(0.01)
        pc.touch()
        self.assertGreater(pc.last_used_at, old_time)

    def test_close(self):
        conn = MagicMock()
        pc = PooledConnection(conn, "https")
        pc.close()
        conn.close.assert_called_once()
        self.assertIsNone(pc.conn)

    def test_close_none_conn(self):
        pc = PooledConnection(None, "https")
        pc.close()  # Should not raise
        self.assertIsNone(pc.conn)

    def test_close_exception_suppressed(self):
        conn = MagicMock()
        conn.close.side_effect = OSError("already closed")
        pc = PooledConnection(conn, "https")
        pc.close()  # Should not raise
        self.assertIsNone(pc.conn)


class TestConnectionPool(unittest.TestCase):
    """Tests for ConnectionPool"""

    def setUp(self):
        self.pool = ConnectionPool(
            max_connections_per_host=3,
            idle_timeout=5.0,
            max_pool_size=10,
        )

    def tearDown(self):
        self.pool.close_all()

    def test_init(self):
        self.assertEqual(self.pool._max_per_host, 3)
        self.assertEqual(self.pool._idle_timeout, 5.0)
        self.assertEqual(self.pool._max_pool_size, 10)
        self.assertEqual(self.pool._total_connections, 0)

    def test_repr(self):
        r = repr(self.pool)
        self.assertIn("ConnectionPool", r)
        self.assertIn("connections=0", r)
        self.assertIn("pools=0", r)

    def test_get_pool_key_case_insensitive(self):
        key1 = self.pool._get_pool_key("Example.COM", 443, "HTTPS")
        key2 = self.pool._get_pool_key("example.com", 443, "https")
        self.assertEqual(key1, key2)

    # --- put_connection ---

    def test_put_new_connection(self):
        conn = _make_mock_conn()
        result = self.pool.put_connection("example.com", 443, "https", conn)
        self.assertTrue(result)
        self.assertEqual(self.pool._total_connections, 1)

    def test_put_connection_with_tls(self):
        conn = _make_mock_conn()
        tls = MagicMock()
        result = self.pool.put_connection("example.com", 443, "https", conn, tls=tls)
        self.assertTrue(result)

    def test_put_existing_pooled_conn(self):
        pc = PooledConnection(_make_mock_conn(), "https", "example.com", 443)
        result = self.pool.put_connection(
            "example.com", 443, "https", pc.conn, pooled_conn=pc
        )
        self.assertTrue(result)
        # Existing pooled_conn doesn't increment total_connections
        self.assertEqual(self.pool._total_connections, 0)

    def test_put_connection_host_limit(self):
        """Reject when per-host limit reached"""
        for i in range(3):
            self.pool.put_connection("host.com", 443, "https", _make_mock_conn())
        result = self.pool.put_connection("host.com", 443, "https", _make_mock_conn())
        self.assertFalse(result)
        self.assertEqual(self.pool._total_connections, 3)

    def test_put_connection_global_limit(self):
        """Reject when global pool limit reached"""
        pool = ConnectionPool(max_connections_per_host=10, max_pool_size=2)
        pool.put_connection("a.com", 80, "http", _make_mock_conn())
        pool.put_connection("b.com", 80, "http", _make_mock_conn())
        result = pool.put_connection("c.com", 80, "http", _make_mock_conn())
        self.assertFalse(result)
        self.assertEqual(pool._total_connections, 2)
        pool.close_all()

    # --- get_connection ---

    def test_get_connection_empty_pool(self):
        result = self.pool.get_connection("example.com", 443, "https")
        self.assertIsNone(result)

    def test_get_connection_success(self):
        conn = _make_mock_conn()
        self.pool.put_connection("example.com", 443, "https", conn)
        result = self.pool.get_connection("example.com", 443, "https")
        self.assertIsNotNone(result)
        self.assertEqual(result.conn, conn)

    def test_get_connection_skips_expired(self):
        """Expired connections are closed and skipped"""
        expired_conn = _make_mock_conn()
        self.pool.put_connection("example.com", 443, "https", expired_conn)

        # Manually expire the connection
        key = ("example.com", 443, "https")
        self.pool._pools[key][0].last_used_at = time.time() - 100

        result = self.pool.get_connection("example.com", 443, "https")
        self.assertIsNone(result)
        self.assertEqual(self.pool._total_connections, 0)
        expired_conn.close.assert_called_once()

    def test_get_connection_skips_dead(self):
        """Dead connections are closed and skipped"""
        dead_conn = _make_mock_conn(alive=False)
        self.pool.put_connection("example.com", 443, "https", dead_conn)

        result = self.pool.get_connection("example.com", 443, "https")
        self.assertIsNone(result)
        self.assertEqual(self.pool._total_connections, 0)

    def test_get_connection_case_insensitive(self):
        self.pool.put_connection("Example.COM", 443, "HTTPS", _make_mock_conn())
        result = self.pool.get_connection("example.com", 443, "https")
        self.assertIsNotNone(result)

    def test_get_connection_different_hosts_isolated(self):
        """Connections for different hosts are separate"""
        self.pool.put_connection("a.com", 443, "https", _make_mock_conn())
        result = self.pool.get_connection("b.com", 443, "https")
        self.assertIsNone(result)

    def test_get_connection_different_ports_isolated(self):
        self.pool.put_connection("a.com", 443, "https", _make_mock_conn())
        result = self.pool.get_connection("a.com", 8443, "https")
        self.assertIsNone(result)

    def test_get_connection_different_schemes_isolated(self):
        self.pool.put_connection("a.com", 80, "http", _make_mock_conn())
        result = self.pool.get_connection("a.com", 80, "https")
        self.assertIsNone(result)

    # --- close_idle_connections ---

    def test_close_idle_connections(self):
        conn1 = _make_mock_conn()
        conn2 = _make_mock_conn()
        self.pool.put_connection("a.com", 443, "https", conn1)
        self.pool.put_connection("b.com", 443, "https", conn2)

        # Expire conn1 only
        key_a = ("a.com", 443, "https")
        self.pool._pools[key_a][0].last_used_at = time.time() - 100

        self.pool.close_idle_connections()
        self.assertEqual(self.pool._total_connections, 1)
        self.assertNotIn(key_a, self.pool._pools)
        conn1.close.assert_called_once()
        conn2.close.assert_not_called()

    def test_close_idle_connections_keeps_active(self):
        self.pool.put_connection("a.com", 443, "https", _make_mock_conn())
        self.pool.close_idle_connections()
        self.assertEqual(self.pool._total_connections, 1)

    # --- close_host_connections ---

    def test_close_host_connections(self):
        self.pool.put_connection("a.com", 443, "https", _make_mock_conn())
        self.pool.put_connection("b.com", 443, "https", _make_mock_conn())

        self.pool.close_host_connections("a.com", 443, "https")
        self.assertEqual(self.pool._total_connections, 1)
        self.assertIsNone(self.pool.get_connection("a.com", 443, "https"))

    def test_close_host_connections_nonexistent(self):
        self.pool.close_host_connections("nohost.com", 443, "https")  # No error

    # --- close_all ---

    def test_close_all(self):
        for i in range(5):
            self.pool.put_connection(f"host{i}.com", 443, "https", _make_mock_conn())
        self.pool.close_all()
        self.assertEqual(self.pool._total_connections, 0)
        self.assertEqual(len(self.pool._pools), 0)

    # --- get_stats ---

    def test_get_stats_empty(self):
        stats = self.pool.get_stats()
        self.assertEqual(stats["total_connections"], 0)
        self.assertEqual(stats["pools"], 0)
        self.assertEqual(stats["hosts"], {})

    def test_get_stats_with_connections(self):
        self.pool.put_connection("a.com", 443, "https", _make_mock_conn())
        self.pool.put_connection("a.com", 443, "https", _make_mock_conn())
        self.pool.put_connection("b.com", 80, "http", _make_mock_conn())

        stats = self.pool.get_stats()
        self.assertEqual(stats["total_connections"], 3)
        self.assertEqual(stats["pools"], 2)
        self.assertEqual(stats["hosts"]["https://a.com:443"], 2)
        self.assertEqual(stats["hosts"]["http://b.com:80"], 1)

    # --- context manager ---

    def test_context_manager(self):
        with ConnectionPool() as pool:
            pool.put_connection("a.com", 443, "https", _make_mock_conn())
            self.assertEqual(pool._total_connections, 1)
        self.assertEqual(pool._total_connections, 0)

    # --- FIFO ordering ---

    def test_fifo_ordering(self):
        """Connections are returned in FIFO order"""
        conn1 = _make_mock_conn()
        conn2 = _make_mock_conn()
        self.pool.put_connection("a.com", 443, "https", conn1)
        self.pool.put_connection("a.com", 443, "https", conn2)

        result = self.pool.get_connection("a.com", 443, "https")
        self.assertEqual(result.conn, conn1)


class TestConnectionPoolThreadSafety(unittest.TestCase):
    """Thread safety tests for ConnectionPool"""

    def test_concurrent_put_connections(self):
        """Multiple threads can safely add connections"""
        pool = ConnectionPool(max_connections_per_host=100, max_pool_size=100)
        errors = []

        def put_conn(host_id):
            try:
                for _ in range(10):
                    pool.put_connection(f"host{host_id}.com", 443, "https", _make_mock_conn())
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=put_conn, args=(i,)) for i in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        self.assertEqual(errors, [])
        self.assertEqual(pool._total_connections, 50)
        pool.close_all()

    def test_concurrent_get_and_put(self):
        """Concurrent get/put operations don't corrupt state"""
        pool = ConnectionPool(max_connections_per_host=50, max_pool_size=200)
        errors = []

        # Pre-fill pool
        for _ in range(20):
            pool.put_connection("shared.com", 443, "https", _make_mock_conn())

        def get_and_put():
            try:
                for _ in range(10):
                    conn = pool.get_connection("shared.com", 443, "https")
                    if conn:
                        pool.put_connection(
                            "shared.com", 443, "https", conn.conn, pooled_conn=conn
                        )
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=get_and_put) for _ in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        self.assertEqual(errors, [])
        # Total should remain at 20 (no new connections added)
        self.assertEqual(pool._total_connections, 20)
        pool.close_all()

    def test_concurrent_close_and_get(self):
        """close_all during get_connection doesn't crash"""
        pool = ConnectionPool(max_connections_per_host=100, max_pool_size=100)
        errors = []

        for _ in range(20):
            pool.put_connection("host.com", 443, "https", _make_mock_conn())

        def getter():
            try:
                for _ in range(50):
                    pool.get_connection("host.com", 443, "https")
            except Exception as e:
                errors.append(e)

        def closer():
            try:
                time.sleep(0.001)
                pool.close_all()
            except Exception as e:
                errors.append(e)

        t1 = threading.Thread(target=getter)
        t2 = threading.Thread(target=closer)
        t1.start()
        t2.start()
        t1.join()
        t2.join()

        self.assertEqual(errors, [])


class TestDefaultPool(unittest.TestCase):
    """Tests for global default pool functions"""

    def test_get_default_pool_creates_singleton(self):
        import ja3requests.pool as pool_module

        # Reset global state
        pool_module._default_pool = None

        pool1 = get_default_pool()
        pool2 = get_default_pool()
        self.assertIs(pool1, pool2)
        self.assertIsInstance(pool1, ConnectionPool)

    def test_set_default_pool_replaces(self):
        import ja3requests.pool as pool_module

        old_pool = ConnectionPool()
        pool_module._default_pool = old_pool

        new_pool = ConnectionPool(max_connections_per_host=5)
        set_default_pool(new_pool)

        self.assertIs(pool_module._default_pool, new_pool)
        # Old pool should have been closed
        self.assertEqual(old_pool._total_connections, 0)

    def test_set_default_pool_from_none(self):
        import ja3requests.pool as pool_module

        pool_module._default_pool = None
        new_pool = ConnectionPool()
        set_default_pool(new_pool)
        self.assertIs(pool_module._default_pool, new_pool)


if __name__ == '__main__':
    unittest.main()
