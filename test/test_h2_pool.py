"""Tests for HTTP/2 connection pool multiplexing (#33)."""

import threading
import unittest

from ja3requests.pool import (
    ConnectionPool,
    PooledConnection,
    PooledH2Connection,
    get_default_pool,
)


class FakeSocket:
    """Fake socket that pretends to be alive."""
    def __init__(self):
        self.closed = False

    def close(self):
        self.closed = True

    def recv(self, n, flags=0):
        return b"\x00"  # Pretend alive

    def setblocking(self, val):
        pass


class TestPooledH2Connection(unittest.TestCase):
    """Test PooledH2Connection stream management."""

    def test_initial_state(self):
        pc = PooledH2Connection(FakeSocket(), "https", "example.com", 443)
        self.assertEqual(pc.active_streams, 0)
        self.assertEqual(pc.negotiated_protocol, "h2")
        self.assertTrue(pc.can_allocate_stream())
        self.assertTrue(pc.is_idle())

    def test_acquire_stream(self):
        pc = PooledH2Connection(FakeSocket(), "https", "example.com", 443)
        self.assertTrue(pc.acquire_stream())
        self.assertEqual(pc.active_streams, 1)
        self.assertFalse(pc.is_idle())

    def test_release_stream(self):
        pc = PooledH2Connection(FakeSocket(), "https", "example.com", 443)
        pc.acquire_stream()
        pc.acquire_stream()
        self.assertEqual(pc.active_streams, 2)
        pc.release_stream()
        self.assertEqual(pc.active_streams, 1)
        pc.release_stream()
        self.assertEqual(pc.active_streams, 0)
        self.assertTrue(pc.is_idle())

    def test_release_below_zero_safe(self):
        pc = PooledH2Connection(FakeSocket(), "https", "example.com", 443)
        pc.release_stream()  # Should not go negative
        self.assertEqual(pc.active_streams, 0)

    def test_max_concurrent_streams(self):
        pc = PooledH2Connection(FakeSocket(), "https", "example.com", 443)
        pc.set_max_concurrent_streams(3)
        self.assertTrue(pc.acquire_stream())
        self.assertTrue(pc.acquire_stream())
        self.assertTrue(pc.acquire_stream())
        self.assertFalse(pc.acquire_stream())  # At limit
        self.assertFalse(pc.can_allocate_stream())

    def test_goaway_blocks_new_streams(self):
        pc = PooledH2Connection(FakeSocket(), "https", "example.com", 443)
        pc.acquire_stream()
        pc.mark_goaway()
        self.assertFalse(pc.can_allocate_stream())
        self.assertFalse(pc.acquire_stream())

    def test_repr(self):
        pc = PooledH2Connection(FakeSocket(), "https", "example.com", 443)
        r = repr(pc)
        self.assertIn("PooledH2Connection", r)
        self.assertIn("streams=0/", r)

    def test_thread_safe_acquire(self):
        """Concurrent acquires should not exceed the limit."""
        pc = PooledH2Connection(FakeSocket(), "https", "example.com", 443)
        pc.set_max_concurrent_streams(50)

        acquired_count = [0]
        lock = threading.Lock()

        def worker():
            for _ in range(10):
                if pc.acquire_stream():
                    with lock:
                        acquired_count[0] += 1

        threads = [threading.Thread(target=worker) for _ in range(20)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # Total attempts: 200, limit: 50
        self.assertLessEqual(acquired_count[0], 50)
        self.assertEqual(pc.active_streams, acquired_count[0])


class TestH2ConnectionPool(unittest.TestCase):
    """Test H2 multiplexing in ConnectionPool."""

    def test_put_h2_connection(self):
        pool = ConnectionPool()
        pc = pool.put_h2_connection("example.com", 443, "https", FakeSocket())
        self.assertIsNotNone(pc)
        self.assertEqual(pc.negotiated_protocol, "h2")

    def test_get_h2_connection_acquires_stream(self):
        pool = ConnectionPool()
        pool.put_h2_connection("example.com", 443, "https", FakeSocket())

        pc = pool.get_h2_connection("example.com", 443, "https")
        self.assertIsNotNone(pc)
        self.assertEqual(pc.active_streams, 1)

    def test_get_h2_connection_stays_in_pool(self):
        """H2 connections are NOT removed on get (multiplexing)."""
        pool = ConnectionPool()
        pool.put_h2_connection("example.com", 443, "https", FakeSocket())

        pc1 = pool.get_h2_connection("example.com", 443, "https")
        pc2 = pool.get_h2_connection("example.com", 443, "https")
        # Should get the same underlying connection twice (multiplexed)
        self.assertIs(pc1, pc2)
        self.assertEqual(pc1.active_streams, 2)

    def test_get_h2_connection_none_when_empty(self):
        pool = ConnectionPool()
        self.assertIsNone(pool.get_h2_connection("nothing.com", 443, "https"))

    def test_release_h2_stream(self):
        pool = ConnectionPool()
        pool.put_h2_connection("example.com", 443, "https", FakeSocket())
        pc = pool.get_h2_connection("example.com", 443, "https")
        self.assertEqual(pc.active_streams, 1)
        pool.release_h2_stream(pc)
        self.assertEqual(pc.active_streams, 0)

    def test_full_multiplexing_lifecycle(self):
        """100 concurrent requests share 1 connection."""
        pool = ConnectionPool()
        pool.put_h2_connection("api.com", 443, "https", FakeSocket())

        streams = []
        for _ in range(100):
            pc = pool.get_h2_connection("api.com", 443, "https")
            self.assertIsNotNone(pc)
            streams.append(pc)

        # All 100 should share the same underlying connection
        first = streams[0]
        for pc in streams:
            self.assertIs(pc, first)

        self.assertEqual(first.active_streams, 100)

        # Release all
        for pc in streams:
            pool.release_h2_stream(pc)
        self.assertEqual(first.active_streams, 0)

    def test_goaway_connection_not_reused(self):
        pool = ConnectionPool()
        pc = pool.put_h2_connection("example.com", 443, "https", FakeSocket())
        pc.mark_goaway()

        result = pool.get_h2_connection("example.com", 443, "https")
        self.assertIsNone(result)

    def test_pool_full_returns_none(self):
        pool = ConnectionPool(max_pool_size=2)
        pool.put_h2_connection("a.com", 443, "https", FakeSocket())
        pool.put_h2_connection("b.com", 443, "https", FakeSocket())
        result = pool.put_h2_connection("c.com", 443, "https", FakeSocket())
        self.assertIsNone(result)

    def test_h2_stats(self):
        pool = ConnectionPool()
        pool.put_h2_connection("example.com", 443, "https", FakeSocket())
        pc = pool.get_h2_connection("example.com", 443, "https")
        stats = pool.get_stats()
        self.assertIn("h2_pools", stats)
        self.assertIn("h2_hosts", stats)
        host_stats = stats["h2_hosts"]["https://example.com:443"]
        self.assertEqual(host_stats["connections"], 1)
        self.assertEqual(host_stats["active_streams"], 1)
        pool.release_h2_stream(pc)

    def test_close_host_closes_h2(self):
        pool = ConnectionPool()
        sock = FakeSocket()
        pool.put_h2_connection("example.com", 443, "https", sock)
        pool.close_host_connections("example.com", 443, "https")
        self.assertTrue(sock.closed)

    def test_close_all_closes_h2(self):
        pool = ConnectionPool()
        sock = FakeSocket()
        pool.put_h2_connection("example.com", 443, "https", sock)
        pool.close_all()
        self.assertTrue(sock.closed)


class TestMixedPool(unittest.TestCase):
    """Test that H1 and H2 pools coexist correctly."""

    def test_h1_and_h2_separate(self):
        pool = ConnectionPool()
        sock1 = FakeSocket()
        sock2 = FakeSocket()
        pool.put_connection("example.com", 443, "https", sock1)
        pool.put_h2_connection("example.com", 443, "https", sock2)

        # H1 get should not return H2
        h1_conn = pool.get_connection("example.com", 443, "https")
        self.assertIsNotNone(h1_conn)
        self.assertNotIsInstance(h1_conn, PooledH2Connection)

        # H2 get should return H2
        h2_conn = pool.get_h2_connection("example.com", 443, "https")
        self.assertIsInstance(h2_conn, PooledH2Connection)


if __name__ == "__main__":
    unittest.main()
