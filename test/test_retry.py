"""Tests for HTTP-level retry with backoff (#11)."""

import unittest
from unittest.mock import patch

from ja3requests.retry import HTTPRetry


class TestHTTPRetryDefaults(unittest.TestCase):
    """Test HTTPRetry default configuration."""

    def test_default_total(self):
        retry = HTTPRetry()
        self.assertEqual(retry.total, 3)

    def test_default_backoff_factor(self):
        retry = HTTPRetry()
        self.assertEqual(retry.backoff_factor, 0.5)

    def test_default_status_forcelist(self):
        retry = HTTPRetry()
        self.assertEqual(retry.status_forcelist, {502, 503, 504})

    def test_default_allowed_methods(self):
        retry = HTTPRetry()
        self.assertIn("GET", retry.allowed_methods)
        self.assertIn("HEAD", retry.allowed_methods)
        self.assertNotIn("POST", retry.allowed_methods)

    def test_default_raise_on_status(self):
        retry = HTTPRetry()
        self.assertTrue(retry.raise_on_status)


class TestHTTPRetryCustom(unittest.TestCase):
    """Test custom HTTPRetry configuration."""

    def test_custom_total(self):
        retry = HTTPRetry(total=5)
        self.assertEqual(retry.total, 5)

    def test_custom_status_forcelist(self):
        retry = HTTPRetry(status_forcelist={500, 502})
        self.assertIn(500, retry.status_forcelist)
        self.assertNotIn(503, retry.status_forcelist)

    def test_custom_allowed_methods(self):
        retry = HTTPRetry(allowed_methods={"GET", "POST"})
        self.assertIn("POST", retry.allowed_methods)

    def test_custom_backoff_factor(self):
        retry = HTTPRetry(backoff_factor=1.0)
        self.assertEqual(retry.backoff_factor, 1.0)


class TestRetryableChecks(unittest.TestCase):
    """Test is_retryable_method and is_retryable_status."""

    def test_get_is_retryable(self):
        retry = HTTPRetry()
        self.assertTrue(retry.is_retryable_method("GET"))

    def test_post_not_retryable_by_default(self):
        retry = HTTPRetry()
        self.assertFalse(retry.is_retryable_method("POST"))

    def test_case_insensitive_method(self):
        retry = HTTPRetry()
        self.assertTrue(retry.is_retryable_method("get"))

    def test_502_is_retryable(self):
        retry = HTTPRetry()
        self.assertTrue(retry.is_retryable_status(502))

    def test_200_not_retryable(self):
        retry = HTTPRetry()
        self.assertFalse(retry.is_retryable_status(200))

    def test_500_not_retryable_by_default(self):
        retry = HTTPRetry()
        self.assertFalse(retry.is_retryable_status(500))


class TestBackoffCalculation(unittest.TestCase):
    """Test backoff time calculation."""

    def test_zero_retry_no_backoff(self):
        retry = HTTPRetry(backoff_factor=0.5)
        self.assertEqual(retry.get_backoff_time(0), 0)

    def test_first_retry_backoff(self):
        retry = HTTPRetry(backoff_factor=0.5)
        backoff = retry.get_backoff_time(1)
        # 0.5 * 2^0 = 0.5, plus up to 10% jitter
        self.assertGreaterEqual(backoff, 0.5)
        self.assertLessEqual(backoff, 0.55 + 0.01)

    def test_second_retry_backoff(self):
        retry = HTTPRetry(backoff_factor=0.5)
        backoff = retry.get_backoff_time(2)
        # 0.5 * 2^1 = 1.0, plus up to 10% jitter
        self.assertGreaterEqual(backoff, 1.0)
        self.assertLessEqual(backoff, 1.1 + 0.01)

    def test_third_retry_backoff(self):
        retry = HTTPRetry(backoff_factor=0.5)
        backoff = retry.get_backoff_time(3)
        # 0.5 * 2^2 = 2.0, plus up to 10% jitter
        self.assertGreaterEqual(backoff, 2.0)
        self.assertLessEqual(backoff, 2.2 + 0.01)

    def test_zero_backoff_factor(self):
        retry = HTTPRetry(backoff_factor=0)
        backoff = retry.get_backoff_time(1)
        self.assertEqual(backoff, 0)


class TestRetryAfter(unittest.TestCase):
    """Test Retry-After header parsing."""

    def test_retry_after_seconds(self):
        retry = HTTPRetry()

        class FakeResp:
            headers = {"Retry-After": "5"}

        self.assertEqual(retry.get_retry_after(FakeResp()), 5.0)

    def test_retry_after_missing(self):
        retry = HTTPRetry()

        class FakeResp:
            headers = {}

        self.assertIsNone(retry.get_retry_after(FakeResp()))

    def test_retry_after_disabled(self):
        retry = HTTPRetry(respect_retry_after=False)

        class FakeResp:
            headers = {"Retry-After": "5"}

        self.assertIsNone(retry.get_retry_after(FakeResp()))

    def test_retry_after_invalid_value(self):
        retry = HTTPRetry()

        class FakeResp:
            headers = {"Retry-After": "not-a-number"}

        self.assertIsNone(retry.get_retry_after(FakeResp()))


class TestSessionRetryIntegration(unittest.TestCase):
    """Test Session integration with HTTPRetry."""

    def test_session_accepts_retry(self):
        from ja3requests.sessions import Session
        retry = HTTPRetry(total=5)
        s = Session(use_pooling=False, retry=retry)
        self.assertIs(s._retry, retry)

    def test_session_default_no_retry(self):
        from ja3requests.sessions import Session
        s = Session(use_pooling=False)
        self.assertIsNone(s._retry)

    def test_retry_exported(self):
        import ja3requests
        self.assertTrue(hasattr(ja3requests, "HTTPRetry"))


class TestSleepForRetry(unittest.TestCase):
    """Test sleep_for_retry behavior."""

    @patch("ja3requests.retry.time.sleep")
    def test_sleep_with_backoff(self, mock_sleep):
        retry = HTTPRetry(backoff_factor=0.5)
        retry.sleep_for_retry(None, 1)
        mock_sleep.assert_called_once()
        call_arg = mock_sleep.call_args[0][0]
        self.assertGreaterEqual(call_arg, 0.5)

    @patch("ja3requests.retry.time.sleep")
    def test_sleep_with_retry_after(self, mock_sleep):
        retry = HTTPRetry()

        class FakeResp:
            headers = {"Retry-After": "3"}

        retry.sleep_for_retry(FakeResp(), 1)
        mock_sleep.assert_called_once_with(3.0)


if __name__ == "__main__":
    unittest.main()
