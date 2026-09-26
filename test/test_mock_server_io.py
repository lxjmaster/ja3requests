"""EOF normalization must not hide truncated messages or authentication errors."""

import ssl

import pytest

from test.mock_servers.local import read_exact, recv_with_ragged_eof


class FailingSocket:
    def __init__(self, error):
        self.error = error

    def recv(self, size):
        raise self.error


def test_old_openssl_eof_is_normalized():
    conn = FailingSocket(
        ssl.SSLError(1, "[SSL: KRB5_S_TKT_NYV] unexpected eof while reading")
    )
    assert recv_with_ragged_eof(conn, 1) == b""
    with pytest.raises(EOFError):
        read_exact(conn, 1)


@pytest.mark.parametrize(
    "error", [ssl.SSLError(1, "bad record mac"), TimeoutError("timed out")]
)
def test_other_read_errors_are_not_suppressed(error):
    with pytest.raises(type(error), match=str(error)):
        recv_with_ragged_eof(FailingSocket(error), 1)
