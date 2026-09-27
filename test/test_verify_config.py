"""Per-request verification overrides must preserve shared cache ownership."""

from types import SimpleNamespace

import pytest

from ja3requests import Session, TlsConfig
from ja3requests.protocol.tls import TLS
from ja3requests.sockets.https import HttpsSocket


@pytest.mark.parametrize("initial,requested", [(False, True), (True, False)])
def test_verify_override_preserves_cache_and_isolates_config(
    monkeypatch, initial, requested
):
    config = TlsConfig()
    config.verify_cert = initial
    config.supported_groups = [29]
    with Session(tls_config=config, use_pooling=False) as session:
        captured = []
        monkeypatch.setattr(
            session, "send", lambda request, **kwargs: captured.append(request)
        )
        session.get("https://example.invalid/", verify=requested)
        clone = captured[0].tls_config
        assert clone.verify_cert is requested
        assert config.verify_cert is initial
        assert clone.session_cache is config.session_cache
        clone.supported_groups.append(23)
        assert config.supported_groups == [29]


@pytest.mark.parametrize("verify_cert", [False, True])
def test_unspecified_verify_uses_session_config(monkeypatch, verify_cert):
    config = TlsConfig()
    config.verify_cert = verify_cert
    with Session(tls_config=config, use_pooling=False) as session:
        captured = []
        monkeypatch.setattr(
            session, "send", lambda request, **kwargs: captured.append(request)
        )
        session.get("https://example.invalid/")
        assert captured[0].tls_config is config
        assert captured[0].tls_config.verify_cert is verify_cert


@pytest.mark.parametrize("initial,requested", [(False, True), (True, False)])
def test_redirect_preserves_request_verify_override(monkeypatch, initial, requested):
    config = TlsConfig()
    config.verify_cert = initial
    with Session(tls_config=config, use_pooling=False) as session:
        captured = []

        def fake_send(request, **kwargs):
            captured.append(request)
            return SimpleNamespace(status_code=200)

        monkeypatch.setattr(session, "send", fake_send)
        session.get("https://example.invalid/start", verify=requested)
        session.resolve_redirects("/next")

        assert captured[0].tls_config.verify_cert is requested
        assert captured[1].tls_config is captured[0].tls_config
        assert config.verify_cert is initial


def test_sni_follows_each_destination_without_mutating_session_config(monkeypatch):
    config = TlsConfig.secure()
    seen = []

    class FakeTLS(TLS):
        def set_payload(self, tls_config):
            super().set_payload(tls_config)
            seen.append(self._server_name)

        def handshake(self):
            return True

    monkeypatch.setattr("ja3requests.sockets.https.TLS", FakeTLS)
    for host in ("first.example", "second.example"):
        context = SimpleNamespace(
            destination_address=host,
            port=443,
            tls_config=config,
            connect_timeout=1,
        )
        sock = HttpsSocket(context)
        sock._new_conn = lambda host, port: SimpleNamespace(close=lambda: None)
        sock.new_conn()

    assert seen == ["first.example", "second.example"]
    assert config.server_name is None


def test_secure_profile_discards_verified_legacy_pooled_connection():
    host = "example.com"
    old_tls = SimpleNamespace(
        _cert_verified=True,
        _verified_hostname=host,
        _selected_cipher_suite=0x002F,
        _pool_policy_key=("legacy",),
    )
    pooled = SimpleNamespace(conn=object(), tls=old_tls)

    class Pool:
        discarded = False

        def get_connection(self, *args):
            return pooled

        def discard_connection(self, connection):
            assert connection is pooled
            self.discarded = True

    class NewConnectionExpected(Exception):
        pass

    def open_new_connection(host, port):
        raise NewConnectionExpected

    pool = Pool()
    context = SimpleNamespace(
        destination_address=host,
        port=443,
        tls_config=TlsConfig.secure(),
    )
    sock = HttpsSocket(context, pool=pool)
    sock._new_conn = open_new_connection
    with pytest.raises(NewConnectionExpected):
        sock.new_conn()
    assert pool.discarded
