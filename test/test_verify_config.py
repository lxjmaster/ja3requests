"""Per-request verification overrides must preserve shared cache ownership."""

from types import SimpleNamespace

import pytest

from ja3requests import Session, TlsConfig


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
