"""Per-request verification overrides must preserve shared cache ownership."""

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
