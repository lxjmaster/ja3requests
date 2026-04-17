"""
ja3requests.protocol.tls.browser_presets
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Version-specific browser TLS fingerprint presets.
Each preset defines: TLS version, cipher suites, extensions, supported groups,
signature algorithms, ALPN, GREASE, and H2 settings — matching real browser JA3 fingerprints.
"""

from ja3requests.protocol.tls.cipher_suites.suites import (
    EcdheEcdsaWithAes128GcmSha256,
    EcdheEcdsaWithAes256GcmSha384,
    EcdheRsaWithAes128CbcSha256,
    EcdheRsaWithAes128GcmSha256,
    EcdheRsaWithAes256CbcSha384,
    EcdheRsaWithAes256GcmSha384,
    RsaWithAes128CbcSha,
    RsaWithAes256CbcSha,
)
from ja3requests.protocol.tls.extensions import (
    ECPointFormatsExtension,
    ExtendedMasterSecretExtension,
    RenegotiationInfoExtension,
    SessionTicketExtension,
    StatusRequestExtension,
)

# ============================================================================
# Cipher suite groups (reusable across presets)
# ============================================================================

_MODERN_CHROME_CIPHERS = [
    EcdheEcdsaWithAes128GcmSha256(),
    EcdheEcdsaWithAes256GcmSha384(),
    EcdheRsaWithAes128GcmSha256(),
    EcdheRsaWithAes256GcmSha384(),
    EcdheRsaWithAes128CbcSha256(),
    RsaWithAes128CbcSha(),
    RsaWithAes256CbcSha(),
]

_MODERN_FIREFOX_CIPHERS = [
    EcdheEcdsaWithAes128GcmSha256(),
    EcdheEcdsaWithAes256GcmSha384(),
    EcdheRsaWithAes128GcmSha256(),
    EcdheRsaWithAes256GcmSha384(),
    EcdheRsaWithAes128CbcSha256(),
    EcdheRsaWithAes256CbcSha384(),
    RsaWithAes128CbcSha(),
    RsaWithAes256CbcSha(),
]

# ============================================================================
# Preset definitions
# ============================================================================

PRESETS = {
    # ------ Chrome ------
    ("chrome", 100): {
        "tls_version": 0x0303,
        "cipher_suites": _MODERN_CHROME_CIPHERS,
        "supported_groups": [29, 23, 24],   # x25519, secp256r1, secp384r1
        "signature_algorithms": [0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601],
        "alpn_protocols": ["h2", "http/1.1"],
        "use_grease": True,
        "extensions": [
            RenegotiationInfoExtension(),
            ExtendedMasterSecretExtension(),
            SessionTicketExtension(),
            StatusRequestExtension(),
            ECPointFormatsExtension([0]),
        ],
        "h2_settings": {0x01: 65536, 0x02: 0, 0x03: 1000, 0x04: 6291456, 0x06: 262144},
        "h2_window_update": 15663105,
    },
    ("chrome", 110): {
        "tls_version": 0x0303,
        "cipher_suites": _MODERN_CHROME_CIPHERS,
        "supported_groups": [29, 23, 24],
        "signature_algorithms": [0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601],
        "alpn_protocols": ["h2", "http/1.1"],
        "use_grease": True,
        "extensions": [
            RenegotiationInfoExtension(),
            ExtendedMasterSecretExtension(),
            SessionTicketExtension(),
            StatusRequestExtension(),
            ECPointFormatsExtension([0]),
        ],
        "h2_settings": {0x01: 65536, 0x02: 0, 0x03: 1000, 0x04: 6291456, 0x06: 262144},
        "h2_window_update": 15663105,
    },
    ("chrome", 120): {
        "tls_version": 0x0304,
        "cipher_suites": _MODERN_CHROME_CIPHERS,
        "supported_groups": [29, 23, 24],
        "signature_algorithms": [0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601],
        "alpn_protocols": ["h2", "http/1.1"],
        "use_grease": True,
        "extensions": [
            RenegotiationInfoExtension(),
            ExtendedMasterSecretExtension(),
            SessionTicketExtension(),
            StatusRequestExtension(),
            ECPointFormatsExtension([0]),
        ],
        "h2_settings": {0x01: 65536, 0x02: 0, 0x03: 1000, 0x04: 6291456, 0x06: 262144},
        "h2_window_update": 15663105,
    },
    ("chrome", 124): {
        "tls_version": 0x0304,
        "cipher_suites": _MODERN_CHROME_CIPHERS,
        "supported_groups": [29, 23, 24],
        "signature_algorithms": [0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601],
        "alpn_protocols": ["h2", "http/1.1"],
        "use_grease": True,
        "extensions": [
            RenegotiationInfoExtension(),
            ExtendedMasterSecretExtension(),
            SessionTicketExtension(),
            StatusRequestExtension(),
            ECPointFormatsExtension([0]),
        ],
        "h2_settings": {0x01: 65536, 0x02: 0, 0x03: 1000, 0x04: 6291456, 0x06: 262144},
        "h2_window_update": 15663105,
    },

    # ------ Firefox ------
    ("firefox", 100): {
        "tls_version": 0x0303,
        "cipher_suites": _MODERN_FIREFOX_CIPHERS,
        "supported_groups": [29, 23, 24, 25],   # x25519, P-256, P-384, P-521
        "signature_algorithms": [0x0403, 0x0503, 0x0603, 0x0804, 0x0805, 0x0806, 0x0401, 0x0501, 0x0601],
        "alpn_protocols": ["h2", "http/1.1"],
        "use_grease": False,
        "extensions": [
            RenegotiationInfoExtension(),
            ExtendedMasterSecretExtension(),
            SessionTicketExtension(),
            StatusRequestExtension(),
            ECPointFormatsExtension([0]),
        ],
        "h2_settings": {0x01: 65536, 0x03: 128, 0x04: 131072, 0x06: 65536},
        "h2_window_update": 12517377,
    },
    ("firefox", 121): {
        "tls_version": 0x0304,
        "cipher_suites": _MODERN_FIREFOX_CIPHERS,
        "supported_groups": [29, 23, 24, 25],
        "signature_algorithms": [0x0403, 0x0503, 0x0603, 0x0804, 0x0805, 0x0806, 0x0401, 0x0501, 0x0601],
        "alpn_protocols": ["h2", "http/1.1"],
        "use_grease": False,
        "extensions": [
            RenegotiationInfoExtension(),
            ExtendedMasterSecretExtension(),
            SessionTicketExtension(),
            StatusRequestExtension(),
            ECPointFormatsExtension([0]),
        ],
        "h2_settings": {0x01: 65536, 0x03: 128, 0x04: 131072, 0x06: 65536},
        "h2_window_update": 12517377,
    },

    # ------ Safari ------
    ("safari", 16): {
        "tls_version": 0x0303,
        "cipher_suites": [
            EcdheEcdsaWithAes256GcmSha384(),
            EcdheEcdsaWithAes128GcmSha256(),
            EcdheRsaWithAes256GcmSha384(),
            EcdheRsaWithAes128GcmSha256(),
            EcdheRsaWithAes256CbcSha384(),
            EcdheRsaWithAes128CbcSha256(),
            RsaWithAes256CbcSha(),
            RsaWithAes128CbcSha(),
        ],
        "supported_groups": [29, 23, 24],
        "signature_algorithms": [0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601],
        "alpn_protocols": ["h2", "http/1.1"],
        "use_grease": True,
        "extensions": [
            RenegotiationInfoExtension(),
            ExtendedMasterSecretExtension(),
            SessionTicketExtension(),
            StatusRequestExtension(),
            ECPointFormatsExtension([0]),
        ],
        "h2_settings": {0x01: 4096, 0x03: 100, 0x04: 2097152, 0x06: 16384},
        "h2_window_update": 10485760,
    },
    ("safari", 17): {
        "tls_version": 0x0304,
        "cipher_suites": [
            EcdheEcdsaWithAes256GcmSha384(),
            EcdheEcdsaWithAes128GcmSha256(),
            EcdheRsaWithAes256GcmSha384(),
            EcdheRsaWithAes128GcmSha256(),
            EcdheRsaWithAes256CbcSha384(),
            EcdheRsaWithAes128CbcSha256(),
            RsaWithAes256CbcSha(),
            RsaWithAes128CbcSha(),
        ],
        "supported_groups": [29, 23, 24],
        "signature_algorithms": [0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601],
        "alpn_protocols": ["h2", "http/1.1"],
        "use_grease": True,
        "extensions": [
            RenegotiationInfoExtension(),
            ExtendedMasterSecretExtension(),
            SessionTicketExtension(),
            StatusRequestExtension(),
            ECPointFormatsExtension([0]),
        ],
        "h2_settings": {0x01: 4096, 0x03: 100, 0x04: 2097152, 0x06: 16384},
        "h2_window_update": 10485760,
    },

    # ------ Edge ------
    ("edge", 120): {
        "tls_version": 0x0304,
        "cipher_suites": _MODERN_CHROME_CIPHERS,  # Edge uses Chromium
        "supported_groups": [29, 23, 24],
        "signature_algorithms": [0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601],
        "alpn_protocols": ["h2", "http/1.1"],
        "use_grease": True,
        "extensions": [
            RenegotiationInfoExtension(),
            ExtendedMasterSecretExtension(),
            SessionTicketExtension(),
            StatusRequestExtension(),
            ECPointFormatsExtension([0]),
        ],
        "h2_settings": {0x01: 65536, 0x02: 0, 0x03: 1000, 0x04: 6291456, 0x06: 262144},
        "h2_window_update": 15663105,
    },
}

# Latest known version for each browser
_LATEST_VERSIONS = {
    "chrome": 124,
    "firefox": 121,
    "safari": 17,
    "edge": 120,
}


def get_preset(browser, version=None):
    """
    Get a browser fingerprint preset.

    :param browser: Browser name ("chrome", "firefox", "safari", "edge")
    :param version: Optional version number. If None, uses latest known.
    :return: Preset dict
    :raises ValueError: If browser/version not found
    """
    browser = browser.lower()

    if version is None:
        version = _LATEST_VERSIONS.get(browser)
        if version is None:
            raise ValueError(
                f"Unknown browser: {browser!r}. "
                f"Available: {', '.join(sorted(_LATEST_VERSIONS.keys()))}"
            )

    key = (browser, version)
    preset = PRESETS.get(key)
    if preset is None:
        available = sorted(v for b, v in PRESETS if b == browser)
        raise ValueError(
            f"No preset for {browser} {version}. "
            f"Available versions: {available}"
        )

    return preset


def list_browsers():
    """List all available browsers and versions."""
    result = {}
    for browser, version in sorted(PRESETS.keys()):
        result.setdefault(browser, []).append(version)
    return result
