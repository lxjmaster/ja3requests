"""
ja3requests.protocol.tls.config
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

This module provides TLS configuration for customizing TLS handshake parameters.
"""

from typing import List, Optional

from ja3requests.protocol.tls.cipher_suites.suites import (
    EcdheEcdsaWithAes128GcmSha256,
    EcdheEcdsaWithAes256GcmSha384,
    EcdheRsaWithAes128CbcSha256,
    EcdheRsaWithAes128GcmSha256,
    EcdheRsaWithAes256CbcSha384,
    EcdheRsaWithAes256GcmSha384,
    ReservedGrease,
    RsaWithAes128CbcSha,
    RsaWithAes256CbcSha,
)


class TlsConfig:
    """
    TLS Configuration class for customizing TLS handshake parameters.

    This class allows customization of various TLS parameters to create
    custom JA3 fingerprints during the TLS handshake process.
    """

    def __init__(self):
        # TLS Version
        self._tls_version = 0x0303  # TLS 1.2 by default

        # Cipher Suites - use minimal, most compatible set by default
        self._cipher_suites = [
            RsaWithAes128CbcSha(),  # Most widely supported
        ]

        # Extensions
        self._extensions = []

        # Supported Groups (for Elliptic Curve) - minimal for compatibility
        self._supported_groups = []  # Empty for maximum compatibility

        # Signature Algorithms - minimal for compatibility
        self._signature_algorithms = []  # Empty for maximum compatibility

        # Compression Methods
        self._compression_methods = [0]  # null compression

        # Random values
        self._client_random = None
        self._server_random = None

        # Session ID
        self._session_id = b""

        # Application Layer Protocol Negotiation (ALPN)
        self._alpn_protocols = []

        # SNI (Server Name Indication)
        self._server_name = None

        # Other configurations
        self._use_grease = False  # Disable GREASE for compatibility
        self._max_fragment_length = None

        # Certificate verification
        self._verify_cert = False  # Default to False for backward compatibility

        # Session cache for TLS session resumption
        self._session_cache = None

        # HTTP/2 fingerprint settings
        self._h2_settings = None
        self._h2_window_update = None

        # Client certificate for mutual TLS
        self._client_cert = None  # PEM-encoded certificate bytes or file path
        self._client_key = None   # PEM-encoded private key bytes or file path

    @property
    def tls_version(self) -> int:
        """Get TLS version"""
        return self._tls_version

    @tls_version.setter
    def tls_version(self, version: int):
        """Set TLS version (e.g., 0x0303 for TLS 1.2, 0x0304 for TLS 1.3)"""
        self._tls_version = version

    @property
    def cipher_suites(self) -> List:
        """Get cipher suites list"""
        return self._cipher_suites

    @cipher_suites.setter
    def cipher_suites(self, suites: List):
        """Set cipher suites list"""
        self._cipher_suites = suites

    def add_cipher_suite(self, suite):
        """Add a cipher suite to the list"""
        if suite not in self._cipher_suites:
            self._cipher_suites.append(suite)

    def remove_cipher_suite(self, suite):
        """Remove a cipher suite from the list"""
        if suite in self._cipher_suites:
            self._cipher_suites.remove(suite)

    @property
    def extensions(self) -> List:
        """Get extensions list"""
        return self._extensions

    @extensions.setter
    def extensions(self, extensions: List):
        """Set extensions list"""
        self._extensions = extensions

    def add_extension(self, extension):
        """Add an extension"""
        self._extensions.append(extension)

    @property
    def supported_groups(self) -> List[int]:
        """Get supported groups (elliptic curves)"""
        return self._supported_groups

    @supported_groups.setter
    def supported_groups(self, groups: List[int]):
        """Set supported groups"""
        self._supported_groups = groups

    @property
    def signature_algorithms(self) -> List[int]:
        """Get signature algorithms"""
        return self._signature_algorithms

    @signature_algorithms.setter
    def signature_algorithms(self, sig_algorithms: List[int]):
        """Set signature algorithms"""
        self._signature_algorithms = sig_algorithms

    @property
    def compression_methods(self) -> List[int]:
        """Get compression methods"""
        return self._compression_methods

    @compression_methods.setter
    def compression_methods(self, methods: List[int]):
        """Set compression methods"""
        self._compression_methods = methods

    @property
    def client_random(self) -> Optional[bytes]:
        """Get client random"""
        return self._client_random

    @client_random.setter
    def client_random(self, random_bytes: bytes):
        """Set client random (32 bytes)"""
        if len(random_bytes) != 32:
            raise ValueError("Client random must be 32 bytes")
        self._client_random = random_bytes

    @property
    def server_random(self) -> Optional[bytes]:
        """Get server random"""
        return self._server_random

    @server_random.setter
    def server_random(self, random_bytes: bytes):
        """Set server random (32 bytes)"""
        if len(random_bytes) != 32:
            raise ValueError("Server random must be 32 bytes")
        self._server_random = random_bytes

    @property
    def session_id(self) -> bytes:
        """Get session ID"""
        return self._session_id

    @session_id.setter
    def session_id(self, session_id: bytes):
        """Set session ID"""
        self._session_id = session_id

    @property
    def alpn_protocols(self) -> List[str]:
        """Get ALPN protocols"""
        return self._alpn_protocols

    @alpn_protocols.setter
    def alpn_protocols(self, protocols: List[str]):
        """Set ALPN protocols (e.g., ['h2', 'http/1.1'])"""
        self._alpn_protocols = protocols

    @property
    def server_name(self) -> Optional[str]:
        """Get SNI server name"""
        return self._server_name

    @server_name.setter
    def server_name(self, name: str):
        """Set SNI server name"""
        self._server_name = name

    @property
    def use_grease(self) -> bool:
        """Get GREASE usage flag"""
        return self._use_grease

    @use_grease.setter
    def use_grease(self, use: bool):
        """Set GREASE usage flag"""
        self._use_grease = use

    @property
    def max_fragment_length(self) -> Optional[int]:
        """Get max fragment length"""
        return self._max_fragment_length

    @max_fragment_length.setter
    def max_fragment_length(self, length: int):
        """Set max fragment length"""
        self._max_fragment_length = length

    @property
    def verify_cert(self) -> bool:
        """Get certificate verification flag"""
        return self._verify_cert

    @verify_cert.setter
    def verify_cert(self, verify: bool):
        """Set certificate verification flag"""
        self._verify_cert = verify

    @property
    def session_cache(self):
        """Get session cache for TLS session resumption."""
        return self._session_cache

    @session_cache.setter
    def session_cache(self, cache):
        """Set session cache for TLS session resumption."""
        self._session_cache = cache

    @property
    def h2_settings(self):
        """Get HTTP/2 SETTINGS for H2 fingerprint."""
        return self._h2_settings

    @h2_settings.setter
    def h2_settings(self, settings):
        """Set HTTP/2 SETTINGS dict (e.g., {0x01: 65535, 0x03: 1000})."""
        self._h2_settings = settings

    @property
    def h2_window_update(self):
        """Get HTTP/2 initial WINDOW_UPDATE increment."""
        return self._h2_window_update

    @h2_window_update.setter
    def h2_window_update(self, value):
        """Set HTTP/2 initial WINDOW_UPDATE increment."""
        self._h2_window_update = value

    @property
    def client_cert(self):
        """Get client certificate path or PEM data."""
        return self._client_cert

    @client_cert.setter
    def client_cert(self, value):
        """Set client certificate (file path or PEM bytes)."""
        self._client_cert = value

    @property
    def client_key(self):
        """Get client private key path or PEM data."""
        return self._client_key

    @client_key.setter
    def client_key(self, value):
        """Set client private key (file path or PEM bytes)."""
        self._client_key = value

    def get_cipher_suite_values(self) -> List[int]:
        """Get cipher suite values as integers for JA3 fingerprint"""
        values = []
        if self._use_grease:
            values.append(ReservedGrease().value)

        for suite in self._cipher_suites:
            values.append(suite.value)

        return values

    def get_ja3_string(self) -> str:
        """
        Generate JA3 fingerprint string based on current configuration.
        Format: TLSVersion,CipherSuites,Extensions,EllipticCurves,EllipticCurvePointFormats
        """
        from ja3requests.protocol.tls.extensions import (  # pylint: disable=import-outside-toplevel
            Extension,
            SNIExtension,
            SupportedGroupsExtension,
            SignatureAlgorithmsExtension,
            ALPNExtension,
        )

        # TLS Version
        tls_version = str(self._tls_version)

        # Cipher Suites
        cipher_suites = "-".join([str(suite.value) for suite in self._cipher_suites])

        # Extensions: collect type IDs from Extension objects + auto-generated ones
        ext_types = []
        custom_types = set()
        for ext in self._extensions:
            if isinstance(ext, Extension):
                ext_types.append(ext.extension_type)
                custom_types.add(ext.extension_type)

        # Auto-generated extensions (same logic as ClientHello._build_extensions)
        if self._server_name and SNIExtension.extension_type not in custom_types:
            ext_types.append(SNIExtension.extension_type)
        if self._supported_groups and SupportedGroupsExtension.extension_type not in custom_types:
            ext_types.append(SupportedGroupsExtension.extension_type)
        if self._signature_algorithms and SignatureAlgorithmsExtension.extension_type not in custom_types:
            ext_types.append(SignatureAlgorithmsExtension.extension_type)
        if self._alpn_protocols and ALPNExtension.extension_type not in custom_types:
            ext_types.append(ALPNExtension.extension_type)

        extensions = "-".join([str(t) for t in ext_types])

        # Elliptic Curves (Supported Groups)
        elliptic_curves = "-".join([str(group) for group in self._supported_groups]) if self._supported_groups else ""

        # Elliptic Curve Point Formats (commonly 0 for uncompressed)
        ec_point_formats = "0"

        return f"{tls_version},{cipher_suites},{extensions},{elliptic_curves},{ec_point_formats}"

    def create_firefox_config(self):
        """Create a TLS config that mimics Firefox"""
        self._tls_version = 0x0303  # TLS 1.2
        self._cipher_suites = [
            EcdheRsaWithAes128GcmSha256(),
            EcdheRsaWithAes256GcmSha384(),
            EcdheEcdsaWithAes128GcmSha256(),
            EcdheEcdsaWithAes256GcmSha384(),
            EcdheRsaWithAes128CbcSha256(),
            EcdheRsaWithAes256CbcSha384(),
            RsaWithAes128CbcSha(),
            RsaWithAes256CbcSha(),
        ]
        self._supported_groups = [23, 24, 25]  # secp256r1, secp384r1, secp521r1
        self._alpn_protocols = ['h2', 'http/1.1']
        return self

    def create_chrome_config(self):
        """Create a TLS config that mimics Chrome"""
        self._tls_version = 0x0303  # TLS 1.2
        self._cipher_suites = [
            EcdheRsaWithAes128GcmSha256(),
            EcdheRsaWithAes256GcmSha384(),
            EcdheEcdsaWithAes128GcmSha256(),
            EcdheEcdsaWithAes256GcmSha384(),
            EcdheRsaWithAes128CbcSha256(),
            EcdheRsaWithAes256CbcSha384(),
            RsaWithAes128CbcSha(),
            RsaWithAes256CbcSha(),
        ]
        self._supported_groups = [23, 24, 25]  # secp256r1, secp384r1, secp521r1
        self._alpn_protocols = ['h2', 'http/1.1']
        return self

    def create_custom_config(
        self,
        *,
        tls_version: int = None,
        cipher_suites: List = None,
        supported_groups: List[int] = None,
        alpn_protocols: List[str] = None,
        server_name: str = None,
    ):
        """Create a custom TLS config with specified parameters"""
        if tls_version is not None:
            self._tls_version = tls_version
        if cipher_suites is not None:
            self._cipher_suites = cipher_suites
        if supported_groups is not None:
            self._supported_groups = supported_groups
        if alpn_protocols is not None:
            self._alpn_protocols = alpn_protocols
        if server_name is not None:
            self._server_name = server_name
        return self

    # Valid IANA named groups (elliptic curves)
    VALID_GROUPS = frozenset({
        1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20,
        21, 22, 23, 24, 25, 26, 27, 28, 29, 30,  # Named curves through x448
        256, 257, 258, 259, 260,  # FFDHE groups
    })

    VALID_TLS_VERSIONS = frozenset({0x0301, 0x0302, 0x0303, 0x0304})

    def validate(self, strict=False):
        """
        Validate the TLS configuration for correctness.

        :param strict: If True, raise ValueError on first issue.
                       If False, return list of issue strings.
        :return: List of issue descriptions (empty if valid)
        """
        issues = []

        # TLS version
        if self._tls_version not in self.VALID_TLS_VERSIONS:
            issues.append(f"Invalid TLS version: 0x{self._tls_version:04X}. "
                          f"Valid: {sorted(hex(v) for v in self.VALID_TLS_VERSIONS)}")

        # Cipher suites
        if not self._cipher_suites:
            issues.append("No cipher suites configured")
        else:
            for suite in self._cipher_suites:
                if not hasattr(suite, 'value'):
                    issues.append(f"Cipher suite {suite!r} missing 'value' attribute")

        # Supported groups
        if self._supported_groups:
            for group in self._supported_groups:
                if group not in self.VALID_GROUPS:
                    issues.append(f"Unknown supported group: {group}")

        # Signature algorithms (must be 2-byte values)
        if self._signature_algorithms:
            for alg in self._signature_algorithms:
                if not (0x0000 <= alg <= 0xFFFF):
                    issues.append(f"Invalid signature algorithm: 0x{alg:04X}")

        # ALPN protocols
        if self._alpn_protocols:
            for proto in self._alpn_protocols:
                if not isinstance(proto, str) or len(proto) == 0 or len(proto) > 255:
                    issues.append(f"Invalid ALPN protocol: {proto!r}")

        # Client random length
        if self._client_random is not None and len(self._client_random) != 32:
            issues.append(f"Client random must be 32 bytes, got {len(self._client_random)}")

        # TLS 1.3 requires supported_groups for key exchange
        if self._tls_version == 0x0304 and not self._supported_groups:
            issues.append("TLS 1.3 requires supported_groups to be set")

        if strict and issues:
            raise ValueError(f"TLS config validation failed: {issues[0]}")

        return issues

    @classmethod
    def from_browser(cls, browser, version=None, server_name=None):
        """
        Create a TlsConfig that mimics a specific browser version.

        :param browser: Browser name ("chrome", "firefox", "safari", "edge")
        :param version: Browser version number (e.g., 120). Defaults to latest.
        :param server_name: Optional SNI server name.
        :return: Configured TlsConfig instance

        Usage::

            config = TlsConfig.from_browser("chrome", version=120)
            session = Session(tls_config=config)
        """
        from ja3requests.protocol.tls.browser_presets import get_preset  # pylint: disable=import-outside-toplevel

        preset = get_preset(browser, version)
        config = cls()
        config._tls_version = preset["tls_version"]
        config._cipher_suites = list(preset["cipher_suites"])
        config._supported_groups = list(preset["supported_groups"])
        config._signature_algorithms = list(preset["signature_algorithms"])
        config._alpn_protocols = list(preset["alpn_protocols"])
        config._use_grease = preset.get("use_grease", False)
        config._extensions = list(preset.get("extensions", []))
        config._h2_settings = preset.get("h2_settings")
        config._h2_window_update = preset.get("h2_window_update")
        if server_name:
            config._server_name = server_name
        return config
