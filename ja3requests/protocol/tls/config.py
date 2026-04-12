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
