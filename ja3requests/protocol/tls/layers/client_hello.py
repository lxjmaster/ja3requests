"""TLS ClientHello handshake message layer."""

import struct
from ja3requests.protocol.tls.layers import HandShake
from ja3requests.protocol.tls.extensions import (
    Extension,
    SNIExtension,
    SupportedGroupsExtension,
    SignatureAlgorithmsExtension,
    ALPNExtension,
)


class ClientHello(HandShake):
    """
    The ClientHello message includes a random structure, which is used later in the protocol.

    struct {
        ProtocolVersion client_version;
        Random random;
        SessionID session_id;
        CipherSuite cipher_suites<2..2^16-2>;
        CompressionMethod compression_methods<1..2^8-1>;
        select (extensions_present) {
            case false:
                struct {};
            case true:
                Extension extensions<0..2^16-1>;
        };
    } ClientHello;
    """

    def __init__(
        self,
        tls_version: bytes = None,
        cipher_suites=None,
        client_random=None,
        server_name=None,
        *,
        supported_groups=None,
        signature_algorithms=None,
        alpn_protocols=None,
        use_grease=True,
        _extensions=None,
    ):
        super().__init__()
        self._version = tls_version
        self._random = client_random
        self._session_id = None
        self._cipher_suites = None
        self._extensions = None
        self._server_name = server_name
        self._supported_groups = supported_groups
        self._signature_algorithms = signature_algorithms
        self._alpn_protocols = alpn_protocols or []
        self._use_grease = use_grease
        self._custom_extensions = _extensions or []

        # Set cipher suites
        if cipher_suites:
            self._set_cipher_suites(cipher_suites)

        # Build extensions
        self._build_extensions()

    @property
    def handshake_type(self) -> bytes:
        """
        HandshakeType client_hello(1)
        :return:
        """

        return struct.pack("B", 1)

    @property
    def version(self) -> bytes:
        """
        client_version
            The version of the TLS protocol by which the client wishes to
            communicate during this session.  This SHOULD be the latest
            (highest valued) version supported by the client.  For this
            version of the specification, the version will be 3.3.

                ProtocolVersion version = { 3, 3 };     /* TLS v1.2*/
        :return:
        """

        if not self._version:
            self._version = struct.pack("B", 3) + struct.pack("B", 3)

        return self._version

    @version.setter
    def version(self, attr: bytes):

        self._version = attr

    def _set_cipher_suites(self, cipher_suites):
        """
        Set cipher suites from TlsConfig
        """
        cipher_bytes = b""

        if self._use_grease:
            # Add GREASE value at the beginning
            # pylint: disable-next=import-outside-toplevel
            from ja3requests.protocol.tls.cipher_suites.suites import ReservedGrease

            grease = ReservedGrease()
            cipher_bytes += struct.pack("!H", grease.value)

        # Add only the specified cipher suites
        for suite in cipher_suites:
            if hasattr(suite, 'value'):
                cipher_bytes += struct.pack("!H", suite.value)
            else:
                cipher_bytes += struct.pack("!H", suite)

        self._cipher_suites = cipher_bytes

    def _build_extensions(self):
        """
        Build TLS extensions from Extension objects and configuration parameters.

        Priority order:
        1. Custom Extension objects passed via _extensions (from TlsConfig)
        2. Extensions auto-generated from individual parameters (server_name, etc.)

        If a custom extension has the same type as an auto-generated one,
        the custom extension takes precedence.
        """
        extension_list = []

        # Collect custom Extension objects first
        custom_types = set()
        for ext in self._custom_extensions:
            if isinstance(ext, Extension):
                extension_list.append(ext)
                custom_types.add(ext.extension_type)

        # Auto-generate extensions from parameters (skip if custom one exists)
        if self._server_name and SNIExtension.extension_type not in custom_types:
            extension_list.append(SNIExtension(self._server_name))

        if (self._supported_groups and len(self._supported_groups) > 0
                and SupportedGroupsExtension.extension_type not in custom_types):
            extension_list.append(SupportedGroupsExtension(self._supported_groups))

        if (self._signature_algorithms and len(self._signature_algorithms) > 0
                and SignatureAlgorithmsExtension.extension_type not in custom_types):
            extension_list.append(SignatureAlgorithmsExtension(self._signature_algorithms))

        if self._alpn_protocols and ALPNExtension.extension_type not in custom_types:
            extension_list.append(ALPNExtension(self._alpn_protocols))

        if extension_list:
            extensions_data = b"".join(ext.to_bytes() for ext in extension_list)
            self._extensions = struct.pack("!H", len(extensions_data)) + extensions_data


if __name__ == '__main__':
    print(ClientHello().message)
