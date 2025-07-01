import time
import os
import struct
from ja3requests.protocol.tls.layers import HandShake


class ClientHello(HandShake):
    """
    The ClientHello message includes a random structure, which is used later in the protocol.

    opaque SessionID<0..32>;
    uint8 CipherSuite[2];    /* Cryptographic suite selector */
    enum { null(0), (255) } CompressionMethod;

    struct {
        ExtensionType extension_type;
        opaque extension_data<0..2^16-1>;
    } Extension;

    enum {
        signature_algorithms(13), (65535)
    } ExtensionType;
    -  "extension_type" identifies the particular extension type.
    -  "extension_data" contains information specific to the particular extension type.

    struct {
        uint8 major;
        uint8 minor;
    } ProtocolVersion;

    ProtocolVersion version = { 3, 3 };     /* TLS v1.2*/

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

    cipher_suites
        This is a list of the cryptographic options supported by the
        client, with the client's first preference first.  If the
        session_id field is not empty (implying a session resumption
        request), this vector MUST include at least the cipher_suite from
        that session.

        A cipher suite defines a cipher specification supported in TLS
        Version 1.2.
            CipherSuite TLS_NULL_WITH_NULL_NULL               = { 0x00,0x00 };

        The following CipherSuite definitions require that the server provide
        an RSA certificate that can be used for key exchange.  The server may
        request any signature-capable certificate in the certificate request
        message.
            CipherSuite TLS_RSA_WITH_NULL_MD5                 = { 0x00,0x01 };
            CipherSuite TLS_RSA_WITH_NULL_SHA                 = { 0x00,0x02 };
            CipherSuite TLS_RSA_WITH_NULL_SHA256              = { 0x00,0x3B };
            CipherSuite TLS_RSA_WITH_RC4_128_MD5              = { 0x00,0x04 };
            CipherSuite TLS_RSA_WITH_RC4_128_SHA              = { 0x00,0x05 };
            CipherSuite TLS_RSA_WITH_3DES_EDE_CBC_SHA         = { 0x00,0x0A };
            CipherSuite TLS_RSA_WITH_AES_128_CBC_SHA          = { 0x00,0x2F };
            CipherSuite TLS_RSA_WITH_AES_256_CBC_SHA          = { 0x00,0x35 };
            CipherSuite TLS_RSA_WITH_AES_128_CBC_SHA256       = { 0x00,0x3C };
            CipherSuite TLS_RSA_WITH_AES_256_CBC_SHA256       = { 0x00,0x3D };

        The following cipher suite definitions are used for server-
        authenticated (and optionally client-authenticated) Diffie-Hellman.
        DH denotes cipher suites in which the server's certificate contains
        the Diffie-Hellman parameters signed by the certificate authority
        (CA).  DHE denotes ephemeral Diffie-Hellman, where the Diffie-Hellman
        parameters are signed by a signature-capable certificate, which has
        been signed by the CA.  The signing algorithm used by the server is
        specified after the DHE component of the CipherSuite name.  The
        server can request any signature-capable certificate from the client
        for client authentication, or it may request a Diffie-Hellman
        certificate.  Any Diffie-Hellman certificate provided by the client
        must use the parameters (group and generator) described by the
        server.
            CipherSuite TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA      = { 0x00,0x0D };
            CipherSuite TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA      = { 0x00,0x10 };
            CipherSuite TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA     = { 0x00,0x13 };
            CipherSuite TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA     = { 0x00,0x16 };
            CipherSuite TLS_DH_DSS_WITH_AES_128_CBC_SHA       = { 0x00,0x30 };
            CipherSuite TLS_DH_RSA_WITH_AES_128_CBC_SHA       = { 0x00,0x31 };
            CipherSuite TLS_DHE_DSS_WITH_AES_128_CBC_SHA      = { 0x00,0x32 };
            CipherSuite TLS_DHE_RSA_WITH_AES_128_CBC_SHA      = { 0x00,0x33 };
            CipherSuite TLS_DH_DSS_WITH_AES_256_CBC_SHA       = { 0x00,0x36 };
            CipherSuite TLS_DH_RSA_WITH_AES_256_CBC_SHA       = { 0x00,0x37 };
            CipherSuite TLS_DHE_DSS_WITH_AES_256_CBC_SHA      = { 0x00,0x38 };
            CipherSuite TLS_DHE_RSA_WITH_AES_256_CBC_SHA      = { 0x00,0x39 };
            CipherSuite TLS_DH_DSS_WITH_AES_128_CBC_SHA256    = { 0x00,0x3E };
            CipherSuite TLS_DH_RSA_WITH_AES_128_CBC_SHA256    = { 0x00,0x3F };
            CipherSuite TLS_DHE_DSS_WITH_AES_128_CBC_SHA256   = { 0x00,0x40 };
            CipherSuite TLS_DHE_RSA_WITH_AES_128_CBC_SHA256   = { 0x00,0x67 };
            CipherSuite TLS_DH_DSS_WITH_AES_256_CBC_SHA256    = { 0x00,0x68 };
            CipherSuite TLS_DH_RSA_WITH_AES_256_CBC_SHA256    = { 0x00,0x69 };
            CipherSuite TLS_DHE_DSS_WITH_AES_256_CBC_SHA256   = { 0x00,0x6A };
            CipherSuite TLS_DHE_RSA_WITH_AES_256_CBC_SHA256   = { 0x00,0x6B };

        The following cipher suites are used for completely anonymous
        Diffie-Hellman communications in which neither party is
        authenticated.  Note that this mode is vulnerable to man-in-the-
        middle attacks.  Using this mode therefore is of limited use: These
        cipher suites MUST NOT be used by TLS 1.2 implementations unless the
        application layer has specifically requested to allow anonymous key
        exchange.  (Anonymous key exchange may sometimes be acceptable, for
        example, to support opportunistic encryption when no set-up for
        authentication is in place, or when TLS is used as part of more
        complex security protocols that have other means to ensure
        authentication.)
            CipherSuite TLS_DH_anon_WITH_RC4_128_MD5          = { 0x00,0x18 };
            CipherSuite TLS_DH_anon_WITH_3DES_EDE_CBC_SHA     = { 0x00,0x1B };
            CipherSuite TLS_DH_anon_WITH_AES_128_CBC_SHA      = { 0x00,0x34 };
            CipherSuite TLS_DH_anon_WITH_AES_256_CBC_SHA      = { 0x00,0x3A };
            CipherSuite TLS_DH_anon_WITH_AES_128_CBC_SHA256   = { 0x00,0x6C };
            CipherSuite TLS_DH_anon_WITH_AES_256_CBC_SHA256   = { 0x00,0x6D };

        Note: The cipher suite values { 0x00, 0x1C } and { 0x00, 0x1D } are
        reserved to avoid collision with Fortezza-based cipher suites in
        SSL 3.
    """

    def __init__(self, tls_version: bytes = None, cipher_suites=None, client_random=None, 
                 server_name=None, supported_groups=None, signature_algorithms=None, 
                 alpn_protocols=None, use_grease=True, extensions=None):
        super().__init__()
        self._version = tls_version
        self._random = client_random
        self._session_id = None
        self._cipher_suites = None
        self._extensions = None
        self._server_name = server_name
        self._supported_groups = supported_groups or [23, 24, 25]  # Default curves
        self._signature_algorithms = signature_algorithms or [0x0601, 0x0603, 0x0501, 0x0503]
        self._alpn_protocols = alpn_protocols or []
        self._use_grease = use_grease
        
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
            # self._version = struct.pack("I", 771)[:2]

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
            from ja3requests.protocol.tls.cipher_suites.suites import ReservedGrease
            grease = ReservedGrease()
            cipher_bytes += struct.pack("!H", grease.value)
        
        for suite in cipher_suites:
            if hasattr(suite, 'value'):
                cipher_bytes += struct.pack("!H", suite.value)
            else:
                cipher_bytes += struct.pack("!H", suite)
        
        self._cipher_suites = cipher_bytes

    def _build_extensions(self):
        """
        Build TLS extensions based on configuration
        """
        extensions = b""
        
        # Server Name Indication (SNI) - Extension Type 0
        if self._server_name:
            sni_data = self._build_sni_extension()
            extensions += struct.pack("!H", 0)  # Extension type
            extensions += struct.pack("!H", len(sni_data))  # Extension length
            extensions += sni_data
        
        # Supported Groups (Elliptic Curves) - Extension Type 10
        if self._supported_groups:
            groups_data = self._build_supported_groups_extension()
            extensions += struct.pack("!H", 10)  # Extension type
            extensions += struct.pack("!H", len(groups_data))  # Extension length
            extensions += groups_data
        
        # Signature Algorithms - Extension Type 13
        if self._signature_algorithms:
            sig_algs_data = self._build_signature_algorithms_extension()
            extensions += struct.pack("!H", 13)  # Extension type
            extensions += struct.pack("!H", len(sig_algs_data))  # Extension length
            extensions += sig_algs_data
        
        # Application Layer Protocol Negotiation (ALPN) - Extension Type 16
        if self._alpn_protocols:
            alpn_data = self._build_alpn_extension()
            extensions += struct.pack("!H", 16)  # Extension type
            extensions += struct.pack("!H", len(alpn_data))  # Extension length
            extensions += alpn_data
        
        # Extended Master Secret - Extension Type 23
        extensions += struct.pack("!H", 23)  # Extension type
        extensions += struct.pack("!H", 0)   # Extension length (empty)
        
        # Session Ticket - Extension Type 35
        extensions += struct.pack("!H", 35)  # Extension type
        extensions += struct.pack("!H", 0)   # Extension length (empty)
        
        if extensions:
            # Add extensions length header
            self._extensions = struct.pack("!H", len(extensions)) + extensions

    def _build_sni_extension(self):
        """Build Server Name Indication extension"""
        server_name_bytes = self._server_name.encode('utf-8')
        sni_data = struct.pack("!H", len(server_name_bytes) + 3)  # Server name list length
        sni_data += struct.pack("!B", 0)  # Name type (hostname)
        sni_data += struct.pack("!H", len(server_name_bytes))  # Name length
        sni_data += server_name_bytes
        return sni_data

    def _build_supported_groups_extension(self):
        """Build Supported Groups extension"""
        groups_data = struct.pack("!H", len(self._supported_groups) * 2)  # Length
        for group in self._supported_groups:
            groups_data += struct.pack("!H", group)
        return groups_data

    def _build_signature_algorithms_extension(self):
        """Build Signature Algorithms extension"""
        sig_data = struct.pack("!H", len(self._signature_algorithms) * 2)  # Length
        for sig_alg in self._signature_algorithms:
            sig_data += struct.pack("!H", sig_alg)
        return sig_data

    def _build_alpn_extension(self):
        """Build Application Layer Protocol Negotiation extension"""
        protocols_data = b""
        for protocol in self._alpn_protocols:
            protocol_bytes = protocol.encode('utf-8')
            protocols_data += struct.pack("!B", len(protocol_bytes))
            protocols_data += protocol_bytes
        
        alpn_data = struct.pack("!H", len(protocols_data))  # Protocol list length
        alpn_data += protocols_data
        return alpn_data


if __name__ == '__main__':
    print(ClientHello().message)
