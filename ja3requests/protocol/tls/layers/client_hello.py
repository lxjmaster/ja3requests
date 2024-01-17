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

    def __init__(self):
        super().__init__()
        self._client_version = None
        self._random = None
        self._session_id = None
        self._cipher_suites = None
        self._compression_methods = None
        self._extensions = None

    @property
    def handshake_type(self) -> bytes:
        """
        HandshakeType client_hello(1)
        :return:
        """

        return struct.pack("B", 1)

    @property
    def client_version(self) -> bytes:
        """
        client_version
            The version of the TLS protocol by which the client wishes to
            communicate during this session.  This SHOULD be the latest
            (highest valued) version supported by the client.  For this
            version of the specification, the version will be 3.3.

                ProtocolVersion version = { 3, 3 };     /* TLS v1.2*/
        :return:
        """

        client_version = self._version
        if not client_version:
            client_version = struct.pack("B", 3) + struct.pack("B", 3)

        return client_version

    @client_version.setter
    def client_version(self, attr: bytes):

        self._version = attr


if __name__ == '__main__':
    print(ClientHello().message)
