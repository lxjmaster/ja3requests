from ja3requests.protocol.tls.cipher_suites import CipherSuite


"""
When SSLv3 and TLS 1.0 were designed, the United States restricted
the export of cryptographic software containing certain strong
encryption algorithms.  A series of cipher suites were designed to
operate at reduced key lengths in order to comply with those
regulations.  Due to advances in computer performance, these
algorithms are now unacceptably weak, and export restrictions have
since been loosened.  TLS 1.1 implementations MUST NOT negotiate
these cipher suites in TLS 1.1 mode.  However, for backward
compatibility they may be offered in the ClientHello for use with TLS
1.0 or SSLv3-only servers.  TLS 1.1 clients MUST check that the
server did not choose one of these cipher suites during the
handshake.  These ciphersuites are listed below for informational
purposes and to reserve the numbers.

    CipherSuite TLS_RSA_EXPORT_WITH_RC4_40_MD5         = { 0x00,0x03 };
    CipherSuite TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5     = { 0x00,0x06 };
    CipherSuite TLS_RSA_EXPORT_WITH_DES40_CBC_SHA      = { 0x00,0x08 };
    CipherSuite TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA   = { 0x00,0x0B };
    CipherSuite TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA   = { 0x00,0x0E };
    CipherSuite TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA  = { 0x00,0x11 };
    CipherSuite TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA  = { 0x00,0x14 };
    CipherSuite TLS_DH_anon_EXPORT_WITH_RC4_40_MD5     = { 0x00,0x17 };
    CipherSuite TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA  = { 0x00,0x19 };

The following cipher suites were defined in [TLSKRB] and are included
here for completeness.  See [TLSKRB] for details:

    CipherSuite    TLS_KRB5_WITH_DES_CBC_SHA           = { 0x00,0x1E }:
    CipherSuite    TLS_KRB5_WITH_3DES_EDE_CBC_SHA      = { 0x00,0x1F };
    CipherSuite    TLS_KRB5_WITH_RC4_128_SHA           = { 0x00,0x20 };
    CipherSuite    TLS_KRB5_WITH_IDEA_CBC_SHA          = { 0x00,0x21 };
    CipherSuite    TLS_KRB5_WITH_DES_CBC_MD5           = { 0x00,0x22 };
    CipherSuite    TLS_KRB5_WITH_3DES_EDE_CBC_MD5      = { 0x00,0x23 };
    CipherSuite    TLS_KRB5_WITH_RC4_128_MD5           = { 0x00,0x24 };
    CipherSuite    TLS_KRB5_WITH_IDEA_CBC_MD5          = { 0x00,0x25 };
    
The following exportable cipher suites were defined in [TLSKRB] and
are included here for completeness.  TLS 1.1 implementations MUST NOT
negotiate these cipher suites.

    CipherSuite  TLS_KRB5_EXPORT_WITH_DES_CBC_40_SHA    = { 0x00,0x26};
    CipherSuite  TLS_KRB5_EXPORT_WITH_RC2_CBC_40_SHA    = { 0x00,0x27};
    CipherSuite  TLS_KRB5_EXPORT_WITH_RC4_40_SHA        = { 0x00,0x28};
    CipherSuite  TLS_KRB5_EXPORT_WITH_DES_CBC_40_MD5    = { 0x00,0x29};
    CipherSuite  TLS_KRB5_EXPORT_WITH_RC2_CBC_40_MD5    = { 0x00,0x2A};
    CipherSuite  TLS_KRB5_EXPORT_WITH_RC4_40_MD5        = { 0x00,0x2B};
"""


class NullWithNullNull(CipherSuite):
    """
    TLS_NULL_WITH_NULL_NULL is specified and is the initial state of a
    TLS connection during the first handshake on that channel, but MUST
    NOT be negotiated, as it provides no more protection than an
    unsecured connection.

        CipherSuite TLS_NULL_WITH_NULL_NULL               = { 0x00,0x00 };
    """

    def __init__(self):
        super().__init__()
        self.name = "TLS_NULL_WITH_NULL_NULL"
        self.key_exchange_type = None
        self.hash_type = None
        self.cipher_type = "Stream"
        self.key_length = 0
        self.mac_key_length = 0
        self.value = 0x0000
        self.version = {1.1, 1.2}


"""
The following CipherSuite definitions require that the server provide
an RSA certificate that can be used for key exchange.  The server may
request any signature-capable certificate in the certificate request
message.
"""


class RsaWithNullMd5(CipherSuite):
    """
    CipherSuite TLS_RSA_WITH_NULL_MD5                 = { 0x00,0x01 };
    """

    def __init__(self):
        super().__init__()
        self.name = "TLS_RSA_WITH_NULL_MD5"
        self.key_exchange_type = "RSA"
        self.hash_type = "HMAC-MD5"
        self.cipher_type = "Stream"
        self.key_length = 0
        self.mac_key_length = 16
        self.value = 0x0001
        self.version = {1.1, 1.2}


class RsaWithNullSha(CipherSuite):
    """
    CipherSuite TLS_RSA_WITH_NULL_SHA                 = { 0x00,0x02 };
    """

    def __init__(self):
        super().__init__()
        self.name = "TLS_RSA_WITH_NULL_SHA"
        self.key_exchange_type = "RSA"
        self.hash_type = "HMAC-SHA1"
        self.cipher_type = "Stream"
        self.key_length = 0
        self.mac_key_length = 20
        self.value = 0x0002
        self.version = {1.1, 1.2}


class RsaWithIdeaCbcSha(CipherSuite):
    """
    CipherSuite TLS_RSA_WITH_IDEA_CBC_SHA              = { 0x00,0x07 };
    """

    def __init__(self):
        super().__init__()
        self.name = "TLS_RSA_WITH_IDEA_CBC_SHA"
        self.key_exchange_type = "RSA"
        self.hash_type = "HMAC-SHA1"
        self.cipher_type = "Block"
        self.key_length = 16
        self.mac_key_length = 20
        self.value = 0x0007
        self.version = {1.2}


class RsaWithDesCbcSha(CipherSuite):
    """
    CipherSuite TLS_RSA_WITH_DES_CBC_SHA               = { 0x00,0x09 };
    """

    def __init__(self):
        super().__init__()
        self.name = "TLS_RSA_WITH_DES_CBC_SHA"
        self.key_exchange_type = "RSA"
        self.hash_type = "HMAC-SHA1"
        self.cipher_type = "Block"
        self.key_length = 8
        self.mac_key_length = 20
        self.value = 0x0009
        self.version = {1.2}


class RsaWithNullSha256(CipherSuite):
    """
    CipherSuite TLS_RSA_WITH_NULL_SHA256              = { 0x00,0x3B };
    """

    def __init__(self):
        super().__init__()
        self.name = "TLS_RSA_WITH_NULL_SHA256"
        self.key_exchange_type = "RSA"
        self.hash_type = "HMAC-SHA256"
        self.cipher_type = "Stream"
        self.key_length = 0
        self.mac_key_length = 32
        self.value = 0x003B
        self.version = {1.1}


class RsaWithRc4128Md5(CipherSuite):
    """
    CipherSuite TLS_RSA_WITH_RC4_128_MD5              = { 0x00,0x04 };
    """

    def __init__(self):
        super().__init__()
        self.name = "TLS_RSA_WITH_RC4_128_MD5"
        self.key_exchange_type = "RSA"
        self.hash_type = "HMAC-MD5"
        self.cipher_type = "Stream"
        self.key_length = 16
        self.mac_key_length = 20
        self.value = 0x0004
        self.version = {1.1, 1.2}


class RsaWithRc4128Sha(CipherSuite):
    """
    CipherSuite TLS_RSA_WITH_RC4_128_SHA              = { 0x00,0x05 };
    """

    def __init__(self):
        super().__init__()
        self.name = "TLS_RSA_WITH_RC4_128_SHA"
        self.key_exchange_type = "RSA"
        self.hash_type = "HMAC-SHA1"
        self.cipher_type = "Stream"
        self.key_length = 16
        self.mac_key_length = 20
        self.value = 0x0005
        self.version = {1.1, 1.2}


class RsaWith3DesEdeCbcSha(CipherSuite):
    """
    CipherSuite TLS_RSA_WITH_3DES_EDE_CBC_SHA         = { 0x00,0x0A };
    """

    def __init__(self):
        super().__init__()
        self.name = "TLS_RSA_WITH_3DES_EDE_CBC_SHA"
        self.key_exchange_type = "RSA"
        self.hash_type = "HMAC-SHA1"
        self.cipher_type = "Block"
        self.key_length = 24
        self.mac_key_length = 20
        self.value = 0x000A
        self.version = {1.1, 1.2}


class RsaWithAes128CbcSha(CipherSuite):
    """
    CipherSuite TLS_RSA_WITH_AES_128_CBC_SHA          = { 0x00,0x2F };
    """

    def __init__(self):
        super().__init__()
        self.name = "TLS_RSA_WITH_AES_128_CBC_SHA"
        self.key_exchange_type = "RSA"
        self.hash_type = "HMAC-SHA1"
        self.cipher_type = "Block"
        self.key_length = 16
        self.mac_key_length = 20
        self.value = 0x002F
        self.version = {1.1, 1.2}


class RsaWithAes256CbcSha(CipherSuite):
    """
    CipherSuite TLS_RSA_WITH_AES_256_CBC_SHA          = { 0x00,0x35 };
    """

    def __init__(self):
        super().__init__()
        self.name = "TLS_RSA_WITH_AES_256_CBC_SHA"
        self.key_exchange_type = "RSA"
        self.hash_type = "HMAC-SHA1"
        self.cipher_type = "Block"
        self.key_length = 32
        self.mac_key_length = 20
        self.value = 0x0035
        self.version = {1.1, 1.2}


class RsaWithAes128CbcSha256(CipherSuite):
    """
    CipherSuite TLS_RSA_WITH_AES_128_CBC_SHA256       = { 0x00,0x3C };
    """

    def __init__(self):
        super().__init__()
        self.name = "TLS_RSA_WITH_AES_128_CBC_SHA256"
        self.key_exchange_type = "RSA"
        self.hash_type = "HMAC-SHA256"
        self.cipher_type = "Block"
        self.key_length = 16
        self.mac_key_length = 32
        self.value = 0x003C
        self.version = {1.1}


class RsaWithAes256CbcSha256(CipherSuite):
    """
    CipherSuite TLS_RSA_WITH_AES_256_CBC_SHA256       = { 0x00,0x3D };
    """

    def __init__(self):
        super().__init__()
        self.name = "TLS_RSA_WITH_AES_256_CBC_SHA256"
        self.key_exchange_type = "RSA"
        self.hash_type = "HMAC-SHA256"
        self.cipher_type = "Block"
        self.key_length = 32
        self.mac_key_length = 32
        self.value = 0x003D
        self.version = {1.1}


"""
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
"""


class DhDssWithDesCbcSha(CipherSuite):
    """
    CipherSuite TLS_DH_DSS_WITH_DES_CBC_SHA            = { 0x00,0x0C };
    """

    def __init__(self):
        super().__init__()
        self.name = "TLS_DH_DSS_WITH_DES_CBC_SHA"
        self.key_exchange_type = "DH_DSS"
        self.hash_type = "HMAC-SHA1"
        self.cipher_type = "Block"
        self.key_length = 8
        self.mac_key_length = 20
        self.value = 0x000C
        self.version = {1.2}


class DhDssWith3DesEdeCbcSha(CipherSuite):
    """
    CipherSuite TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA      = { 0x00,0x0D };
    """

    def __init__(self):
        super().__init__()
        self.name = "TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA"
        self.key_exchange_type = "DH_DSS"
        self.hash_type = "HMAC-SHA1"
        self.cipher_type = "Block"
        self.key_length = 24
        self.mac_key_length = 20
        self.value = 0x000D
        self.version = {1.1, 1.2}


class DhRsaWithDesCbcSha(CipherSuite):
    """
    CipherSuite TLS_DH_RSA_WITH_DES_CBC_SHA            = { 0x00,0x0F };
    """

    def __init__(self):
        super().__init__()
        self.name = "TLS_DH_RSA_WITH_DES_CBC_SHA"
        self.key_exchange_type = "DH_RSA"
        self.hash_type = "HMAC-SHA1"
        self.cipher_type = "Block"
        self.key_length = 8
        self.mac_key_length = 20
        self.value = 0x000F
        self.version = {1.2}


class DhRsaWith3DesEdeCbcSha(CipherSuite):
    """
    CipherSuite TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA      = { 0x00,0x10 };
    """

    def __init__(self):
        super().__init__()
        self.name = "TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA"
        self.key_exchange_type = "DH_RSA"
        self.hash_type = "HMAC-SHA1"
        self.cipher_type = "Block"
        self.key_length = 24
        self.mac_key_length = 20
        self.value = 0x0010
        self.version = {1.1, 1.2}


class DheDssWithDesCbcSha(CipherSuite):
    """
    CipherSuite TLS_DHE_DSS_WITH_DES_CBC_SHA           = { 0x00,0x12 };
    """

    def __init__(self):
        super().__init__()
        self.name = "TLS_DHE_DSS_WITH_DES_CBC_SHA"
        self.key_exchange_type = "DHE_DSS"
        self.hash_type = "HMAC-SHA1"
        self.cipher_type = "Block"
        self.key_length = 8
        self.mac_key_length = 20
        self.value = 0x0012
        self.version = {1.2}


class DheDssWith3DesEdeCbcSha(CipherSuite):
    """
    CipherSuite TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA     = { 0x00,0x13 };
    """

    def __init__(self):
        super().__init__()
        self.name = "TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA"
        self.key_exchange_type = "DHE_DSS"
        self.hash_type = "HMAC-SHA1"
        self.cipher_type = "Block"
        self.key_length = 24
        self.mac_key_length = 20
        self.value = 0x0013
        self.version = {1.1, 1.2}


class DheRsaWithDesCbcSha(CipherSuite):
    """
    CipherSuite TLS_DHE_RSA_WITH_DES_CBC_SHA           = { 0x00,0x15 };
    """

    def __init__(self):
        super().__init__()
        self.name = "TLS_DHE_RSA_WITH_DES_CBC_SHA"
        self.key_exchange_type = "DHE_DSS"
        self.hash_type = "HMAC-SHA1"
        self.cipher_type = "Block"
        self.key_length = 8
        self.mac_key_length = 20
        self.value = 0x0015
        self.version = {1.2}


class DheRsaWith3DesEdeCbcSha(CipherSuite):
    """
    CipherSuite TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA     = { 0x00,0x16 };
    """

    def __init__(self):
        super().__init__()
        self.name = "TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA"
        self.key_exchange_type = "DHE_RSA"
        self.hash_type = "HMAC-SHA1"
        self.cipher_type = "Block"
        self.key_length = 24
        self.mac_key_length = 20
        self.value = 0x0016
        self.version = {1.1, 1.2}


class DhDssWithAes128CbcSha(CipherSuite):
    """
    CipherSuite TLS_DH_DSS_WITH_AES_128_CBC_SHA       = { 0x00,0x30 };
    """

    def __init__(self):
        super().__init__()
        self.name = "TLS_DH_DSS_WITH_AES_128_CBC_SHA"
        self.key_exchange_type = "DH_DSS"
        self.hash_type = "HMAC-SHA1"
        self.cipher_type = "Block"
        self.key_length = 16
        self.mac_key_length = 20
        self.value = 0x0030
        self.version = {1.1, 1.2}


class DhRsaWithAes128CbcSha(CipherSuite):
    """
    CipherSuite TLS_DH_RSA_WITH_AES_128_CBC_SHA       = { 0x00,0x31 };
    """

    def __init__(self):
        super().__init__()
        self.name = "TLS_DH_RSA_WITH_AES_128_CBC_SHA"
        self.key_exchange_type = "DH_RSA"
        self.hash_type = "HMAC-SHA1"
        self.cipher_type = "Block"
        self.key_length = 16
        self.mac_key_length = 20
        self.value = 0x0031
        self.version = {1.1, 1.2}


class DheDssWithAes128CbcSha(CipherSuite):
    """
    CipherSuite TLS_DHE_DSS_WITH_AES_128_CBC_SHA      = { 0x00,0x32 };
    """

    def __init__(self):
        super().__init__()
        self.name = "TLS_DHE_DSS_WITH_AES_128_CBC_SHA"
        self.key_exchange_type = "DHE_DSS"
        self.hash_type = "HMAC-SHA1"
        self.cipher_type = "Block"
        self.key_length = 16
        self.mac_key_length = 20
        self.value = 0x0032
        self.version = {1.1, 1.2}


class DheRsaWithAes128CbcSha(CipherSuite):
    """
    CipherSuite TLS_DHE_RSA_WITH_AES_128_CBC_SHA      = { 0x00,0x33 };
    """

    def __init__(self):
        super().__init__()
        self.name = "TLS_DHE_RSA_WITH_AES_128_CBC_SHA"
        self.key_exchange_type = "DHE_RSA"
        self.hash_type = "HMAC-SHA1"
        self.cipher_type = "Block"
        self.key_length = 16
        self.mac_key_length = 20
        self.value = 0x0033
        self.version = {1.1, 1.2}


class DhDssWithAes256CbcSha(CipherSuite):
    """
    CipherSuite TLS_DH_DSS_WITH_AES_256_CBC_SHA       = { 0x00,0x36 };
    """

    def __init__(self):
        super().__init__()
        self.name = "TLS_DH_DSS_WITH_AES_256_CBC_SHA"
        self.key_exchange_type = "DH_DSS"
        self.hash_type = "HMAC-SHA1"
        self.cipher_type = "Block"
        self.key_length = 32
        self.mac_key_length = 20
        self.value = 0x0036
        self.version = {1.1, 1.2}


class DhRsaWithAes256CbcSha(CipherSuite):
    """
    CipherSuite TLS_DH_RSA_WITH_AES_256_CBC_SHA       = { 0x00,0x37 };
    """

    def __init__(self):
        super().__init__()
        self.name = "TLS_DH_RSA_WITH_AES_256_CBC_SHA"
        self.key_exchange_type = "DH_RSA"
        self.hash_type = "HMAC-SHA1"
        self.cipher_type = "Block"
        self.key_length = 32
        self.mac_key_length = 20
        self.value = 0x0037
        self.version = {1.1, 1.2}


class DheDssWithAes256CbcSha(CipherSuite):
    """
    CipherSuite TLS_DHE_DSS_WITH_AES_256_CBC_SHA      = { 0x00,0x38 };
    """

    def __init__(self):
        super().__init__()
        self.name = "TLS_DHE_DSS_WITH_AES_256_CBC_SHA"
        self.key_exchange_type = "DHE_DSS"
        self.hash_type = "HMAC-SHA1"
        self.cipher_type = "Block"
        self.key_length = 32
        self.mac_key_length = 20
        self.value = 0x0038
        self.version = {1.1, 1.2}


class DheRsaWithAes256CbcSha(CipherSuite):
    """
    CipherSuite TLS_DHE_RSA_WITH_AES_256_CBC_SHA      = { 0x00,0x39 };
    """

    def __init__(self):
        super().__init__()
        self.name = "TLS_DHE_RSA_WITH_AES_256_CBC_SHA"
        self.key_exchange_type = "DHE_RSA"
        self.hash_type = "HMAC-SHA1"
        self.cipher_type = "Block"
        self.key_length = 32
        self.mac_key_length = 20
        self.value = 0x0039
        self.version = {1.1, 1.2}


class DhDssWithAes128CbcSha256(CipherSuite):
    """
    CipherSuite TLS_DH_DSS_WITH_AES_128_CBC_SHA256    = { 0x00,0x3E };
    """

    def __init__(self):
        super().__init__()
        self.name = "TLS_DH_DSS_WITH_AES_128_CBC_SHA256"
        self.key_exchange_type = "DH_DSS"
        self.hash_type = "HMAC-SHA256"
        self.cipher_type = "Block"
        self.key_length = 16
        self.mac_key_length = 32
        self.value = 0x003E
        self.version = {1.1}


class DhRsaWithAes128CbcSha256(CipherSuite):
    """
    CipherSuite TLS_DH_RSA_WITH_AES_128_CBC_SHA256    = { 0x00,0x3F };
    """

    def __init__(self):
        super().__init__()
        self.name = "TLS_DH_RSA_WITH_AES_128_CBC_SHA256"
        self.key_exchange_type = "DH_RSA"
        self.hash_type = "HMAC-SHA256"
        self.cipher_type = "Block"
        self.key_length = 16
        self.mac_key_length = 32
        self.value = 0x003F
        self.version = {1.1}


class DheDssWithAes128CbcSha256(CipherSuite):
    """
    CipherSuite TLS_DHE_DSS_WITH_AES_128_CBC_SHA256   = { 0x00,0x40 };
    """

    def __init__(self):
        super().__init__()
        self.name = "TLS_DHE_DSS_WITH_AES_128_CBC_SHA256"
        self.key_exchange_type = "DHE_DSS"
        self.hash_type = "HMAC-SHA256"
        self.cipher_type = "Block"
        self.key_length = 16
        self.mac_key_length = 32
        self.value = 0x0040
        self.version = {1.1}


class DheRsaWithAes128CbcSha256(CipherSuite):
    """
    CipherSuite TLS_DHE_RSA_WITH_AES_128_CBC_SHA256   = { 0x00,0x67 };
    """

    def __init__(self):
        super().__init__()
        self.name = "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256"
        self.key_exchange_type = "DHE_RSA"
        self.hash_type = "HMAC-SHA256"
        self.cipher_type = "Block"
        self.key_length = 16
        self.mac_key_length = 32
        self.value = 0x0067
        self.version = {1.1}


class DhDssWithAes256CbcSha256(CipherSuite):
    """
    CipherSuite TLS_DH_DSS_WITH_AES_256_CBC_SHA256    = { 0x00,0x68 };
    """

    def __init__(self):
        super().__init__()
        self.name = "TLS_DH_DSS_WITH_AES_256_CBC_SHA256"
        self.key_exchange_type = "DH_DSS"
        self.hash_type = "HMAC-SHA256"
        self.cipher_type = "Block"
        self.key_length = 32
        self.mac_key_length = 32
        self.value = 0x0068
        self.version = {1.1}


class DhRsaWithAes256CbcSha256(CipherSuite):
    """
    CipherSuite TLS_DH_RSA_WITH_AES_256_CBC_SHA256    = { 0x00,0x69 };
    """

    def __init__(self):
        super().__init__()
        self.name = "TLS_DH_RSA_WITH_AES_256_CBC_SHA256"
        self.key_exchange_type = "DH_RSA"
        self.hash_type = "HMAC-SHA256"
        self.cipher_type = "Block"
        self.key_length = 32
        self.mac_key_length = 32
        self.value = 0x0069
        self.version = {1.1}


class DheDssWithAes256CbcSha256(CipherSuite):
    """
    CipherSuite TLS_DHE_DSS_WITH_AES_256_CBC_SHA256   = { 0x00,0x6A };
    """

    def __init__(self):
        super().__init__()
        self.name = "TLS_DHE_DSS_WITH_AES_256_CBC_SHA256"
        self.key_exchange_type = "DHE_DSS"
        self.hash_type = "HMAC-SHA256"
        self.cipher_type = "Block"
        self.key_length = 32
        self.mac_key_length = 32
        self.value = 0x006A
        self.version = {1.1}


class DheRsaWithAes256CbcSha256(CipherSuite):
    """
    CipherSuite TLS_DHE_RSA_WITH_AES_256_CBC_SHA256   = { 0x00,0x6B };
    """

    def __init__(self):
        super().__init__()
        self.name = "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256"
        self.key_exchange_type = "DHE_RSA"
        self.hash_type = "HMAC-SHA256"
        self.cipher_type = "Block"
        self.key_length = 32
        self.mac_key_length = 32
        self.value = 0x006B
        self.version = {1.1}


"""
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
"""


class DhAnonWithRc4128Md5(CipherSuite):
    """
    CipherSuite TLS_DH_anon_WITH_RC4_128_MD5          = { 0x00,0x18 };
    """

    def __init__(self):
        super().__init__()
        self.name = "TLS_DH_anon_WITH_RC4_128_MD5"
        self.key_exchange_type = "DH_anon"
        self.hash_type = "HMAC-MD5"
        self.cipher_type = "Stream"
        self.key_length = 16
        self.mac_key_length = 16
        self.value = 0x0018
        self.version = {1.1, 1.2}


class DhAnonWithDesCbcSha(CipherSuite):
    """
    CipherSuite TLS_DH_anon_WITH_DES_CBC_SHA           = { 0x00,0x1A };
    """

    def __init__(self):
        super().__init__()
        self.name = "TLS_DH_anon_WITH_DES_CBC_SHA"
        self.key_exchange_type = "DH_anon"
        self.hash_type = "HMAC-SHA1"
        self.cipher_type = "Block"
        self.key_length = 8
        self.mac_key_length = 20
        self.value = 0x001A
        self.version = {1.2}


class DhAnonWith3DesEdeCbcSha(CipherSuite):
    """
    CipherSuite TLS_DH_anon_WITH_3DES_EDE_CBC_SHA     = { 0x00,0x1B };
    """

    def __init__(self):
        super().__init__()
        self.name = "TLS_DH_anon_WITH_3DES_EDE_CBC_SHA"
        self.key_exchange_type = "DH_anon"
        self.hash_type = "HMAC-SHA1"
        self.cipher_type = "Block"
        self.key_length = 24
        self.mac_key_length = 20
        self.value = 0x001B
        self.version = {1.1, 1.2}


class DhAnonWithAes128CbcSha(CipherSuite):
    """
      CipherSuite TLS_DH_anon_WITH_AES_128_CBC_SHA      = { 0x00,0x34 };
    """

    def __init__(self):
        super().__init__()
        self.name = "TLS_DH_anon_WITH_AES_128_CBC_SHA"
        self.key_exchange_type = "DH_anon"
        self.hash_type = "HMAC-SHA1"
        self.cipher_type = "Block"
        self.key_length = 16
        self.mac_key_length = 20
        self.value = 0x0034
        self.version = {1.1, 1.2}


class DhAnonWithAes256CbcSha(CipherSuite):
    """
      CipherSuite TLS_DH_anon_WITH_AES_256_CBC_SHA      = { 0x00,0x3A };
    """

    def __init__(self):
        super().__init__()
        self.name = "TLS_DH_anon_WITH_AES_256_CBC_SHA"
        self.key_exchange_type = "DH_anon"
        self.hash_type = "HMAC-SHA1"
        self.cipher_type = "Block"
        self.key_length = 32
        self.mac_key_length = 20
        self.value = 0x003A
        self.version = {1.1, 1.2}


class DhAnonWithAes128CbcSha256(CipherSuite):
    """
    CipherSuite TLS_DH_anon_WITH_AES_128_CBC_SHA256   = { 0x00,0x6C };
    """

    def __init__(self):
        super().__init__()
        self.name = "TLS_DH_anon_WITH_AES_128_CBC_SHA256"
        self.key_exchange_type = "DH_anon"
        self.hash_type = "HMAC-SHA256"
        self.cipher_type = "Block"
        self.key_length = 16
        self.mac_key_length = 32
        self.value = 0x006C
        self.version = {1.1}


class DhAnonWithAes256CbcSha256(CipherSuite):
    """
    CipherSuite TLS_DH_anon_WITH_AES_256_CBC_SHA256   = { 0x00,0x6D };
    """

    def __init__(self):
        super().__init__()
        self.name = "TLS_DH_anon_WITH_AES_256_CBC_SHA256"
        self.key_exchange_type = "DH_anon"
        self.hash_type = "HMAC-SHA256"
        self.cipher_type = "Block"
        self.key_length = 32
        self.mac_key_length = 32
        self.value = 0x006D
        self.version = {1.1}


"""
Note that using non-anonymous key exchange without actually verifying
the key exchange is essentially equivalent to anonymous key exchange,
and the same precautions apply.  While non-anonymous key exchange
will generally involve a higher computational and communicational
cost than anonymous key exchange, it may be in the interest of
interoperability not to disable non-anonymous key exchange when the
application layer is allowing anonymous key exchange.

Note: The cipher suite values { 0x00, 0x1C } and { 0x00, 0x1D } are
reserved to avoid collision with Fortezza-based cipher suites in SSL 3.
"""


"""
A symmetric cipher suite defines the pair of the AEAD algorithm and
hash algorithm to be used with HKDF.  Cipher suite names follow the
naming convention:

    CipherSuite TLS_AEAD_HASH = VALUE;
    
    +-----------+------------------------------------------------+
    | Component | Contents                                       |
    +-----------+------------------------------------------------+
    | TLS       | The string "TLS"                               |
    |           |                                                |
    | AEAD      | The AEAD algorithm used for record protection  |
    |           |                                                |
    | HASH      | The hash algorithm used with HKDF              |
    |           |                                                |
    | VALUE     | The two-byte ID assigned for this cipher suite |
    +-----------+------------------------------------------------+

This specification defines the following cipher suites for use with
TLS 1.3.

    +------------------------------+-------------+
    | Description                  | Value       |
    +------------------------------+-------------+
    | TLS_AES_128_GCM_SHA256       | {0x13,0x01} |
    |                              |             |
    | TLS_AES_256_GCM_SHA384       | {0x13,0x02} |
    |                              |             |
    | TLS_CHACHA20_POLY1305_SHA256 | {0x13,0x03} |
    |                              |             |
    | TLS_AES_128_CCM_SHA256       | {0x13,0x04} |
    |                              |             |
    | TLS_AES_128_CCM_8_SHA256     | {0x13,0x05} |
    +------------------------------+-------------+
    
The corresponding AEAD algorithms AEAD_AES_128_GCM, AEAD_AES_256_GCM,
and AEAD_AES_128_CCM are defined in [RFC5116](https://datatracker.ietf.org/doc/html/rfc5116).
AEAD_CHACHA20_POLY1305 is defined in [RFC8439](https://datatracker.ietf.org/doc/html/rfc8439).
AEAD_AES_128_CCM_8 is defined in [RFC6655](https://datatracker.ietf.org/doc/html/rfc6655).
The corresponding hash algorithms are defined in [SHS].

[SHS]     Dang, Q., "Secure Hash Standard (SHS)", National Institute
          of Standards and Technology report,
          DOI 10.6028/NIST.FIPS.180-4, August 2015.

Although TLS 1.3 uses the same cipher suite space as previous
versions of TLS, TLS 1.3 cipher suites are defined differently, only
specifying the symmetric ciphers, and cannot be used for TLS 1.2.
Similarly, cipher suites for TLS 1.2 and lower cannot be used with
TLS 1.3.

[CCM]     Dworkin, M., "NIST Special Publication 800-38C: The CCM
          Mode for Authentication and Confidentiality", U.S.
          National Institute of Standards and Technology,
          <http://csrc.nist.gov/publications/nistpubs/800-38C/
          SP800-38C.pdf>.
          
[GCM]     Dworkin, M., "NIST Special Publication 800-38D:
          Recommendation for Block Cipher Modes of Operation:
          Galois/Counter Mode (GCM) and GMAC.", U.S. National
          Institute of Standards and Technology, November 2007,
          <http://csrc.nist.gov/publications/nistpubs/800-38D/
          SP-800-38D.pdf>.

[MV04]    McGrew, D. and J. Viega, "The Security and Performance of
          the Galois/Counter Mode (GCM)", Proceedings of
          INDOCRYPT '04, December 2004,
          <http://eprint.iacr.org/2004/193>.

[J02]     Jonsson, J., "On the Security of CTR + CBC-MAC",
          Proceedings of the 9th Annual Workshop on Selected Areas
          on Cryptography, 2002, <http://csrc.nist.gov/groups/ST/
          toolkit/BCM/documents/proposedmodes/ccm/ccm-ad1.pdf>.
"""


class Aes128GcmSha256(CipherSuite):
    """
    CipherSuite TLS_AES_128_GCM_SHA256   = { 0x13,0x01 };

    The AEAD_AES_128_GCM authenticated encryption algorithm works as
    specified in [GCM], using AES-128 as the block cipher, by providing
    the key, nonce, and plaintext, and associated data to that mode of
    operation.  An authentication tag with a length of 16 octets (128
    bits) is used.  The AEAD_AES_128_GCM ciphertext is formed by
    appending the authentication tag provided as an output to the GCM
    encryption operation to the ciphertext that is output by that
    operation.  Test cases are provided in the appendix of [GCM].  The
    input and output lengths are as follows:

        K_LEN is 16 octets,

        P_MAX is 2^36 - 31 octets,

        A_MAX is 2^61 - 1 octets,

        N_MIN and N_MAX are both 12 octets, and

        C_MAX is 2^36 - 15 octets.

    An AEAD_AES_128_GCM ciphertext is exactly 16 octets longer than its
    corresponding plaintext.

    A security analysis of GCM is available in [MV04].
    """

    def __init__(self):
        super().__init__()
        self.name = "TLS_AES_128_GCM_SHA256"
        self.key_exchange_type = "AES"
        self.hash_type = "HMAC-SHA256"
        self.cipher_type = "Block"
        self.key_length = 16
        self.mac_key_length = 32
        self.value = 0x1301
        self.version = {1.3}


class Aes256GcmSha384(CipherSuite):
    """
    CipherSuite TLS_AES_256_GCM_SHA384   = { 0x13,0x02 };

    The AEAD_AES_128_CCM authenticated encryption algorithm works as
    specified in [CCM], using AES-128 as the block cipher, by providing
    the key, nonce, associated data, and plaintext to that mode of
    operation.  The formatting and counter generation function are as
    specified in Appendix A of that reference, and the values of the
    parameters identified in that appendix are as follows:

        the nonce length n is 12,

        the tag length t is 16, and

        the value of q is 3.

    An authentication tag with a length of 16 octets (128 bits) is used.
    The AEAD_AES_128_CCM ciphertext is formed by appending the
    authentication tag provided as an output to the CCM encryption
    operation to the ciphertext that is output by that operation.  Test
    cases are provided in [CCM].  The input and output lengths are as
    follows:

        K_LEN is 16 octets,

        P_MAX is 2^24 - 1 octets,

        A_MAX is 2^64 - 1 octets,

        N_MIN and N_MAX are both 12 octets, and

        C_MAX is 2^24 + 15 octets.

    An AEAD_AES_128_CCM ciphertext is exactly 16 octets longer than its
    corresponding plaintext.

    A security analysis of AES CCM is available in [J02].
    """

    def __init__(self):
        super().__init__()
        self.name = "TLS_AES_256_GCM_SHA384"
        self.key_exchange_type = "AES"
        self.hash_type = "HMAC-SHA384"
        self.cipher_type = "Block"
        self.key_length = 32
        self.mac_key_length = 48
        self.value = 0x1302
        self.version = {1.3}


class ChaCha20Poly1305Sha256(CipherSuite):
    """
    CipherSuite TLS_CHACHA20_POLY1305_SHA256   = { 0x13,0x03 };
    """

    def __init__(self):
        super().__init__()
        self.name = "TLS_CHACHA20_POLY1305_SHA256"
        self.key_exchange_type = "AEAD"
        self.hash_type = "HMAC-SHA256"
        self.cipher_type = "Block"
        self.key_length = 32
        self.mac_key_length = None
        self.value = 0x1303
        self.version = {1.3}


class Aes128CcmSha256(CipherSuite):
    """
    CipherSuite TLS_AES_128_CCM_SHA256   = { 0x13,0x04 };

    The AEAD_AES_128_CCM authenticated encryption algorithm works as
    specified in [CCM], using AES-128 as the block cipher, by providing
    the key, nonce, associated data, and plaintext to that mode of
    operation.  The formatting and counter generation function are as
    specified in Appendix A of that reference, and the values of the
    parameters identified in that appendix are as follows:

        the nonce length n is 12,

        the tag length t is 16, and

        the value of q is 3.

    An authentication tag with a length of 16 octets (128 bits) is used.
    The AEAD_AES_128_CCM ciphertext is formed by appending the
    authentication tag provided as an output to the CCM encryption
    operation to the ciphertext that is output by that operation.  Test
    cases are provided in [CCM].  The input and output lengths are as
    follows:

        K_LEN is 16 octets,

        P_MAX is 2^24 - 1 octets,

        A_MAX is 2^64 - 1 octets,

        N_MIN and N_MAX are both 12 octets, and

        C_MAX is 2^24 + 15 octets.

    An AEAD_AES_128_CCM ciphertext is exactly 16 octets longer than its
    corresponding plaintext.

    A security analysis of AES CCM is available in [J02].
    """

    def __init__(self):
        super().__init__()
        self.name = "TLS_AES_128_CCM_SHA256"
        self.key_exchange_type = "AES"
        self.hash_type = "HMAC-SHA256"
        self.cipher_type = "Block"
        self.key_length = 16
        self.mac_key_length = 32
        self.value = 0x1304
        self.version = {1.3}


class Aes128Ccm8Sha256(CipherSuite):
    """
    CipherSuite TLS_AES_128_CCM_8_SHA256   = { 0x13,0x05 };
    """

    def __init__(self):
        super().__init__()
        self.name = "TLS_AES_128_CCM_8_SHA256"
        self.key_exchange_type = "AES"
        self.hash_type = "HMAC-SHA256"
        self.cipher_type = "Block"
        self.key_length = 16
        self.mac_key_length = 32
        self.value = 0x1305
        self.version = {1.3}


# AEAD_AES_256_CCM
