"""
ja3requests.protocol.tls.extensions
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

This package contains all TLS extensions supported by ja3requests.

struct {
    ExtensionType extension_type;
    opaque extension_data<0..2^16-1>;
} Extension;

enum {
    signature_algorithms(13), (65535)
} ExtensionType;
"""

import struct
from abc import ABC, abstractmethod


class Extension(ABC):
    """Abstract base class for TLS extensions.

    Each extension encodes itself into the TLS wire format:
        2 bytes extension_type + 2 bytes length + extension_data
    """

    extension_type = None
    extension_data = b''

    @abstractmethod
    def encode(self):
        """Encode the extension data (without type and length header)."""
        raise NotImplementedError("encode method must be implemented by subclass.")

    def to_bytes(self):
        """Encode the full extension with type and length header."""
        data = self.encode()
        return struct.pack("!HH", self.extension_type, len(data)) + data

    def __repr__(self):
        return f"<{self.__class__.__name__} type=0x{self.extension_type:04X}>"


class SNIExtension(Extension):
    """Server Name Indication (SNI) extension (type 0x0000).

    Allows the client to indicate which hostname it is connecting to,
    enabling the server to present the appropriate certificate.
    """

    extension_type = 0x0000

    def __init__(self, server_name):
        self.server_name = server_name

    def encode(self):
        # Convert internationalized domain names to Punycode (RFC 5890)
        name = self.server_name
        try:
            name.encode('ascii')
        except UnicodeEncodeError:
            # Non-ASCII domain: convert to IDNA/Punycode
            name = name.encode('idna').decode('ascii')

        name_bytes = name.encode('ascii')
        # ServerNameList: 2 bytes list length
        #   ServerName: 1 byte name type (0 = hostname) + 2 bytes name length + name
        sni_entry = struct.pack("!BH", 0, len(name_bytes)) + name_bytes
        return struct.pack("!H", len(sni_entry)) + sni_entry


class SupportedGroupsExtension(Extension):
    """Supported Groups (Elliptic Curves) extension (type 0x000A).

    Indicates the named groups (elliptic curves) the client supports
    for key exchange.

    Common group IDs:
        23 = secp256r1, 24 = secp384r1, 25 = secp521r1,
        29 = x25519, 30 = x448
    """

    extension_type = 0x000A

    def __init__(self, groups):
        self.groups = groups

    def encode(self):
        groups_bytes = b"".join(struct.pack("!H", g) for g in self.groups)
        return struct.pack("!H", len(groups_bytes)) + groups_bytes


class SignatureAlgorithmsExtension(Extension):
    """Signature Algorithms extension (type 0x000D).

    Indicates which signature/hash algorithm pairs the client supports
    for verifying server certificates and key exchange signatures.

    Common values (HashAlgorithm << 8 | SignatureAlgorithm):
        0x0401 = RSA PKCS1 SHA256, 0x0501 = RSA PKCS1 SHA384,
        0x0601 = RSA PKCS1 SHA512, 0x0403 = ECDSA SHA256,
        0x0804 = RSA PSS SHA256
    """

    extension_type = 0x000D

    def __init__(self, algorithms):
        self.algorithms = algorithms

    def encode(self):
        algs_bytes = b"".join(struct.pack("!H", a) for a in self.algorithms)
        return struct.pack("!H", len(algs_bytes)) + algs_bytes


class ALPNExtension(Extension):
    """Application-Layer Protocol Negotiation (ALPN) extension (type 0x0010).

    Allows the client to indicate supported application protocols
    (e.g., 'h2', 'http/1.1') during the TLS handshake.
    """

    extension_type = 0x0010

    def __init__(self, protocols):
        self.protocols = protocols

    def encode(self):
        protocols_data = b""
        for protocol in self.protocols:
            proto_bytes = protocol.encode('utf-8')
            protocols_data += struct.pack("!B", len(proto_bytes)) + proto_bytes
        return struct.pack("!H", len(protocols_data)) + protocols_data


class ECPointFormatsExtension(Extension):
    """EC Point Formats extension (type 0x000B).

    Indicates the point formats the client can parse for elliptic curve points.

    Format IDs: 0 = uncompressed, 1 = ansiX962_compressed_prime,
                2 = ansiX962_compressed_char2
    """

    extension_type = 0x000B

    def __init__(self, formats=None):
        self.formats = formats or [0]  # uncompressed by default

    def encode(self):
        formats_bytes = b"".join(struct.pack("!B", f) for f in self.formats)
        return struct.pack("!B", len(formats_bytes)) + formats_bytes


class SessionTicketExtension(Extension):
    """Session Ticket extension (type 0x0023).

    Used for TLS session resumption without server-side state.
    An empty extension indicates the client supports session tickets
    but does not have one to offer.
    """

    extension_type = 0x0023

    def __init__(self, ticket=None):
        self.ticket = ticket or b""

    def encode(self):
        return self.ticket


class ExtendedMasterSecretExtension(Extension):
    """Extended Master Secret extension (type 0x0017).

    Strengthens the TLS master secret computation to bind it to the
    full handshake transcript, mitigating certain man-in-the-middle attacks.
    (RFC 7627)
    """

    extension_type = 0x0017

    def encode(self):
        return b""


class RenegotiationInfoExtension(Extension):
    """Renegotiation Info extension (type 0xFF01).

    Indicates support for secure renegotiation.
    For initial handshakes, the renegotiated_connection field is empty.
    (RFC 5746)
    """

    extension_type = 0xFF01

    def __init__(self, renegotiated_connection=None):
        self.renegotiated_connection = renegotiated_connection or b""

    def encode(self):
        return struct.pack("!B", len(self.renegotiated_connection)) + self.renegotiated_connection


class StatusRequestExtension(Extension):
    """Certificate Status Request (OCSP Stapling) extension (type 0x0005).

    Requests the server to provide an OCSP response during the handshake
    to prove its certificate has not been revoked. (RFC 6066)
    """

    extension_type = 0x0005

    def encode(self):
        # status_type = ocsp(1), responder_id_list = empty, request_extensions = empty
        return struct.pack("!BHH", 1, 0, 0)


class SupportedVersionsExtension(Extension):
    """Supported Versions extension (type 0x002B).

    Required for TLS 1.3. Indicates which TLS versions the client supports.
    In TLS 1.3, the client_version field in ClientHello is set to 0x0303 (TLS 1.2)
    for compatibility, and the actual supported versions are listed here.
    (RFC 8446 Section 4.2.1)
    """

    extension_type = 0x002B

    def __init__(self, versions=None):
        # Default: support TLS 1.3 and TLS 1.2
        self.versions = versions or [0x0304, 0x0303]

    def encode(self):
        versions_bytes = b"".join(struct.pack("!H", v) for v in self.versions)
        return struct.pack("B", len(versions_bytes)) + versions_bytes


class KeyShareExtension(Extension):
    """Key Share extension (type 0x0033).

    Carries the client's ECDHE public key(s) in the ClientHello,
    enabling 1-RTT handshake in TLS 1.3.
    (RFC 8446 Section 4.2.8)

    Named group IDs: 0x001D = x25519, 0x0017 = secp256r1
    """

    extension_type = 0x0033

    def __init__(self, key_shares=None):
        """
        :param key_shares: List of (group_id, public_key_bytes) tuples.
        """
        self.key_shares = key_shares or []

    def encode(self):
        entries = b""
        for group_id, key_bytes in self.key_shares:
            entries += struct.pack("!HH", group_id, len(key_bytes)) + key_bytes
        return struct.pack("!H", len(entries)) + entries


class PSKKeyExchangeModesExtension(Extension):
    """PSK Key Exchange Modes extension (type 0x002D).

    Required when offering PSK. Indicates which PSK key exchange modes
    the client supports.
    (RFC 8446 Section 4.2.9)

    Modes: 0 = psk_ke, 1 = psk_dhe_ke
    """

    extension_type = 0x002D

    def __init__(self, modes=None):
        self.modes = modes or [1]  # psk_dhe_ke by default

    def encode(self):
        modes_bytes = b"".join(struct.pack("B", m) for m in self.modes)
        return struct.pack("B", len(modes_bytes)) + modes_bytes
