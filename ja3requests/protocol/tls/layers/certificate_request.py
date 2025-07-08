import struct
from ja3requests.protocol.tls.layers import HandShake


class CertificateRequest(HandShake):
    """
    struct {
        ClientCertificateType certificate_types<1..2^8-1>;
        DistinguishedName certificate_authorities<0..2^16-1>;
    } CertificateRequest;

    enum {
        rsa_sign(1), dss_sign(2), rsa_fixed_dh(3), dss_fixed_dh(4),
        rsa_ephemeral_dh_RESERVED(5), dss_ephemeral_dh_RESERVED(6),
        fortezza_dms_RESERVED(20), (255)
    } ClientCertificateType;

    opaque DistinguishedName<1..2^16-1>;
    """

    def __init__(self):
        super().__init__()
        self._certificate_types = None
        self._certificate_authorities = None

    @property
    def handshake_type(self) -> bytes:
        """
        HandshakeType certificate_request(13)
        :return:
        """
        return struct.pack("B", 13)

    def parse(self, data: bytes):
        """
        Parse certificate request message from received data
        :param data: Raw certificate request message
        """
        # Skip TLS record header (5 bytes)
        data = data[5:]

        # Skip handshake header (4 bytes)
        data = data[4:]

        # Parse certificate types length and types
        cert_types_length = data[0]
        data = data[1:]
        self._certificate_types = data[:cert_types_length]
        data = data[cert_types_length:]

        # Parse certificate authorities length and authorities
        if len(data) > 0:
            auth_length = struct.unpack("!H", data[:2])[0]
            data = data[2:]
            self._certificate_authorities = data[:auth_length]

    @property
    def certificate_types(self) -> bytes:
        return self._certificate_types

    @property
    def certificate_authorities(self) -> bytes:
        return self._certificate_authorities
