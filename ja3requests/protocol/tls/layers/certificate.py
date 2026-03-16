"""TLS Certificate handshake message layer."""

import struct
from ja3requests.protocol.tls.layers import HandShake


class Certificate(HandShake):
    """
    struct {
        ASN.1Cert certificate_list<0..2^24-1>;
    } Certificate;

    struct {
        opaque ASN.1Cert<1..2^24-1>;
    } ASN.1Cert;
    """

    def __init__(self):
        super().__init__()
        self._certificate_list = None

    @property
    def handshake_type(self) -> bytes:
        """
        HandshakeType certificate(11)
        :return:
        """
        return struct.pack("B", 11)

    def parse(self, data: bytes):
        """
        Parse certificate message from received data
        :param data: Raw certificate message
        """
        # Skip TLS record header (5 bytes)
        data = data[5:]

        # Skip handshake header (4 bytes)
        data = data[4:]

        # Parse certificate list length (3 bytes)
        cert_list_length = struct.unpack("!I", b"\x00" + data[:3])[0]
        data = data[3:]

        # Parse certificate list
        self._certificate_list = data[:cert_list_length]

    @property
    def certificate_list(self) -> bytes:
        """Return the parsed certificate list."""
        return self._certificate_list
