import struct
from ja3requests.protocol.tls.layers import HandShake


class CertificateVerify(HandShake):
    """
    struct {
        digitally-signed struct {
            opaque handshake_messages[handshake_messages.length];
        };
    } CertificateVerify;
    """

    def __init__(self):
        super().__init__()
        self._signature = None

    @property
    def handshake_type(self) -> bytes:
        """
        HandshakeType certificate_verify(15)
        :return:
        """
        return struct.pack("B", 15)

    def content(self) -> bytes:
        """
        Generate certificate verify content
        :return: Certificate verify content
        """
        # TODO: Implement proper signature generation
        # For now, return a placeholder signature
        self._signature = struct.pack("!H", 0)  # Placeholder for signature
        return self._signature

    @property
    def signature(self) -> bytes:
        return self._signature
