import struct
from ja3requests.protocol.tls.layers import HandShake


class ServerHelloDone(HandShake):
    """
    struct {} ServerHelloDone;
    """

    def __init__(self):
        super().__init__()

    @property
    def handshake_type(self) -> bytes:
        """
        HandshakeType server_hello_done(14)
        :return:
        """
        return struct.pack("B", 14)

    def parse(self, data: bytes):
        """
        Parse server hello done message from received data
        :param data: Raw server hello done message
        """
        # Skip TLS record header (5 bytes)
        data = data[5:]

        # Skip handshake header (4 bytes)
        data = data[4:]

        # ServerHelloDone has no body
