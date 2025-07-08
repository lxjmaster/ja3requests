import struct
import hashlib
from ja3requests.protocol.tls.layers import HandShake


class Finished(HandShake):
    """
    struct {
        opaque verify_data[12];
    } Finished;

    verify_data
        PRF(master_secret, finished_label, Hash(handshake_messages))[0..11];
    """

    def __init__(
        self,
        master_secret: bytes = None,
        client_random: bytes = None,
        server_random: bytes = None,
    ):
        super().__init__()
        self._master_secret = master_secret
        self._client_random = client_random
        self._server_random = server_random
        self._verify_data = None

    @property
    def handshake_type(self) -> bytes:
        """
        HandshakeType finished(20)
        :return:
        """
        return struct.pack("B", 20)

    def content(self) -> bytes:
        """
        Generate finished message content
        :return: Finished message content
        """
        if (
            not self._master_secret
            or not self._client_random
            or not self._server_random
        ):
            # For parsing received Finished message
            return self._verify_data

        # TODO: Implement proper PRF and hash calculation
        # For now, generate a placeholder verify_data
        self._verify_data = struct.pack("!12B", *[0] * 12)
        return self._verify_data

    def parse(self, data: bytes):
        """
        Parse finished message from received data
        :param data: Raw finished message
        """
        # Skip TLS record header (5 bytes)
        data = data[5:]

        # Skip handshake header (4 bytes)
        data = data[4:]

        # Parse verify_data (12 bytes)
        self._verify_data = data[:12]

    @property
    def verify_data(self) -> bytes:
        return self._verify_data
