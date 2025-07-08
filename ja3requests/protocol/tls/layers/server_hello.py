import struct
from ja3requests.protocol.tls.layers import HandShake


class ServerHello(HandShake):
    """
    struct {
        ProtocolVersion server_version;
        Random random;
        SessionID session_id;
        CipherSuite cipher_suite;
        CompressionMethod compression_method;
        select (extensions_present) {
            case false:
                struct {};
            case true:
                Extension extensions<0..2^16-1>;
        };
    } ServerHello;
    """

    def __init__(self):
        super().__init__()
        self._version = None
        self._random = None
        self._session_id = None
        self._cipher_suite = None
        self._compression_method = None
        self._extensions = None

    @property
    def handshake_type(self) -> bytes:
        """
        HandshakeType server_hello(2)
        :return:
        """
        return struct.pack("B", 2)

    def parse(self, data: bytes):
        """
        Parse server hello message from received data
        :param data: Raw server hello message
        """

        print(data)
        # Skip TLS record header (5 bytes)
        data = data[5:]

        # Skip handshake header (4 bytes)
        data = data[4:]

        # Parse server version (2 bytes)
        self._version = data[:2]
        data = data[2:]

        # Parse random (32 bytes)
        self._random = data[:32]
        data = data[32:]

        # Parse session ID length and session ID
        session_id_length = data[0]
        data = data[1:]
        if session_id_length > 0:
            self._session_id = data[:session_id_length]
            data = data[session_id_length:]

        # Parse cipher suite (2 bytes)
        self._cipher_suite = data[:2]
        data = data[2:]

        # Parse compression method (1 byte)
        self._compression_method = data[0]
        data = data[1:]

        # Parse extensions if present
        if len(data) > 0:
            self._extensions = data

    @property
    def version(self) -> bytes:
        return self._version

    @property
    def random(self) -> bytes:
        return self._random

    @property
    def session_id(self) -> bytes:
        return self._session_id

    @property
    def cipher_suite(self) -> bytes:
        return self._cipher_suite

    @property
    def compression_method(self) -> bytes:
        return struct.pack("B", self._compression_method)

    @property
    def extensions(self) -> bytes:
        return self._extensions
