import struct
from ja3requests.protocol.tls.layers import HandShake


class ServerKeyExchange(HandShake):
    """
    struct {
        select (KeyExchangeAlgorithm) {
            case dh_anon:
                ServerDHParams params;
            case dhe_rsa:
            case dhe_dss:
                ServerDHParams params;
                digitally-signed struct {
                    opaque client_random[32];
                    opaque server_random[32];
                    ServerDHParams params;
                } signed_params;
            case rsa:
            case dh_rsa:
            case dh_dss:
                struct {};
            case ec_diffie_hellman:
                ServerECDHParams params;
                Signature signed_params;
            case ecdhe_rsa:
            case ecdhe_ecdsa:
                ServerECDHParams params;
                digitally-signed struct {
                    opaque client_random[32];
                    opaque server_random[32];
                    ServerECDHParams params;
                } signed_params;
        };
    } ServerKeyExchange;

    struct {
        opaque dh_p<1..2^16-1>;
        opaque dh_g<1..2^16-1>;
        opaque dh_Ys<1..2^16-1>;
    } ServerDHParams;
    """

    def __init__(self):
        super().__init__()
        self._params = None
        self._signed_params = None

    @property
    def handshake_type(self) -> bytes:
        """
        HandshakeType server_key_exchange(12)
        :return:
        """
        return struct.pack("B", 12)

    def parse(self, data: bytes):
        """
        Parse server key exchange message from received data
        :param data: Raw server key exchange message
        """
        # Skip TLS record header (5 bytes)
        data = data[5:]

        # Skip handshake header (4 bytes)
        data = data[4:]

        # Parse DH parameters
        # Parse dh_p length and value
        dh_p_length = struct.unpack("!H", data[:2])[0]
        data = data[2:]
        dh_p = data[:dh_p_length]
        data = data[dh_p_length:]

        # Parse dh_g length and value
        dh_g_length = struct.unpack("!H", data[:2])[0]
        data = data[2:]
        dh_g = data[:dh_g_length]
        data = data[dh_g_length:]

        # Parse dh_Ys length and value
        dh_Ys_length = struct.unpack("!H", data[:2])[0]
        data = data[2:]
        dh_Ys = data[:dh_Ys_length]
        data = data[dh_Ys_length:]

        # Store DH parameters
        self._params = {'dh_p': dh_p, 'dh_g': dh_g, 'dh_Ys': dh_Ys}

        # Parse signed parameters if present
        if len(data) > 0:
            self._signed_params = data

    @property
    def params(self) -> dict:
        return self._params

    @property
    def signed_params(self) -> bytes:
        return self._signed_params
