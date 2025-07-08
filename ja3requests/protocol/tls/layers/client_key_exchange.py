import struct
from ja3requests.protocol.tls.layers import HandShake


class ClientKeyExchange(HandShake):
    """
    struct {
        select (KeyExchangeAlgorithm) {
            case rsa:
                EncryptedPreMasterSecret;
            case dhe_dss:
            case dhe_rsa:
            case dh_dss:
            case dh_rsa:
            case dh_anon:
                ClientDiffieHellmanPublic;
            case ec_diffie_hellman:
                ClientECDiffieHellmanPublic;
        } exchange_keys;
    } ClientKeyExchange;

    struct {
        ProtocolVersion client_version;
        opaque random[46];
    } PreMasterSecret;

    struct {
        public-key-encrypted PreMasterSecret pre_master_secret;
    } EncryptedPreMasterSecret;

    struct {
        opaque dh_Yc<1..2^16-1>;
    } ClientDiffieHellmanPublic;
    """

    def __init__(self, cipher_suite: bytes):
        super().__init__()
        self._cipher_suite = cipher_suite
        self._exchange_keys = None

    @property
    def handshake_type(self) -> bytes:
        """
        HandshakeType client_key_exchange(16)
        :return:
        """
        return struct.pack("B", 16)

    def content(self) -> bytes:
        """
        Generate client key exchange content based on cipher suite
        :return: Client key exchange content
        """
        # For RSA key exchange
        if self._cipher_suite in [
            b'\x00\x2f',
            b'\x00\x35',
            b'\x00\x3c',
            b'\x00\x3d',
        ]:  # RSA cipher suites
            # Generate PreMasterSecret
            client_version = struct.pack("!H", 0x0303)  # TLS 1.2
            random = struct.pack("!46B", *[0] * 46)  # 46 bytes of random data
            pre_master_secret = client_version + random

            # TODO: Encrypt PreMasterSecret with server's public key
            # For now, just return the PreMasterSecret
            self._exchange_keys = pre_master_secret
            return self._exchange_keys

        # For DHE key exchange
        elif self._cipher_suite in [
            b'\x00\x33',
            b'\x00\x39',
            b'\x00\x67',
            b'\x00\x6b',
        ]:  # DHE cipher suites
            # Generate client's DH public key
            # TODO: Implement proper DH key generation
            dh_Yc = struct.pack("!H", 0)  # Placeholder for DH public key
            self._exchange_keys = dh_Yc
            return self._exchange_keys

        else:
            raise ValueError(f"Unsupported cipher suite: {self._cipher_suite}")

    @property
    def exchange_keys(self) -> bytes:
        return self._exchange_keys
