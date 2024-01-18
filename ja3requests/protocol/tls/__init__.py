import struct
from ja3requests.protocol.tls.layers import HandShake
from ja3requests.protocol.tls.layers.client_hello import ClientHello


class TLS:

    def __init__(self, conn):

        # TODO: cipher suites, extensions
        self._tls_version = None
        self._body = None
        self.conn = conn

    @property
    def tls_version(self) -> bytes:
        tls_version = self._tls_version
        if not tls_version:
            tls_version = struct.pack("I", 771)[:2]

        return tls_version

    @tls_version.setter
    def tls_version(self, attr: bytes):

        self._tls_version = attr

    @property
    def body(self) -> HandShake:
        body = self._body
        if not body:
            body = ClientHello(
                # TODO: cipher suites, extensions
            )

        return body

    @body.setter
    def body(self, attr: HandShake):

        self._body = attr

    def set_payload(self):
        pass

    def handshake(self):
        """
        enum {
            hello_request(0), client_hello(1), server_hello(2),
            certificate(11), server_key_exchange (12),
            certificate_request(13), server_hello_done(14),
            certificate_verify(15), client_key_exchange(16),
            finished(20)
            (255)
        } HandshakeType;

        struct {
            HandshakeType msg_type;
            uint24 length;
            select (HandshakeType) {
                case hello_request:         HelloRequest;
                case client_hello:          ClientHello;
                case server_hello:          ServerHello;
                case certificate:            Certificate;
                case server_key_exchange:   ServerKeyExchange;
                case certificate_request:    CertificateRequest;
                case server_hello_done:     ServerHelloDone;
                case certificate_verify:     CertificateVerify;
                case client_key_exchange:   ClientKeyExchange;
                case finished:               Finished;
            } body;
        } Handshake;
        :return:
        """
        print(self.body.message)
