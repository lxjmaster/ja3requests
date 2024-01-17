

class TLS:

    def __init__(self, conn):

        self.conn = conn

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
        pass
