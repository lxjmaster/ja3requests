import struct
from ja3requests.protocol.tls.layers import HandShake


class HelloRequest(HandShake):

    @property
    def handshake_type(self) -> bytes:

        return struct.pack("B", 0)

    @property
    def message(self):
        return self.handshake_type


if __name__ == '__main__':
    print(HelloRequest().message)
