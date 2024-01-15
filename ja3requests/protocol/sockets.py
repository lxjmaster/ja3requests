# pylint: skip-file
"""
Ja3Requests.protocol.sockets
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

This module contains socket dependencies.
"""

import socket
from .exceptions import LocationParseError


def create_connection(
    address,
    timeout=socket._GLOBAL_DEFAULT_TIMEOUT,
    source_address=None,
    socket_options=None,
):
    """
    Create a socket connection.
    :param address:
    :param timeout:
    :param source_address:
    :param socket_options:
    :return:
    """
    if socket_options is None:
        socket_options = [(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)]

    err = None
    host, port = address

    family = allowed_gai_family()

    try:
        host.encode("idna")
    except UnicodeError:
        raise LocationParseError(f"{host!r}, label empty or too long")

    for res in socket.getaddrinfo(host, port, family, socket.SOCK_STREAM):
        _family, _type, _proto, _canonname, _addr = res
        sock = None
        try:
            sock = socket.socket(_family, _type, _proto)

            # If provided, set socket level options before connecting.
            _set_socket_options(sock, socket_options)

            if timeout is not socket._GLOBAL_DEFAULT_TIMEOUT:
                sock.settimeout(timeout)
            if source_address:
                sock.bind(source_address)
            sock.connect(_addr)
            return sock

        except socket.error as e:
            err = e
            if sock is not None:
                sock.close()

    if err is not None:
        raise err

    raise socket.error("getaddrinfo returns an empty list")


def _set_socket_options(sock, options):
    if options is None:
        return

    for opt in options:
        sock.setsockopt(*opt)


def allowed_gai_family():
    family = socket.AF_INET
    if HAS_IPV6:
        family = socket.AF_UNSPEC
    return family


def _has_ipv6(host):
    """Returns True if the system can bind an IPv6 address."""
    sock = None
    has_ipv6 = False

    if socket.has_ipv6:
        try:
            sock = socket.socket(socket.AF_INET6)
            sock.bind((host, 0))
            has_ipv6 = True
        except Exception:
            pass

    if sock:
        sock.close()
    return has_ipv6


HAS_IPV6 = _has_ipv6("::1")


if __name__ == '__main__':
    sock = create_connection(("127.0.0.1", 7890))
    sock.sendall("CONNECT ifconfig.me:80 HTTP/1.1\r\n\r\n".encode())
    response = sock.recv(4096).decode("utf8")
    if "200" in response:
        sock.sendall(
            # "GET / HTTP/1.1\r\nAccept: */*\r\nConnection: keep-alive\r\nUser-Agent: Python/3.11.6 (Darwin; macOS-13.3.1-x86_64-i386-64bit) Ja3Requests/1.0.2\r\nHost: ifconfig.me\r\n\r\n".encode()
            "GET / HTTP/1.1\r\nAccept: */*\r\nConnection: keep-alive\r\nUser-Agent: Python/3.11.6 (Darwin; macOS-13.3.1-x86_64-i386-64bit) Ja3Requests/1.0.2\r\nHost: ifconfig.me\r\n\r\n".encode()
        )
    a = 0
    while a < 50:
        response = sock.recv(4096).decode("utf8")
        a += 1
        print(response)
