"""
ja3Requests.base._connection
~~~~~~~~~~~~~~~~~~~~~~~~~~

Basic HTTP Connection
"""


class BaseHttpConnection:

    def __init__(self):

        self._scheme = None
        self._host = None
        self._port = None
        self._source_address = None
        self._destination_address = None
        self._path = None
        self._timeout = None
        self._proxy = None
        self._proxy_username = None
        self._proxy_password = None
        self._connection = None
        self._is_close = None

    @property
    def scheme(self):
        return self._scheme

    @scheme.setter
    def scheme(self, attr):
        self._scheme = attr

    @property
    def host(self):
        return self._host

    @host.setter
    def host(self, attr):
        self._host = attr

    @property
    def port(self):
        return self._port

    @port.setter
    def port(self, attr):
        self._port = attr

    @property
    def source_address(self):
        return self._source_address

    @source_address.setter
    def source_address(self, attr):
        self._source_address = attr

    @property
    def destination_address(self):
        return self._destination_address

    @destination_address.setter
    def destination_address(self, attr):
        self._destination_address = attr

    @property
    def path(self):
        return self._path

    @path.setter
    def path(self, attr):
        self._path = attr

    @property
    def timeout(self):
        return self._timeout

    @timeout.setter
    def timeout(self, attr):
        self._timeout = attr

    @property
    def proxy(self):
        return self._proxy

    @proxy.setter
    def proxy(self, attr):
        self._proxy = attr

    @property
    def proxy_username(self):
        return self._proxy_username

    @proxy_username.setter
    def proxy_username(self, attr):
        self._proxy_username = attr

    @property
    def proxy_password(self):
        return self._proxy_password

    @proxy_password.setter
    def proxy_password(self, attr):
        self._proxy_password = attr

    @property
    def connection(self):
        return self._connection

    @connection.setter
    def connection(self, attr):
        self._connection = attr

    @property
    def is_close(self):
        return self._is_close

    @is_close.setter
    def is_close(self, attr):
        self._is_close = attr
