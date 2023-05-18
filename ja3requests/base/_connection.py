"""
ja3Requests.base._connection
~~~~~~~~~~~~~~~~~~~~~~~~~~

Basic HTTP Connection
"""


class BaseHttpConnection:
    """
    Basic HTTP Connection
    """

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
        """
        Scheme
        :return:
        """
        return self._scheme

    @scheme.setter
    def scheme(self, attr):
        """
        Set Scheme
        :param attr:
        :return:
        """
        self._scheme = attr

    @property
    def host(self):
        """
        Host
        :return:
        """
        return self._host

    @host.setter
    def host(self, attr):
        """
        Set Host
        :param attr:
        :return:
        """
        self._host = attr

    @property
    def port(self):
        """
        Port
        :return:
        """
        return self._port

    @port.setter
    def port(self, attr):
        """
        Set Port
        :param attr:
        :return:
        """
        self._port = attr

    @property
    def source_address(self):
        """
        Source Address
        :return:
        """
        return self._source_address

    @source_address.setter
    def source_address(self, attr):
        """
        Set Source Address
        :param attr:
        :return:
        """
        self._source_address = attr

    @property
    def destination_address(self):
        """
        Destination Address
        :return:
        """
        return self._destination_address

    @destination_address.setter
    def destination_address(self, attr):
        """
        Set Destination Address
        :param attr:
        :return:
        """
        self._destination_address = attr

    @property
    def path(self):
        """
        Path
        :return:
        """
        return self._path

    @path.setter
    def path(self, attr):
        """
        Set Path
        :param attr:
        :return:
        """
        self._path = attr

    @property
    def timeout(self):
        """
        Timeout
        :return:
        """
        return self._timeout

    @timeout.setter
    def timeout(self, attr):
        """
        Set Timeout
        :param attr:
        :return:
        """
        self._timeout = attr

    @property
    def proxy(self):
        """
        Proxy
        :return:
        """
        return self._proxy

    @proxy.setter
    def proxy(self, attr):
        """
        Set Proxy
        :param attr:
        :return:
        """
        self._proxy = attr

    @property
    def proxy_username(self):
        """
        Proxy username
        :return:
        """
        return self._proxy_username

    @proxy_username.setter
    def proxy_username(self, attr):
        """
        Set Proxy Username
        :param attr:
        :return:
        """
        self._proxy_username = attr

    @property
    def proxy_password(self):
        """
        Proxy Password
        :return:
        """
        return self._proxy_password

    @proxy_password.setter
    def proxy_password(self, attr):
        """
        Set Proxy Password
        :param attr:
        :return:
        """
        self._proxy_password = attr

    @property
    def connection(self):
        """
        Connection
        :return:
        """
        return self._connection

    @connection.setter
    def connection(self, attr):
        """
        Set Connection
        :param attr:
        :return:
        """
        self._connection = attr

    @property
    def is_close(self):
        """
        Connection is closed
        :return:
        """
        return self._is_close

    @is_close.setter
    def is_close(self, attr):
        """
        Set connection close
        :param attr:
        :return:
        """
        self._is_close = attr
