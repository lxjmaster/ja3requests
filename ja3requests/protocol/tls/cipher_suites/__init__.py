"""
ja3requests.protocol.tls.cipher_suites
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The cipher suite base structure class.
"""

from abc import ABC


class CipherSuite(ABC):
    """Base structure class for TLS cipher suites."""

    def __init__(self):
        self._name = None
        self._key_exchange_type = None
        self._hash_type = None
        self._cipher_type = None
        self._key_length = None
        self._mac_key_length = None
        self._value = None
        self._version = None

    def __repr__(self):
        """Return string representation of the cipher suite."""
        if self.name:
            return f"<CipherSuite({self.name})>"

        return "<CipherSuite(NotImplemented)>"

    @property
    def name(self):
        """Get cipher suite name."""
        return self._name

    @name.setter
    def name(self, attr):
        """Set cipher suite name."""
        self._name = attr

    @property
    def key_exchange_type(self):
        """Get key exchange type."""
        return self._key_exchange_type

    @key_exchange_type.setter
    def key_exchange_type(self, attr):
        """Set key exchange type."""
        self._key_exchange_type = attr

    @property
    def hash_type(self):
        """Get hash type."""
        return self._hash_type

    @hash_type.setter
    def hash_type(self, attr):
        """Set hash type."""
        self._hash_type = attr

    @property
    def cipher_type(self):
        """Get cipher type."""
        return self._cipher_type

    @cipher_type.setter
    def cipher_type(self, attr):
        """Set cipher type."""
        self._cipher_type = attr

    @property
    def key_length(self):
        """Get key length."""
        return self._key_length

    @key_length.setter
    def key_length(self, attr):
        """Set key length."""
        self._key_length = attr

    @property
    def mac_key_length(self):
        """Get MAC key length."""
        return self._mac_key_length

    @mac_key_length.setter
    def mac_key_length(self, attr):
        """Set MAC key length."""
        self._mac_key_length = attr

    @property
    def value(self):
        """Get cipher suite value."""
        return self._value

    @value.setter
    def value(self, attr):
        """Set cipher suite value."""
        self._value = attr

    @property
    def version(self):
        """Get TLS version."""
        return self._version

    @version.setter
    def version(self, attr):
        """Set TLS version."""
        self._version = attr
