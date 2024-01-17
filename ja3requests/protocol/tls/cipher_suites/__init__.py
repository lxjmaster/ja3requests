from abc import ABC, abstractmethod


class CipherSuite:

    def __init__(self):
        self._name = None
        self._key_exchange_type = None
        self._hash_type = None
        self._cipher_type = None
        self._key_length = None
        self._mac_key_length = None
        self._value = None

    def __repr__(self):
        if self.name:
            return self.name

        return "<CipherSuite()>"

    @property
    def name(self):

        return self._name

    @name.setter
    def name(self, attr):

        self._name = attr

    @property
    def key_exchange_type(self):

        return self._key_exchange_type

    @key_exchange_type.setter
    def key_exchange_type(self, attr):

        self._key_exchange_type = attr

    @property
    def hash_type(self):

        return self._hash_type

    @hash_type.setter
    def hash_type(self, attr):

        self._hash_type = attr

    @property
    def cipher_type(self):

        return self._cipher_type

    @cipher_type.setter
    def cipher_type(self, attr):

        self._cipher_type = attr

    @property
    def key_length(self):

        return self._key_length

    @key_length.setter
    def key_length(self, attr):

        self._key_length = attr

    @property
    def mac_key_length(self):

        return self._mac_key_length

    @mac_key_length.setter
    def mac_key_length(self, attr):

        self._mac_key_length = attr

    @property
    def value(self):

        return self._value

    @value.setter
    def value(self, attr):

        self._value = attr
