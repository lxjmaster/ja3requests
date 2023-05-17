"""
ja3requests.const
~~~~~~~~~~~~~~~~~

A constant module.
"""

import sys


class _Const:
    class ConstError(TypeError):
        """
        Const Error
        """

    class ConstCaseError(ConstError):
        """
        Const Case Error
        """

    def __setattr__(self, key, value):
        if self.__dict__.get(key) is not None:
            raise self.ConstError(f"The constant {key} already exists")

        if not key.isupper():
            raise self.ConstCaseError(f"{key}-constants need to be capitalized.")

        self.__dict__[key] = value


const = _Const()

const.MAX_LINE = 65536
const.MAX_HEADERS = 100
const.DEFAULT_CHUNKED_SIZE = 2048
const.DEFAULT_HTTP_SCHEME = "http"
const.DEFAULT_HTTPS_SCHEME = "https"
const.DEFAULT_HTTP_PORT = 80
const.DEFAULT_HTTPS_PORT = 443
const.DEFAULT_REDIRECT_LIMIT = 8  # max redirect

sys.modules[__name__] = const
