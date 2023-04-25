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

const.DEFAULT_REDIRECT_LIMIT = 8  # max redirect

sys.modules[__name__] = const
