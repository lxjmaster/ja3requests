"""
Ja3Requests.__init__
~~~~~~~~~~~~~~~~~~~~~~~~~~

Ja3Request
"""


from .sessions import Session


def session():
    """
    Return a Session object.
    :return:
    """
    return Session()
