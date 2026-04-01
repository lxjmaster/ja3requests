"""
ja3requests.protocol.tls.security_warnings
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Security warnings and notices for the TLS implementation.
"""

import warnings


class TLSSecurityWarning(UserWarning):
    """Warning for TLS security issues"""


def warn_no_certificate_verification():
    """Warn about disabled certificate verification"""
    warnings.warn(
        "Certificate verification is disabled. "
        "Connections may be vulnerable to man-in-the-middle attacks. "
        "Set verify=True to enable certificate verification.",
        TLSSecurityWarning,
        stacklevel=3,
    )
