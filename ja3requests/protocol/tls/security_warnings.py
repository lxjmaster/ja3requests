"""
ja3requests.protocol.tls.security_warnings
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Security warnings and notices for the TLS implementation.
"""

import warnings


class TLSSecurityWarning(UserWarning):
    """Warning for TLS security issues"""
    pass


def warn_insecure_implementation():
    """Warn about insecure TLS implementation"""
    warnings.warn(
        "ja3requests TLS implementation is incomplete and insecure. "
        "This library should NOT be used in production environments. "
        "Key security features are missing or use placeholder implementations.",
        TLSSecurityWarning,
        stacklevel=3
    )


def warn_no_certificate_verification():
    """Warn about missing certificate verification"""
    warnings.warn(
        "Certificate verification is not implemented. "
        "Connections are vulnerable to man-in-the-middle attacks.",
        TLSSecurityWarning,
        stacklevel=3
    )


def warn_unencrypted_key_exchange():
    """Warn about unencrypted key exchange"""
    warnings.warn(
        "Key exchange is using unencrypted premaster secret. "
        "This makes the connection completely insecure.",
        TLSSecurityWarning,
        stacklevel=3
    )


def warn_invalid_finished_message():
    """Warn about invalid finished message"""
    warnings.warn(
        "Finished message is using random verify_data instead of proper PRF calculation. "
        "Handshake integrity cannot be verified.",
        TLSSecurityWarning,
        stacklevel=3
    )


# Security notice for users
SECURITY_NOTICE = """
⚠️  SECURITY WARNING ⚠️

The ja3requests library is currently in development and contains incomplete 
security implementations. DO NOT use this library for:

- Production applications
- Handling sensitive data
- Secure communications
- Any security-critical operations

Current security issues:
- No certificate verification
- Unencrypted key exchange
- Missing cryptographic implementations
- No integrity verification

This library is intended for:
- Research and development
- TLS fingerprinting studies
- Educational purposes
- Testing and experimentation

Please implement proper security measures before using in any real-world scenarios.
"""


def print_security_notice():
    """Print security notice to console"""
    print("=" * 70)
    print(SECURITY_NOTICE)
    print("=" * 70)