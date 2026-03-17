"""
ja3requests.protocol.tls.extensions
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

This package contains all TLS extensions supported by ja3requests.

struct {
    ExtensionType extension_type;
    opaque extension_data<0..2^16-1>;
} Extension;

enum {
    signature_algorithms(13), (65535)
} ExtensionType;
"""

from abc import ABC, abstractmethod


class Extension(ABC):
    """Abstract base class for TLS extensions."""

    extension_type = None
    extension_data = b''

    @abstractmethod
    def encode(self):
        """Encode the extension into bytes."""
        raise NotImplementedError("encode method must be implemented by subclass.")
