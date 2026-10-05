"""
ja3requests.protocol.tls.certificate_verify
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Certificate verification for TLS connections.
"""

from datetime import datetime, timezone
import ipaddress
import ssl
from typing import List, Optional, Tuple

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa, ec, ed25519, ed448
from cryptography.exceptions import InvalidSignature
from cryptography.x509.oid import ExtensionOID, NameOID
from cryptography.x509.verification import PolicyBuilder, Store, VerificationError

from ja3requests.protocol.tls.debug import debug

# Constants
CERT_LENGTH_FIELD_SIZE = 3  # Certificate length field is 3 bytes in TLS


class CertificateVerificationError(Exception):
    """Base exception for certificate verification errors"""


class CertificateExpiredError(CertificateVerificationError):
    """Certificate has expired or is not yet valid"""


class CertificateHostnameMismatchError(CertificateVerificationError):
    """Certificate hostname does not match the requested hostname"""


class CertificateChainError(CertificateVerificationError):
    """Certificate chain validation failed"""


def verify_tls_signature(public_key, scheme, signature, data, tls13=False):
    """Verify proof of possession for TLS CertificateVerify/ServerKeyExchange."""
    algorithms = {4: hashes.SHA256, 5: hashes.SHA384, 6: hashes.SHA512}
    try:
        if scheme in (0x0804, 0x0805, 0x0806) and isinstance(
            public_key, rsa.RSAPublicKey
        ):
            digest = algorithms[scheme & 0xFF]()
            public_key.verify(
                signature,
                data,
                padding.PSS(mgf=padding.MGF1(digest), salt_length=digest.digest_size),
                digest,
            )
        elif (
            not tls13
            and scheme in (0x0401, 0x0501, 0x0601)
            and isinstance(public_key, rsa.RSAPublicKey)
        ):
            public_key.verify(
                signature, data, padding.PKCS1v15(), algorithms[scheme >> 8]()
            )
        elif scheme in (0x0403, 0x0503, 0x0603) and isinstance(
            public_key, ec.EllipticCurvePublicKey
        ):
            curves = {0x0403: 'secp256r1', 0x0503: 'secp384r1', 0x0603: 'secp521r1'}
            if tls13 and public_key.curve.name != curves[scheme]:
                raise CertificateVerificationError("TLS signature curve mismatch")
            public_key.verify(signature, data, ec.ECDSA(algorithms[scheme >> 8]()))
        elif (
            scheme == 0x0807 and isinstance(public_key, ed25519.Ed25519PublicKey)
        ) or (scheme == 0x0808 and isinstance(public_key, ed448.Ed448PublicKey)):
            public_key.verify(signature, data)
        else:
            raise CertificateVerificationError(
                f"Unsupported TLS signature scheme/key: {scheme:#06x}"
            )
    except (InvalidSignature, ValueError, TypeError) as error:
        raise CertificateVerificationError("Invalid TLS handshake signature") from error


class CertificateVerifier:
    """
    Verifies TLS certificates including:
    - Certificate chain validation
    - Hostname verification
    - Expiration checking
    - Signature verification
    """

    def __init__(
        self,
        verify: bool = True,
        ca_certs: Optional[str] = None,
        trust_roots: Optional[Tuple[bytes, ...]] = None,
    ):
        """
        Initialize certificate verifier.

        Args:
            verify: Whether to verify certificates (default True)
            ca_certs: Path to CA certificates bundle (uses system default if None)
            trust_roots: Preloaded DER trust roots for non-blocking callers.
        """
        self.verify = verify
        self.ca_certs = ca_certs
        self._trust_roots = trust_roots
        self._certificates = []

    def parse_certificate_chain(self, certificate_data: bytes) -> List[bytes]:
        """
        Parse certificate chain from TLS Certificate message.

        Args:
            certificate_data: Raw certificate list data from TLS handshake

        Returns:
            List of DER-encoded certificates (leaf first, root last)
        """
        certificates = []
        offset = 0

        if len(certificate_data) < CERT_LENGTH_FIELD_SIZE:
            return certificates

        total_length = int.from_bytes(
            certificate_data[0:CERT_LENGTH_FIELD_SIZE], byteorder='big'
        )
        if total_length != len(certificate_data) - CERT_LENGTH_FIELD_SIZE:
            return []
        offset = CERT_LENGTH_FIELD_SIZE

        while (
            offset < len(certificate_data)
            and offset < total_length + CERT_LENGTH_FIELD_SIZE
        ):
            if offset + CERT_LENGTH_FIELD_SIZE > len(certificate_data):
                return []

            cert_length = int.from_bytes(
                certificate_data[offset : offset + CERT_LENGTH_FIELD_SIZE],
                byteorder='big',
            )
            offset += CERT_LENGTH_FIELD_SIZE

            if not cert_length or offset + cert_length > len(certificate_data):
                return []

            cert_der = certificate_data[offset : offset + cert_length]
            certificates.append(cert_der)
            offset += cert_length

        self._certificates = certificates
        debug(f"Parsed {len(certificates)} certificates from chain")
        return certificates

    def verify_certificate(
        self,
        hostname: str,
        certificate_data: bytes,
        check_hostname: bool = True,
        check_expiry: bool = True,
    ) -> Tuple[bool, Optional[str]]:
        """
        Verify server certificate.

        Args:
            hostname: Expected server hostname
            certificate_data: Raw certificate list from TLS handshake
            check_hostname: Enable the preliminary identity check. Trust-path
                validation always enforces endpoint identity.
            check_expiry: Enable the preliminary validity check. Trust-path
                validation always enforces validity.

        Returns:
            Tuple of (is_valid, error_message)

        Raises:
            CertificateVerificationError: When verification fails (if raise_on_error=True)
        """
        if not self.verify:
            debug("Certificate verification disabled")
            return True, None

        try:
            certificates = self.parse_certificate_chain(certificate_data)
            if not certificates:
                raise CertificateChainError("No certificates in chain")

            leaf_cert = self._load_certificate(certificates[0])
            if leaf_cert is None:
                raise CertificateChainError("Failed to parse leaf certificate")

            if check_expiry:
                self._check_expiration(leaf_cert)

            if check_hostname:
                self._verify_hostname(leaf_cert, hostname)

            self._verify_chain(certificates, hostname)

            debug(f"Certificate verification successful for {hostname}")
            return True, None

        except CertificateVerificationError as e:
            debug(f"Certificate verification failed: {e}")
            return False, str(e)
        except (ValueError, TypeError, AttributeError, OSError, VerificationError) as e:
            debug(f"Certificate verification error: {e}")
            return False, str(e)

    def _load_certificate(self, cert_der: bytes):
        """Load certificate from DER bytes"""
        try:
            return x509.load_der_x509_certificate(cert_der, default_backend())
        except (ValueError, TypeError) as e:
            debug(f"Failed to load certificate: {e}")
            return None

    def _check_expiration(self, cert) -> None:
        """
        Check if certificate is within validity period.

        Raises:
            CertificateExpiredError: If certificate is expired or not yet valid
        """
        try:
            now = datetime.now(timezone.utc).replace(tzinfo=None)

            # Try new API first (cryptography >= 42.0)
            try:
                not_before = cert.not_valid_before_utc.replace(tzinfo=None)
                not_after = cert.not_valid_after_utc.replace(tzinfo=None)
            except AttributeError:
                # Fallback for older cryptography versions
                not_before = cert.not_valid_before
                not_after = cert.not_valid_after

            if now < not_before:
                raise CertificateExpiredError(
                    f"Certificate not yet valid (valid from {not_before})"
                )

            if now > not_after:
                raise CertificateExpiredError(
                    f"Certificate expired (expired on {not_after})"
                )

            debug(f"Certificate valid until {not_after}")

        except CertificateExpiredError:  # pylint: disable=try-except-raise
            raise
        except (ValueError, TypeError, AttributeError) as e:
            raise CertificateExpiredError(f"Invalid validity period: {e}") from e

    def _verify_hostname(self, cert, hostname: str) -> None:
        """
        Verify certificate matches hostname.

        Raises:
            CertificateHostnameMismatchError: If hostname doesn't match
        """
        try:
            # Check Subject Alternative Names first (preferred method)
            try:
                san_ext = cert.extensions.get_extension_for_oid(
                    ExtensionOID.SUBJECT_ALTERNATIVE_NAME
                )
                try:
                    address = ipaddress.ip_address(hostname)
                except ValueError:
                    address = None
                if address is not None:
                    if address in san_ext.value.get_values_for_type(x509.IPAddress):
                        return
                san_names = (
                    san_ext.value.get_values_for_type(x509.DNSName)
                    if address is None
                    else []
                )

                for name in san_names:
                    if self._match_hostname(hostname, name):
                        debug(f"Hostname {hostname} matches SAN {name}")
                        return
                raise CertificateHostnameMismatchError(
                    f"Hostname {hostname} does not match certificate SAN"
                )
            except x509.ExtensionNotFound:
                pass

            # Fall back to Common Name (deprecated but still used)
            try:
                cn_attrs = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
                for attr in cn_attrs:
                    if self._match_hostname(hostname, attr.value):
                        debug(f"Hostname {hostname} matches CN {attr.value}")
                        return
            except (ValueError, AttributeError):
                pass

            raise CertificateHostnameMismatchError(
                f"Hostname {hostname} does not match certificate"
            )

        except CertificateHostnameMismatchError:  # pylint: disable=try-except-raise
            raise
        except (ValueError, TypeError, AttributeError) as e:
            debug(f"Hostname verification error: {e}")
            raise CertificateHostnameMismatchError(str(e)) from e

    def _match_hostname(self, hostname: str, pattern: str) -> bool:
        """
        Match hostname against certificate pattern.
        Supports wildcard matching (*.example.com)
        """
        hostname = hostname.lower()
        pattern = pattern.lower()

        if pattern.startswith('*.'):
            # Wildcard matching - only matches one label
            suffix = pattern[2:]
            if '.' in hostname:
                hostname_suffix = hostname.split('.', 1)[1]
                return hostname_suffix == suffix
            return False
        return hostname == pattern

    def _verify_chain(self, certificates: List[bytes], hostname: str) -> None:
        """Validate signatures and constraints to independently trusted roots."""
        if not certificates:
            raise CertificateChainError("Empty certificate chain")
        loaded = [x509.load_der_x509_certificate(cert) for cert in certificates]
        if self._trust_roots is not None:
            roots = [x509.load_der_x509_certificate(cert) for cert in self._trust_roots]
        elif self.ca_certs is not None:
            with open(self.ca_certs, 'rb') as bundle:
                roots = x509.load_pem_x509_certificates(bundle.read())
        else:
            roots = [
                x509.load_der_x509_certificate(cert)
                for cert in ssl.create_default_context().get_ca_certs(binary_form=True)
            ]
        try:
            subject = x509.IPAddress(ipaddress.ip_address(hostname))
        except ValueError:
            subject = x509.DNSName(hostname.encode('idna').decode('ascii'))
        verifier = PolicyBuilder().store(Store(roots)).build_server_verifier(subject)
        verifier.verify(loaded[0], loaded[1:])

    def get_certificate_info(self, cert_der: bytes) -> dict:
        """
        Get human-readable information about a certificate.

        Args:
            cert_der: DER-encoded certificate

        Returns:
            Dictionary with certificate details
        """
        cert = self._load_certificate(cert_der)
        if cert is None:
            return {}

        try:
            # Handle different cryptography versions
            try:
                valid_from = str(cert.not_valid_before_utc)
                valid_until = str(cert.not_valid_after_utc)
            except AttributeError:
                valid_from = str(cert.not_valid_before)
                valid_until = str(cert.not_valid_after)

            info = {
                'subject': {},
                'issuer': {},
                'valid_from': valid_from,
                'valid_until': valid_until,
                'serial_number': str(cert.serial_number),
                'san': [],
            }

            for attr in cert.subject:
                name = attr.oid._name  # pylint: disable=protected-access
                info['subject'][name] = attr.value

            for attr in cert.issuer:
                name = attr.oid._name  # pylint: disable=protected-access
                info['issuer'][name] = attr.value

            try:
                san_ext = cert.extensions.get_extension_for_oid(
                    ExtensionOID.SUBJECT_ALTERNATIVE_NAME
                )
                info['san'] = san_ext.value.get_values_for_type(x509.DNSName)
            except x509.ExtensionNotFound:
                pass

            return info

        except (ValueError, TypeError, AttributeError) as e:
            debug(f"Error getting certificate info: {e}")
            return {}


def verify_server_certificate(
    hostname: str,
    certificate_data: bytes,
    verify: bool = True,
) -> Tuple[bool, Optional[str]]:
    """
    Convenience function to verify server certificate.

    Args:
        hostname: Server hostname
        certificate_data: Raw certificate data from TLS handshake
        verify: Whether to perform verification

    Returns:
        Tuple of (is_valid, error_message)
    """
    verifier = CertificateVerifier(verify=verify)
    return verifier.verify_certificate(hostname, certificate_data)
