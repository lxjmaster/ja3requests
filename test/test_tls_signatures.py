"""TLS signature schemes must authenticate the exact signed bytes."""

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519, ed448, padding

from ja3requests.protocol.tls.certificate_verify import (
    CertificateVerificationError,
    verify_tls_signature,
)


@pytest.fixture(scope="module")
def signing_keys():
    return {
        "rsa": rsa.generate_private_key(public_exponent=65537, key_size=2048),
        "p256": ec.generate_private_key(ec.SECP256R1()),
        "p384": ec.generate_private_key(ec.SECP384R1()),
        "p521": ec.generate_private_key(ec.SECP521R1()),
        "ed25519": ed25519.Ed25519PrivateKey.generate(),
        "ed448": ed448.Ed448PrivateKey.generate(),
    }


@pytest.mark.parametrize(
    "scheme,key_name,digest",
    [
        (0x0804, "rsa", hashes.SHA256),
        (0x0805, "rsa", hashes.SHA384),
        (0x0806, "rsa", hashes.SHA512),
        (0x0403, "p256", hashes.SHA256),
        (0x0503, "p384", hashes.SHA384),
        (0x0603, "p521", hashes.SHA512),
        (0x0807, "ed25519", None),
        (0x0808, "ed448", None),
    ],
)
def test_tls13_signature_authenticates_payload(signing_keys, scheme, key_name, digest):
    key = signing_keys[key_name]
    payload = b"independent handshake signature test"
    if key_name == "rsa":
        algorithm = digest()
        signature = key.sign(
            payload,
            padding.PSS(mgf=padding.MGF1(algorithm), salt_length=algorithm.digest_size),
            algorithm,
        )
    elif digest is not None:
        signature = key.sign(payload, ec.ECDSA(digest()))
    else:
        signature = key.sign(payload)
    verify_tls_signature(key.public_key(), scheme, signature, payload, tls13=True)
    with pytest.raises(CertificateVerificationError):
        verify_tls_signature(
            key.public_key(), scheme, signature, payload + b"tampered", tls13=True
        )


def test_tls13_rejects_legacy_rsa_signature(signing_keys):
    key = signing_keys["rsa"]
    signature = key.sign(b"message", padding.PKCS1v15(), hashes.SHA256())
    verify_tls_signature(key.public_key(), 0x0401, signature, b"message")
    with pytest.raises(CertificateVerificationError):
        verify_tls_signature(
            key.public_key(), 0x0401, signature, b"message", tls13=True
        )


def test_tls13_rejects_mismatched_curve(signing_keys):
    key = signing_keys["p384"]
    signature = key.sign(b"message", ec.ECDSA(hashes.SHA256()))
    with pytest.raises(CertificateVerificationError, match="curve mismatch"):
        verify_tls_signature(
            key.public_key(), 0x0403, signature, b"message", tls13=True
        )
