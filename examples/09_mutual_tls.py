"""Mutual TLS (mTLS): client certificate authentication."""

from ja3requests import Session, TlsConfig

# Configure client certificate
config = TlsConfig()
config.tls_version = 0x0303
config.verify_cert = True

# Option 1: File paths
config.client_cert = "/path/to/client.pem"
config.client_key = "/path/to/client-key.pem"

# Option 2: PEM data directly
# config.client_cert = b"""-----BEGIN CERTIFICATE-----
# MIICpDCCAYwCCQD...
# -----END CERTIFICATE-----"""

session = Session(tls_config=config, use_pooling=False)

# When the server sends CertificateRequest during TLS handshake,
# the library will:
# 1. Parse cert types and signature algorithms from the request
# 2. Load the configured client certificate PEM
# 3. Send the certificate chain in the TLS Certificate message
# 4. (If no client cert configured, sends empty certificate)

# resp = session.get("https://mtls.example.com/api")

print(f"Client cert: {config.client_cert}")
print(f"Verify: {config.verify_cert}")
