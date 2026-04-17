"""Browser fingerprint customization: Chrome, Firefox, Safari presets and custom JA3."""

from ja3requests import Session, TlsConfig
from ja3requests.protocol.tls.browser_presets import list_browsers

# List available browser presets
print("Available browser presets:")
for browser, versions in list_browsers().items():
    print(f"  {browser}: {versions}")

# Use Chrome 120 fingerprint
config = TlsConfig.from_browser("chrome", 120)
print(f"\nChrome 120 JA3: {config.get_ja3_string()}")

session = Session(tls_config=config)
# resp = session.get("https://tls.browserleaks.com/json")

# Use Firefox 121 fingerprint
config = TlsConfig.from_browser("firefox", 121)
print(f"Firefox 121 JA3: {config.get_ja3_string()}")

# Use Safari 17 fingerprint
config = TlsConfig.from_browser("safari", 17)
print(f"Safari 17 JA3: {config.get_ja3_string()}")

# Custom JA3 fingerprint
from ja3requests.protocol.tls.cipher_suites.suites import (
    EcdheRsaWithAes128GcmSha256,
    EcdheRsaWithAes256GcmSha384,
)

config = TlsConfig()
config.tls_version = 0x0303
config.cipher_suites = [EcdheRsaWithAes128GcmSha256(), EcdheRsaWithAes256GcmSha384()]
config.supported_groups = [29, 23, 24]
config.alpn_protocols = ["h2", "http/1.1"]
print(f"\nCustom JA3: {config.get_ja3_string()}")

# Validate the config
issues = config.validate()
print(f"Validation issues: {issues or 'None'}")
