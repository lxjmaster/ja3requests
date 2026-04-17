"""HTTP/2 fingerprint customization: SETTINGS, WINDOW_UPDATE, pseudo-header order."""

from ja3requests import Session, TlsConfig

# Chrome-like H2 fingerprint
config = TlsConfig.from_browser("chrome", 120)

# Customize H2 SETTINGS frame values
config.h2_settings = {
    0x01: 65536,    # HEADER_TABLE_SIZE
    0x02: 0,        # ENABLE_PUSH (disabled)
    0x03: 1000,     # MAX_CONCURRENT_STREAMS
    0x04: 6291456,  # INITIAL_WINDOW_SIZE (6MB)
    0x06: 262144,   # MAX_HEADER_LIST_SIZE
}

# Customize initial WINDOW_UPDATE
config.h2_window_update = 15663105

print(f"H2 SETTINGS: {config.h2_settings}")
print(f"H2 WINDOW_UPDATE: {config.h2_window_update}")
print(f"ALPN: {config.alpn_protocols}")

session = Session(tls_config=config)

# When connecting to an H2-capable server, the library will:
# 1. Negotiate h2 via ALPN during TLS handshake
# 2. Send connection preface with custom SETTINGS
# 3. Send WINDOW_UPDATE with custom increment
# 4. Encode requests as HTTP/2 HEADERS + DATA frames

# Firefox has different H2 fingerprint
firefox_config = TlsConfig.from_browser("firefox", 121)
print(f"\nFirefox H2 SETTINGS: {firefox_config.h2_settings}")
print(f"Firefox WINDOW_UPDATE: {firefox_config.h2_window_update}")
