#!/usr/bin/env python3
"""
Debug test to trace the bytes error
"""

import ja3requests
from ja3requests.protocol.tls.config import TlsConfig

def debug_tls_handshake():
    """Debug TLS handshake to find the bytes error"""
    print("Debugging TLS handshake...")
    
    try:
        tls_config = TlsConfig()
        tls_config.server_name = "127.0.0.1"
        
        session = ja3requests.Session(tls_config=tls_config)
        # This will trigger the TLS handshake and show us where the error occurs
        response = session.get("https://127.0.0.1:443")
        print("Unexpected success!")
        
    except Exception as e:
        print(f"Expected error: {e}")

if __name__ == "__main__":
    debug_tls_handshake()