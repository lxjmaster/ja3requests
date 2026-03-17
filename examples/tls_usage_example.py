#!/usr/bin/env python3
"""
TLS Configuration Usage Examples for ja3requests

This file demonstrates how to use the new TLS configuration features
implemented in ja3requests library.
"""

import ja3requests
from ja3requests.protocol.tls.config import TlsConfig
from ja3requests.protocol.tls.cipher_suites.suites import *


def example_basic_usage():
    """
    Basic usage with default TLS configuration
    """
    print("=== Basic Usage Example ===")
    
    # Create session with default TLS config
    session = ja3requests.Session()
    
    try:
        response = session.get("https://httpbin.org/get")
        print(f"Status Code: {response.status_code}")
        print(f"Response: {response.text[:100]}...")
    except Exception as e:
        print(f"Error: {e}")


def example_custom_tls_config():
    """
    Using custom TLS configuration
    """
    print("\n=== Custom TLS Configuration Example ===")
    
    # Create custom TLS configuration
    tls_config = TlsConfig()
    
    # Set specific cipher suites
    tls_config.cipher_suites = [
        Aes128GcmSha256(),
        Aes256GcmSha384(),
        RsaWithAes128CbcSha(),
        RsaWithAes256CbcSha(),
    ]
    
    # Set supported groups (elliptic curves)
    tls_config.supported_groups = [23, 24, 25]  # secp256r1, secp384r1, secp521r1
    
    # Set ALPN protocols
    tls_config.alpn_protocols = ['h2', 'http/1.1']
    
    # Set server name for SNI
    tls_config.server_name = "httpbin.org"
    
    # Create session with custom TLS config
    session = ja3requests.Session(tls_config=tls_config)
    
    try:
        response = session.get("https://httpbin.org/get")
        print(f"Status Code: {response.status_code}")
        print(f"JA3 String: {tls_config.get_ja3_string()}")
    except Exception as e:
        print(f"Error: {e}")


def example_firefox_mimicry():
    """
    Mimicking Firefox browser TLS fingerprint
    """
    print("\n=== Firefox Mimicry Example ===")
    
    # Create Firefox-like TLS configuration
    tls_config = TlsConfig().create_firefox_config()
    
    # Create session
    session = ja3requests.Session(tls_config=tls_config)
    
    # Add Firefox-like headers
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.5',
        'Accept-Encoding': 'gzip, deflate, br',
        'Connection': 'keep-alive',
        'Upgrade-Insecure-Requests': '1',
        'Sec-Fetch-Dest': 'document',
        'Sec-Fetch-Mode': 'navigate',
        'Sec-Fetch-Site': 'none',
        'Sec-Fetch-User': '?1',
    }
    
    try:
        response = session.get("https://httpbin.org/headers", headers=headers)
        print(f"Status Code: {response.status_code}")
        print(f"JA3 String: {tls_config.get_ja3_string()}")
    except Exception as e:
        print(f"Error: {e}")


def example_chrome_mimicry():
    """
    Mimicking Chrome browser TLS fingerprint
    """
    print("\n=== Chrome Mimicry Example ===")
    
    # Create Chrome-like TLS configuration
    tls_config = TlsConfig().create_chrome_config()
    
    # Create session
    session = ja3requests.Session(tls_config=tls_config)
    
    # Add Chrome-like headers
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
        'Accept-Language': 'en-US,en;q=0.9',
        'Accept-Encoding': 'gzip, deflate, br',
        'Connection': 'keep-alive',
        'Upgrade-Insecure-Requests': '1',
        'Sec-Fetch-Dest': 'document',
        'Sec-Fetch-Mode': 'navigate',
        'Sec-Fetch-Site': 'none',
        'Sec-Fetch-User': '?1',
        'sec-ch-ua': '"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"',
        'sec-ch-ua-mobile': '?0',
        'sec-ch-ua-platform': '"Windows"',
    }
    
    try:
        response = session.get("https://httpbin.org/headers", headers=headers)
        print(f"Status Code: {response.status_code}")
        print(f"JA3 String: {tls_config.get_ja3_string()}")
    except Exception as e:
        print(f"Error: {e}")


def example_custom_ja3_fingerprint():
    """
    Creating a completely custom JA3 fingerprint
    """
    print("\n=== Custom JA3 Fingerprint Example ===")
    
    # Create custom configuration
    tls_config = TlsConfig().create_custom_config(
        tls_version=0x0303,  # TLS 1.2
        cipher_suites=[
            ChaCha20Poly1305Sha256(),
            Aes256GcmSha384(),
            Aes128GcmSha256(),
        ],
        supported_groups=[29, 23, 24],  # x25519, secp256r1, secp384r1
        alpn_protocols=['h2'],
        server_name="example.com"
    )
    
    # Disable GREASE for more predictable fingerprint
    tls_config.use_grease = False
    
    print(f"Custom JA3 String: {tls_config.get_ja3_string()}")
    
    # Create session
    session = ja3requests.Session(tls_config=tls_config)
    
    try:
        response = session.get("https://httpbin.org/get")
        print(f"Status Code: {response.status_code}")
    except Exception as e:
        print(f"Error: {e}")


def example_cipher_suite_analysis():
    """
    Analyzing different cipher suites
    """
    print("\n=== Cipher Suite Analysis Example ===")
    
    from ja3requests.protocol.tls.crypto import get_cipher_info
    
    # Test different cipher suites
    cipher_suites = [
        0x002F,  # TLS_RSA_WITH_AES_128_CBC_SHA
        0x0035,  # TLS_RSA_WITH_AES_256_CBC_SHA
        0x1301,  # TLS_AES_128_GCM_SHA256
        0x1302,  # TLS_AES_256_GCM_SHA384
    ]
    
    for cipher in cipher_suites:
        info = get_cipher_info(cipher)
        print(f"Cipher 0x{cipher:04X}: {info['name']}")
        print(f"  Key Exchange: {info['key_exchange']}")
        print(f"  Cipher: {info['cipher']}")
        print(f"  MAC: {info['mac']}")
        print(f"  Key Size: {info['key_size']} bytes")
        print()


def main():
    """
    Run all examples
    """
    print("ja3requests TLS Configuration Examples")
    print("=" * 50)
    
    # Run examples
    example_basic_usage()
    example_custom_tls_config()
    example_firefox_mimicry()
    example_chrome_mimicry()
    example_custom_ja3_fingerprint()
    example_cipher_suite_analysis()
    
    print("\nAll examples completed!")


if __name__ == "__main__":
    main()