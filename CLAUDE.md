# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Development Commands

### Testing
- Run tests: `python -m pytest test --ignore=test/test_session.py -q`
- Run a focused test: `python -m pytest test/test_sync_redirect_review.py -q`
- `test/test_session.py` is a legacy manual test that depends on external
  services; exclude it from the local and CI suite unless you are intentionally
  running that manual check.

### Code Quality
- Format code: `make fmt` (uses black with skip-string-normalization)
- Lint code: `make lint` (uses pylint with custom configuration)
- Clean transient build artifacts: `make clean` (retains `dist/` acceptance
  evidence; use `make clean-dist` only when the distribution directory itself
  is task-owned and may be removed)

### Building and Distribution
- Build source distribution: `make dist`
- Build wheel: `make build`
- Upload the exact versioned wheel and sdist: `make upload RELEASE_VERSION=2.3.0`

## Architecture Overview

Ja3Requests is a custom HTTP request library that allows customization of JA3 and H2 fingerprints for TLS connections. The library mimics the requests library API while providing low-level TLS control. Supports Python 3.7+.

### Core Components

**Session Management (`ja3requests/sessions.py`)**
- `Session` class extends `BaseSession` and provides the main API
- Handles cookie persistence, connection pooling, and configuration
- Entry point through `ja3requests.session()` factory function
- Accepts `TlsConfig` for JA3 fingerprint customization

**TLS/JA3 Fingerprinting (`ja3requests/protocol/tls/`)**
- `TLS` class in `__init__.py` - orchestrates the complete TLS handshake
- `TlsConfig` in `config.py` - configures cipher suites, extensions, supported groups for custom JA3 fingerprints
- Browser presets: `TlsConfig().create_firefox_config()` and `create_chrome_config()`
- Handshake layers in `layers/` - client_hello, server_hello, certificate, key_exchange, finished
- `crypto.py` - AES-CBC encryption, HMAC-SHA1, PRF for key derivation

**TLS Handshake Flow**
1. `HttpsSocket.new_conn()` creates TCP connection and initiates TLS
2. `TLS.set_payload()` configures ClientHello based on TlsConfig
3. `TLS.handshake()` performs full handshake: ClientHello → ServerHello/Certificate/KeyExchange → ClientKeyExchange/ChangeCipherSpec/Finished

**Request/Response Handling**
- `ja3requests/requests/` - HTTP/HTTPS request implementations
- `ja3requests/response.py` - Response object similar to requests library
- `ja3requests/sockets/` - Custom socket implementations for HTTP/HTTPS/proxy

**Base Classes (`ja3requests/base/`)**
- Abstract base classes for sessions, requests, responses, and sockets
- Context management for connection handling

### Key Design Patterns

- Factory pattern for session creation
- Inheritance hierarchy with base classes for extensibility
- Context managers for resource management
- Custom socket implementations to control TLS handshake details

## Dependencies

- Runtime: `brotli` for compression, `cryptography` for TLS operations
- Development: `black`, `pylint`, `pytest`, `twine`

## Testing Strategy

Tests are located in `test/` directory using unittest framework with pytest runner. Current tests cover session functionality and utility functions.
