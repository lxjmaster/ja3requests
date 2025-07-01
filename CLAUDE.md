# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Development Commands

### Testing
- Run tests: `python setup.py test` or `pytest`
- Run specific test: `pytest test/test_session.py`
- Setup uses pytest with parallel execution and boxed mode by default

### Code Quality
- Format code: `make fmt` (uses black with skip-string-normalization)
- Lint code: `make lint` (uses pylint with custom configuration)
- Clean build artifacts: `make clean`

### Building and Distribution
- Build source distribution: `make dist`
- Build wheel: `make build`
- Upload to PyPI: `make upload`

## Architecture Overview

Ja3Requests is a custom HTTP request library that allows customization of JA3 and H2 fingerprints for TLS connections. The library mimics the requests library API while providing low-level TLS control.

### Core Components

**Session Management (`ja3requests/sessions.py`)**
- `Session` class extends `BaseSession` and provides the main API
- Handles cookie persistence, connection pooling, and configuration
- Entry point through `ja3requests.session()` factory function

**Protocol Implementation (`ja3requests/protocol/`)**
- Custom TLS implementation in `tls/` directory
- Cipher suites configuration in `cipher_suites/suites.py`
- TLS layers for handshake messages (client_hello, server_hello, etc.)
- Extensions handling for TLS negotiation

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

- Runtime: `brotli` for compression support
- Development: `black`, `pylint`, `pytest`, `twine`

## Testing Strategy

Tests are located in `test/` directory using unittest framework with pytest runner. Current tests cover session functionality and utility functions.