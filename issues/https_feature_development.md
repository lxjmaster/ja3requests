# HTTPS Feature Development

## Summary
Implemented and fixed HTTPS/TLS functionality for ja3requests library.

## Completed Tasks

### [x] POST Request Type Error Fix
- **Issue**: `can't concat str to bytes` error when POST data is passed
- **Cause**: `self.body = self.data` in `__contexts.py` assigned string data to body, but `message` construction expected bytes
- **Fix**: Added encoding in `message` property getter:
  ```python
  if self.data:
      data = self.data
      if isinstance(data, str):
          data = data.encode()
      self.body = data
  ```
- **File**: `ja3requests/base/__contexts.py`

### [x] Retry Class Connection Reuse Bug Fix
- **Issue**: Intermittent `MaxRetriedException` on redirect or multiple requests
- **Cause**: `Retry` class is a singleton that cached Task objects keyed by function reference, causing:
  - Depleted retry counters from previous calls
  - Stale connection parameters
- **Fix**: Create new Task for each call instead of reusing:
  ```python
  def do(self, obj, exception, *args, **kwargs):
      # Always create a new task for each call
      task = Task(obj, DEFAULT_MAX_RETRY_LIMIT, exception, *args, **kwargs)
      while task.times > 0:
          ...
  ```
- **File**: `ja3requests/utils.py`

### [x] Previous Session Fixes (from earlier work)
- Header parsing: Changed `headers_list[1:]` to `headers_list`
- Redirect handling: Added `tls_config` parameter and `urljoin` for relative URLs
- HTTP version: Changed HTTPSContext default from HTTP/2.0 to HTTP/1.1
- AES-GCM cipher support: Added GCM encryption/decryption
- Certificate verification: Added `CertificateVerifier` class

## Test Results

All HTTPS features tested and working:
- GET requests
- GET with query params
- POST with form data
- POST with JSON
- Custom headers
- Redirect following (relative and absolute URLs)
- Gzip response decompression

## Files Modified
- `ja3requests/base/__contexts.py` - POST data encoding fix
- `ja3requests/utils.py` - Retry class fix
- `ja3requests/sessions.py` - Redirect handling improvements
- `ja3requests/response.py` - Header parsing fix
- `ja3requests/contexts/context.py` - HTTP version fix
- `ja3requests/protocol/tls/crypto.py` - AES-GCM support
- `ja3requests/protocol/tls/__init__.py` - GCM and cert verification
- `ja3requests/sockets/https.py` - GCM application data
- `ja3requests/protocol/tls/certificate_verify.py` - New file
- `ja3requests/protocol/tls/config.py` - verify_cert option

### [x] Connection Pooling (Thread-Safe)
- **File**: `ja3requests/pool.py` (new)
- **Features**:
  - `ConnectionPool` class with thread-safe RLock protection
  - `PooledConnection` wrapper with metadata (created_at, last_used_at, TLS context)
  - Connection reuse for same (host, port, scheme) combination
  - Configurable max connections per host (default: 10)
  - Idle timeout with automatic cleanup (default: 60s)
  - Connection health check before reuse
  - Global default pool with `get_default_pool()`
- **Integration**:
  - `Session` accepts `pool` and `use_pooling` parameters
  - `HttpSocket` and `HttpsSocket` support pool-based connection reuse
  - Context manager support for Session (`with session as s:`)

## Next Steps
- [ ] TLS 1.3 support
- [ ] HTTP/2 support
- [ ] Session persistence
