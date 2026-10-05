# Response and errors API

Body ownership, consumption and replay rules are described in the
[streaming guide](../streaming.md). The error classes below are real source
objects; their existence does not imply every socket/protocol failure is
normalized into one hierarchy. See [configuration and errors](../configuration.md).

::: ja3requests.response.Response
    options:
      members:
        - status_code
        - headers
        - cookies
        - body
        - content
        - text
        - encoding
        - json
        - iter_content
        - iter_lines
        - close
        - raise_for_status
        - is_redirected
        - location

## Public exceptions

::: ja3requests.exceptions
    options:
      members:
        - RequestException
        - HTTPError
        - ConnectionException
        - Timeout
        - StreamConsumedError
        - ContentDecodingError
        - MaxRetriedException
        - NotAllowedRequestMethod
        - MissingScheme
        - NotAllowedScheme
        - InvalidParams
        - InvalidData
        - InvalidHost
        - InvalidStatusLine
        - InvalidResponseHeaders
        - TLSError
        - TLSEncryptionError
        - TLSDecryptionError
        - TLSMACVerificationError
        - TLSHandshakeError
        - TLSKeyError

## Protocol transport exceptions

::: ja3requests.protocol.exceptions
