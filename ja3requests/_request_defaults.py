"""Validated, opt-in defaults for request headers and query parameters."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import TYPE_CHECKING, Any, Dict, Optional, Tuple

from ja3requests._typing import Headers, Params
from ja3requests.utils import _validated_header_items, default_headers

if TYPE_CHECKING:
    from ja3requests._typing import RequestDefaults


_DEFAULT_HEADER_FORBIDDEN = frozenset(
    {
        'authorization',
        'proxy-authorization',
        'cookie',
        'host',
        'content-length',
        'transfer-encoding',
    }
)


def normalize_request_defaults(value: Any) -> Optional[Dict[str, Any]]:
    """Validate and detach a ``request_defaults`` assignment.

    The returned mapping is private and contains only non-empty ``headers`` and
    ``params`` fields.  Replacing it is therefore atomic for callers: a failed
    validation never produces a partial configuration.
    """
    if value is None:
        return None
    if not isinstance(value, Mapping):
        raise TypeError('request_defaults must be a mapping, None, or {}')

    unknown = set(value) - {'headers', 'params'}
    if unknown:
        names = ', '.join(sorted(str(name) for name in unknown))
        raise TypeError('Unsupported request default field(s): %s' % names)

    result: Dict[str, Any] = {}
    if 'headers' in value:
        headers = _normalize_default_headers(value['headers'])
        if headers:
            result['headers'] = headers
    if 'params' in value:
        params = _normalize_default_params(value['params'])
        if params:
            result['params'] = params
    return result or None


def request_defaults_snapshot(
    value: Optional[Dict[str, Any]],
) -> Optional[RequestDefaults]:
    """Return a detached public snapshot of private defaults."""
    if not value:
        return None
    result: RequestDefaults = {}
    if value.get('headers'):
        result['headers'] = dict(value['headers'])
    if value.get('params'):
        result['params'] = tuple(value['params'])
    return result or None


def merge_default_headers(
    defaults: Optional[Mapping[str, Any]], headers: Optional[Headers]
) -> Optional[Headers]:
    """Merge configured headers without changing the explicit empty contract."""
    if not defaults:
        return headers
    if headers is not None and isinstance(headers, Mapping) and not headers:
        # An explicit empty mapping bypasses configured defaults.  The sync and
        # async preparation layers retain their existing empty-header behavior.
        return {}
    if headers is not None and not isinstance(headers, Mapping):
        # Let the existing request preparation report its established error.
        return headers

    merged: Dict[str, Any] = dict(default_headers())
    _overlay_headers(merged, defaults)
    if headers is not None:
        _overlay_headers(merged, headers)
    return merged


def merge_default_params(
    defaults: Optional[Tuple[Tuple[str, str], ...]], params: Optional[Params]
) -> Optional[Params]:
    """Merge ordered defaults while preserving each client's URL encoding."""
    if not defaults:
        return params
    if params is None:
        return tuple(defaults)
    if isinstance(params, (str, bytes)):
        return params
    if isinstance(params, Mapping) and not params:
        return params
    if isinstance(params, (list, tuple)) and not params:
        return params

    if not isinstance(params, (Mapping, list, tuple)):
        # Preserve existing rejection of unsupported inputs; do not consume
        # a caller's iterator while trying to merge configuration.
        return params
    request_pairs = (
        list(params.items()) if isinstance(params, Mapping) else list(params)
    )
    if not all(
        isinstance(pair, (list, tuple)) and len(pair) == 2 for pair in request_pairs
    ):
        return params

    request_keys = [pair[0] for pair in request_pairs]
    inherited = tuple(pair for pair in defaults if pair[0] not in request_keys)
    return inherited + tuple((pair[0], pair[1]) for pair in request_pairs)


def _normalize_default_headers(value: Any) -> Dict[str, Any]:
    if value is None:
        return {}
    if not isinstance(value, Mapping):
        raise TypeError('request_defaults.headers must be a mapping or None')
    if not value:
        return {}

    result: Dict[str, Any] = {}
    seen = set()
    for name, item in value.items():
        if not isinstance(name, str):
            raise TypeError('request_defaults header names must be strings')
        if not isinstance(item, (str, bytes, int, float)):
            raise TypeError(
                'request_defaults header values must be text, bytes, or numbers'
            )
        lowered = name.lower()
        if lowered in seen:
            raise ValueError('Duplicate request default header name: %s' % name)
        seen.add(lowered)
        if lowered in _DEFAULT_HEADER_FORBIDDEN:
            raise ValueError('Header is not allowed in request_defaults: %s' % name)
        result[name] = item

    # Use the same token and control-character rules as outgoing requests.
    _validated_header_items(result)
    return result


def _normalize_default_params(value: Any) -> Tuple[Tuple[str, str], ...]:
    if value is None:
        return ()
    if isinstance(value, Mapping):
        pairs = list(value.items())
    elif isinstance(value, Sequence) and not isinstance(value, (str, bytes)):
        pairs = list(value)
    else:
        raise TypeError(
            'request_defaults.params must be a string mapping or sequence of pairs'
        )

    normalized = []
    for pair in pairs:
        if (
            not isinstance(pair, (list, tuple))
            or len(pair) != 2
            or not isinstance(pair[0], str)
            or not isinstance(pair[1], str)
        ):
            raise TypeError('request_defaults.params pairs must contain two strings')
        normalized.append((pair[0], pair[1]))
    return tuple(normalized)


def _overlay_headers(target: Dict[str, Any], source: Mapping[str, Any]) -> None:
    for name, value in source.items():
        for existing in tuple(target):
            if (
                isinstance(existing, str)
                and isinstance(name, str)
                and existing.lower() == name.lower()
            ):
                del target[existing]
        target[name] = value
