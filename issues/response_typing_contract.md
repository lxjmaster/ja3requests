# Synchronous response typing: compatibility inventory

Prepared: 2026-10-25. Status: **N2a COMPLETE; N2b CONDITIONAL ENTRY NOT MET**.
Source baseline: `e28ee3302679455decd6348c89cf9f23b76fe2b0`.
Selected sequence: [N1 -> N2 -> N3](next_development_plan.md).
This is an analysis deliverable; no response implementation was changed.

## 1. Verified contracts

| Boundary | Current behavior | Typing implication |
| --- | --- | --- |
| `BaseResponse` | All six stored fields start as None; raw/protocol/status/headers/body properties have setters | A common byte-only or immutable schema does not describe every subclass |
| `HTTPResponse` / `HTTPSResponse` | Inherit the writable properties; status/protocol fields become bytes, headers move from None through a byte-line list to serialized bytes | Describe initialization and parser phases without assuming all fields are populated at construction |
| Public `Response.headers` | Computes a string dictionary; replaces the inherited property with a getter only | Assignment raises AttributeError; nominal inheritance from the writable base violates the checker's property-substitution rule |
| Public `Response.status_code` | Computes an int; returns -1 when no parser exists; also getter only | Same writable-to-read-only override conflict, independently of the int/bytes difference |
| Public `Response.body` | Byte-valued read; its setter accepts bytes or None | Preserve the setter and lazy-read/failed-consumption rules; do not make this property read-only |
| `Response()` without a parser | `status_code == -1`, `content == b''`; accessing headers raises AttributeError on the absent parser | A new empty-header return would be a runtime correction, not an annotation-only change |
| Raw/body generators | Actual generators support close; uncached consumption owns cleanup | Generator[bytes, None, None] can describe the actual close interface |
| `_ContentDecoder.decoder` | None initially, then a Brotli decompressor or zlib decompressor selected by encoding | Requires distinct static views/narrowing; one inferred None field is insufficient |
| Transport/file adapters | Socket and response-reader objects include project adapters and test doubles | Preserve the existing dynamic adapter boundary rather than requiring only stdlib socket/file classes |

The property inventory was read from actual descriptors on BaseResponse,
HTTPResponse and Response. In-memory checks verified writable base properties,
rejected assignments on Response, and the empty-response behavior above.
They opened no network connections and changed no source files.

## 2. Reproduced diagnostics and static limitation

Focused, nonincremental mypy still reports **24 diagnostics in response.py**
and **13 in base/__response.py** after N1. These include decoder inference,
an untyped Brotli import, generator close, nullable lengths/parser state,
untyped base methods and two read-only property override errors.

An isolated strict-checker example reproduces the property error even when
both getter return types are identical:

```python
class Writable:
    @property
    def value(self) -> int:
        return 1

    @value.setter
    def value(self, value: int) -> None:
        pass

class ReadOnly(Writable):
    @property
    def value(self) -> int:
        return 1
```

Mypy reports `Read-only property cannot override read-write property [misc]`.
The reproduction used a task-owned temporary directory and verified its removal.
Changing only annotations cannot make this example a sound writable subtype.

## 3. Brotli and shared decoder boundary

Runtime requirements contain `brotli>=1.2.0`; the current checker requirements
contain mypy and typing-extensions without Brotli stubs. A future typed view must
describe the installed operations actually used here: `process` with
`output_buffer_limit`, `can_accept_more_data`, `is_finished`, `decompress` and
the exception type. A stub package's existence or name alone is insufficient.
Use a verified development-only stub or bounded checker interface; no runtime
typing dependency, global missing-import exemption or new decompression logic.

Preserve byte chunks, the delayed two-byte deflate probe, raw-deflate fallback
only before decoded output, concatenated gzip handling, Brotli draining,
truncation rejection and the existing eager raw-body fallback. This decoder is
shared by sync and async responses; its later acceptance includes both readers.

## 4. Options and selected disposition

| Option | Benefit | Cost / compatibility boundary |
| --- | --- | --- |
| Preserve current hierarchy and property behavior | Keeps existing callers, subclass identity, setters and exceptions | The full response module cannot enter the strict gate while the nominal override conflict remains |
| Redesign the response hierarchy or property contract | Can provide sound immutable public metadata with a writable parser model | Requires explicit decisions about BaseResponse inheritance, public setters/subclasses and empty-response behavior; broader than this annotation-only batch |

**Recommendation and current disposition: preserve existing behavior.** The
selected plan made N2b conditional on compatibility. That condition is not met
for full-module strict migration, so N2b implementation is deferred at its entry
check. No ignore, checker-only substitute base, setter addition, inherited-setter
removal or unrelated empty-response fix was applied. N1 delivery and N3 design
can complete independently; this does not claim N2b was implemented.

## 5. Concrete re-entry and acceptance

1. Select either a response-hierarchy compatibility design, with a precise
   inheritance/setter decision, or a separately scoped decoder/parser-only
   annotation increment that keeps the whole module outside the gate.
2. For a hierarchy design, inventory external BaseResponse subclass usage and
   choose migration behavior for read-only metadata and empty responses before
   implementation. Do not silently invent writable Response metadata.
3. For decoder/parser-only work, verify the Brotli interface first and keep the
   unresolved override findings visible. Reducing diagnostics is not equivalent
   to completing the full-module strict gate.
4. Reuse response, failure-state and sync/async streaming tests. Add installed
   consumers for generator close and property mutability. Verify changed behavior
   and independent artifacts; use exact-commit CI for selected delivery.

No temporary environment or service remains. Historical artifacts and user files
are preserved. This document records a compatibility decision for later scope
selection; it creates no Issue, release or new required implementation task.
