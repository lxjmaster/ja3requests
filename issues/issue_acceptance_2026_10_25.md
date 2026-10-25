# Historical Issue acceptance: proposed updates

Prepared: 2026-10-25. Status: **LOCAL DRAFTS COMPLETE**.
The original bodies and states of Issues 36, 37, 40, 41 and 42 were read from
GitHub on this date. All five were OPEN, with no updates since 2026-04-17.
No remote comment, checklist edit or closure was performed.

These drafts support the [current delivery sequence](next_development_plan.md#current-sequence-2026-10-25).
Local evidence links become available remotely only after their files are
delivered. At that point use the actual delivered commit's permalinks; do not
invent a commit identity or present an uncommitted result as published evidence.

## Evidence baseline

- Repository master: `9af4cc7032b82bea055dcd09b82d5bf8bba80f44`.
- Latest GitHub Release: [v2.6.0](https://github.com/lxjmaster/ja3requests/releases/tag/v2.6.0),
  published 2026-10-23, with tag target
  `76f1e6b4fba91c8e53d500f6bc7832cf86ece0e8`.
- The post-release typing commit above has five successful workflows:
  [Tests](https://github.com/lxjmaster/ja3requests/actions/runs/39945013394),
  [Coverage](https://github.com/lxjmaster/ja3requests/actions/runs/39945013464),
  [Lint](https://github.com/lxjmaster/ja3requests/actions/runs/39945013381),
  [Documentation](https://github.com/lxjmaster/ja3requests/actions/runs/39945013501),
  [Public typing](https://github.com/lxjmaster/ja3requests/actions/runs/39945013420).
- New streaming-memory tools and the
  [portable original report](../bench/streaming-memory-2026-10-23.json) are local
  uncommitted delivery inputs. The report is byte-identical to the retained
  `dist/streaming-memory/acceptance-01/measurement.json`; it records the measured
  source and tool hashes independently of the dirty-worktree flags.

## Issue 36: public typing

[Original Issue](https://github.com/lxjmaster/ja3requests/issues/36).
Recommended eventual action: post the evidence below and close the original
public-typing work after acceptance. Further internal diagnostics remain a
separate maintenance queue.

Proposed comment:

> The named base/session/request public signatures and request helpers are
> annotated; the remaining response-parser signatures were completed in
> `9af4cc7`. Both distribution formats include `py.typed`. The configured strict
> seven-module check and independently installed valid/invalid consumers are
> required CI gates. The consumer suite includes 85 expected negative markers.
> Structural Protocol types are used at the shared boundaries.
>
> CI also runs `mypy ja3requests/` with step-level allow-failure, as the original
> Issue permits. The implementation still has internal diagnostics; this does
> not claim that the whole package passes strict mypy. See the successful
> Public typing workflow and the typing acceptance guide.

Evidence: [typing guide](../typecheck/README.md),
[workflow](../.github/workflows/typing.yml),
[request helpers](../ja3requests/requests/request.py),
[response signatures](../ja3requests/response.py).

## Issue 37: native asynchronous API

[Original Issue](https://github.com/lxjmaster/ja3requests/issues/37).
Recommended eventual action: reconcile the API/implementation mapping below
in the Issue before closing it as the delivered native-async capability.

Proposed comment:

> Native `AsyncSession`, `AsyncResponse` and `AsyncConnectionPool` are delivered,
> including awaited request methods, synchronous/awaitable hooks, TLS1.2/1.3,
> H2 multiplexing, streaming and cancellation/ownership tests.
>
> The implementation uses top-level exports, `aiter_content`/`aiter_lines`,
> native socket awaits with the shared project TLS state machine, and its own
> bounded pool admission queue. These map to the original proposal's asyncio
> submodule, async iterators, StreamReader/Writer and semaphore-based limits;
> those particular names and mechanisms were not added as compatibility aliases.
> The synchronous client retains its existing API. The async guide documents
> the supported usage and ownership boundaries.

Evidence: [async guide](../docs/async.md),
[API reference source](../docs/api/async.md),
[async design and failure boundaries](async_api_design.md),
[async policy/lifecycle tests](../test/test_async_lifecycle_review.py).
Module-level async helpers and streaming prepared requests remain separate
extensions, rather than silently becoming new completion gates for this Issue.

## Issue 40: performance suite

[Original Issue](https://github.com/lxjmaster/ja3requests/issues/40).
Recommended eventual action: post the scoped historical evidence and close the
required suite work. Keep optional performance CI separate.

Proposed comment:

> The repository contains explicitly invoked protocol and pytest-benchmark
> component suites: full/resumed TLS, HTTP1/H2 requests and reuse, HPACK,
> connection pools, Cookies and JA3. Requests comparisons cover shared HTTP1
> workloads. Optional development dependencies are in `bench/requirements.txt`;
> they are not runtime dependencies.
>
> `bench/RESULTS.md` preserves the initial HTTP1 baseline and links to the
> broader protocol and subsequent sync/async results. Each report identifies
> the measured source, environment and limitations. Historical numbers are not
> fresh measurements of 2.6.0 or universal performance claims. The original
> optional PR benchmark/comment workflow remains a separate proposal.

Evidence: [initial baseline](../bench/RESULTS.md),
[protocol categories](../bench/PERFORMANCE_RESULTS.md),
[subsequent results](../bench/POST_2_1_0_RESULTS.md),
[component suite](../bench/test_component_performance.py),
[methodology](../bench/PERFORMANCE.md).

## Issue 41: reconcile the memory criterion first

[Original Issue](https://github.com/lxjmaster/ja3requests/issues/41).
Recommended eventual action: post the measured evidence and explicitly adopt
the following replacement memory criterion before considering closure. Do not
mark the original `chunk_size`-only memory criterion as having passed.

Proposed comment:

> Incremental HTTP1/TLS/H2 delivery, chunked framing, gzip/deflate/Brotli,
> backpressure and early-close ownership are implemented. Existing event-gated
> line tests also exercise delivery before the peer sends the tail.
>
> On 2026-10-23 the selected local measurement completed 100,000,000 and
> 1,000,000,000 decoded bytes on sync/async across seven paths: 28 cases and
> 14 size comparisons. Each case used a fresh client process, one request and
> one connection, with application chunks <=16,384 bytes, no response-body
> cache, verified content and a first application chunk before tail release.
>
> Proposed replacement criterion: record client RSS baseline/sampled peak,
> traced Python allocations, observable protocol/decoder state and application
> chunks separately. For this fixed workload use the predeclared budgets of
> 64 MiB request RSS increase, 16 MiB traced Python peak increase, and size-growth
> budgets of 8 MiB RSS and 1 MiB traced Python. All cases, comparisons,
> protocol budgets and cleanup checks must pass without changing those budgets
> after seeing the results.
>
> All checks passed: maximum sampled RSS increase 10,059,776 bytes, maximum
> traced Python peak increase 789,406 bytes; maximum cross-size growth
> 2,539,520 RSS bytes and 407 traced Python bytes. This is evidence for the
> stated configuration and payloads. RSS sampling can miss transients, native
> decoder state is not fully attributable, and total memory is not bounded by
> `chunk_size` alone. This criterion needs to be explicitly reconciled with
> the Issue's original wording before closure.

Evidence: [measurement method/results](../bench/STREAMING_MEMORY.md),
[portable original JSON](../bench/streaming-memory-2026-10-23.json),
[measurement execution record](streaming_memory_acceptance.md),
[gated line-delivery regression](../test/test_network_streaming.py).
The JSON SHA-256 is
`641230a2fe374c263931cf717889d3f5f125aba8e511407a05ce1d326a8afe79`.

## Issue 42: documentation

[Original Issue](https://github.com/lxjmaster/ja3requests/issues/42).
Recommended eventual action: post the documentation/CI evidence and close the
required documentation scope; keep hosting as the original optional item.

Proposed comment:

> The repository ships MkDocs with generated public API reference, getting
> started/configuration guides, feature guides, architecture, exceptions and a
> Requests migration guide. The README links to current capabilities and
> examples. Documentation CI builds with strict warnings, checks links/API
> objects/snippets and runs the local examples.
>
> The documentation workflow currently has read-only repository permissions
> and does not publish a public site. GitHub Pages was optional in the original
> Issue; hosting URL, version policy and deployment remain a separate task.

Evidence: [site configuration](../mkdocs.yml),
[documentation workflow](../.github/workflows/docs.yml),
[contributor verification guide](../docs/contributing_docs.md),
[architecture](../docs/architecture.md),
[Requests migration](../docs/requests_migration.md).
