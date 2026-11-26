# PALACO INDUSTRIE — Independent Continuity Authority Gate v2.5 (DRAFT / HOLD)

The new `distribution/independent-continuity-authority.js` defines an explicit fail-closed adapter for **an independently managed durable, atomic, monotonic compare-and-advance service**. This repository does **not** provide that service or any proof of its rollback-resistance.

## Integration

Use `createIndependentContinuityAuthority({namespace,compareAndAdvance})` to configure a trusted adapter. `compareAndAdvance(namespace,epoch,minimumLastSeenMs,signal)` MUST perform a linearizable, durable compare-and-advance across all participating processes and hosts, maintaining independent monotonic high-watermarks for both signer epoch and clock-floor value. Its exact result MUST be boolean `true` to proceed. The adapter does not substitute for TLS, trusted service credentials, hardware-backed roots, quorum or durable storage guarantees.

`createIndependentlyGuardedChallengeRegistry(db,{floorAuthority,independentContinuity,...})` is the explicit strict factory. It refuses missing, forged or namespace-mismatched continuity adapters. The existing `createPrefetchedSignedChallengeRegistry` remains available for earlier opt-in contracts; supplying `independentContinuity` there activates the same check, but is not required in its legacy-compatible mode.

## Processing

1. Fetch and Ed25519-verify a fresh, challenge-bound signed clock floor outside SQLite `BEGIN IMMEDIATE`.
2. Before any SQLite write, invoke the configured independent authority's compare-and-advance, with an AbortSignal and `fetchTimeoutMs` deadline. A denial, exception, timeout, non-boolean response or interrupted request fails closed.
3. A timed-out authority call that ignores cancellation retains local/shared permits until the underlying Promise actually settles, following v2.3's resource-safety rule.
4. After independent acceptance, v2.4 process-local continuity must still accept the epoch and floor. Only then may the v1.5 transaction validate its pre-update stored clock and audit/issue/consume.

## Guarantees and limitations

An authority that advances the durable floor but returns a transport failure can cause conservative denial. This is expected; it must never weaken the monotonic floor. If the external service returns a stale or unauthentic result, or is itself rolled back, the adapter cannot detect that by itself. The service implementation must protect its persistent state from restore/rollback and guarantee atomicity under concurrency, crash recovery, and multi-host access.

An external service that ignores AbortSignal may hold shared permits indefinitely; operating systems cannot cancel arbitrary synchronous JS callbacks. These paths never authorize recovery or release. The in-process circuit breaker may classify external continuity failures as proof-preparation failures. All flags remain `authorization=DENY`, `go13=HOLD`, with no merge, deployment, publication, issuance authority or root rotation.

Tests: four authority adapter tests and four registry integration tests, including simulated restart, refusal, strict configuration and hanging calls. The simulated backend in tests is **not production-safe durable storage**.
