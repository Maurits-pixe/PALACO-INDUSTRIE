# PALACO INDUSTRIE — Monotonic Authority Contract v1.0 (DRAFT / HOLD)

This module adds **pure read-only precondition checks** for a future independently hosted monotonic checkpoint authority. It is not an implementation of that authority.

## Functions

- `assessMonotonicAdvance(namespace, current, proposed, expected)` validates an authenticated caller-supplied current state, optimistic compare-and-swap expectations, an exactly sequential update, and a changed digest.
- `assessMonotonicRecovery(namespace, current, restored)` requires a restored anchor to match an independently authenticated current state exactly. Earlier, newer and forked states block.

All state objects contain `namespace`, `sequence` (non-negative safe integer) and `digest` (64 lowercase hexadecimal characters). The current authority state additionally requires `authenticated: true`.

**Important:** the `authenticated` property is an assertion supplied by the caller, NOT cryptographic verification. An untrusted caller setting it to true can defeat the claimed boundary. Do not use these results for release or security decisions until a genuine independently authenticated authority adapter is implemented. Compare-and-swap checks here are **not atomic database operations**; the actual authority must serialize writers, enforce conditional durable writes and return signed receipts. Hardware-backed monotonicity, secure bootstrap, rollback-resistant persistence, root rotation and audited recovery are not implemented.

Every result returns `authorization=DENY`, `go13=HOLD`, `mayAdvance=false`, `mayRestore=false`, `mayRotate=false`, `mayPublish=false` and `mayInstall=false`, regardless of diagnostic success.

Run `node --test tests/distribution-monotonic-authority.test.js`. Eight local tests passed during development. Independent CI and review remain required.
