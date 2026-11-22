# PALACO INDUSTRIE — Signed Audited Challenge Integration v1.7 (DRAFT / HOLD)

The new distribution/signed-audited-challenge-registry.js provides an explicit strict factory, `createSignedAuditedChallengeRegistry(db,{floorAuthority,clock,ttlMs,maxPending,maxRows})`.

It composes the v1.6 signed Ed25519 clock-floor provider with v1.5 SQLite `BEGIN IMMEDIATE` audit transaction processing. For every issue/consume transaction the provider generates a fresh 256-bit challenge and verifies a signed floor; v1.5 compares the pre-update **stored** clock against this authenticated minimum, checks all registry records and only then mutates the registry. Invalid signatures, stale epochs, expired or misbound challenges, invalid records and restored clocks behind the floor fail closed.

Security prerequisites: floorAuthority must contain `namespace`, `fetchSignedFloor(challenge)`, independently pinned `pinnedRoots`, and a rollback-protected `minimumEpoch`. Clock authority must be independently authenticated, trustworthy, bounded, and synchronous. No external network service or clock signer is implemented here. Do not hold a SQLite write transaction during unbounded remote calls; an operational integration should provide a bounded trusted local source or redesign the protocol.

Important: This cannot establish that a signer is honest or that its lower bound is updated monotonically; fresh nonces do not prove correctness of clock time or underlying durable storage. The legacy unguarded registry factory remains accessible for backward compatibility and must not be treated as hardened.

The integration performs no deployment, installation, identity issuance or trust-root rotation. All receipts retain `authorization=DENY`, `go13=HOLD`, `mayPublish=false`, and `mayInstall=false`. No merge to main.

Tests: `node --test tests/distribution-signed-audited-challenge-registry.test.js`.
