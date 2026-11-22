# PALACO INDUSTRIE — One-Time Authority Challenge Session v1.2 (DRAFT / HOLD)

The module `distribution/authority-challenge-session.js` wraps the existing v1.1 Ed25519 receipt verifier with a local, in-process, one-time challenge lifecycle.

`createAuthorityChallengeSession({ttlMs,maxPending})` generates 256-bit unpredictable challenges using `crypto.randomBytes`. Each challenge is bound to one namespace, has a monotonic-clock expiry, and is consumed **before** signature verification, including when that verification fails. Capacity is bounded; the manager never discards a still-live challenge to accept another.

1. `session.issue('palaco.one')` returns `{issued:true,challenge}` or `{issued:false,reason}`.
2. Send the challenge to an independently authenticated authority.
3. `session.consume(namespace,challenge,state,endorsement,pinnedRoots,minimumSequence)` checks one-time use and calls the v1.1 signed-receipt verifier.
4. `session.close()` clears outstanding challenges.

This is **not** a persistent or distributed nonce store, network authentication protocol, authority server, clock-freshness proof, or durable monotonic checkpoint service. Process restarts invalidate pending challenges. Multi-instance deployments need an independently secured shared consume-once mechanism. Trusted root provisioning and the independently rollback-resistant minimum sequence remain external prerequisites.

In every result, release and execution authority remain DENY / GO-13 HOLD. No installation, publishing, recovery or database changes take place.

Run `node --test tests/distribution-authority-challenge-session.test.js`. Eight new regression tests passed locally on Node v22.16.0, with a local copy of the v1.1 verifier. Full branch CI and independent review remain necessary.
