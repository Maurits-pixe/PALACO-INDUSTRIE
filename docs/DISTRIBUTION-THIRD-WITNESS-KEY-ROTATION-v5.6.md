# PALACO INDUSTRIE — Independently Reviewed Witness Key Rotation v5.6

**Draft PR #36. `authorization=DENY` / `GO-13=HOLD`. No merge, install, release or production deployment.**

## Change

`distribution/third-witness-key-rotation-v5.6.js` defines a deterministic, domain-separated Ed25519-signed **key-manifest succession statement** binding namespace, unique logical rotation number, old and new manifest SHA-256 digests, retiring/new signing key IDs, rotation instant, and explicit non-authorizing purpose.

Verification requires all three separately validated Ed25519 signatures: retiring key, newly introduced successor key and an independently pinned reviewer key. The reviewer key must differ from old and new key IDs and public keys. The prior manifest digest and prior rotation number are supplied independently, not inferred from a potentially rolled-back registry. A successful proof still returns only `THIRD_WITNESS_KEY_ROTATION_VERIFIED_NON_AUTHORIZING`, with all execution flags false.

Changes to previously anchored key epochs are rejected; the replacement history may only append one epoch. The old and new observer identities must agree, historic signer key IDs must differ and the new epoch must begin **exactly** when the old epoch ends. No overlapping/gapped key intervals or rollback of the independently pinned floor is permitted. Invalid, revoked, reused or forged keys, modified proofs, replayed rotation numbers, absent review or altered manifests all fail closed.

`distribution/third-witness-rotation-attestor-v5.6.js` is an opt-in trusted-module adapter: it checks the independently provided policy and three signatures before a parameterized `INSERT ... SELECT` into an append-only review ledger. The statement requires either an empty ledger for rotation 1 or an existing immediately preceding rotation with exactly matching prior digest, as well as no competing later rotation. The adapter exposes no raw SQL write access, signing interface or key activation.

`distribution/sql/third-witness-key-rotation-v5.6.sql` provisions an independently administered review-attestation table with immutable UPDATE/DELETE/TRUNCATE triggers, unique rotation numbers and unique successor manifest digests. This is a Draft SQL contract; it is **not** a production migration and does not independently enforce Ed25519 cryptography.

## Tests

`tests/distribution-third-witness-key-rotation-v5.6.test.js` contains six security test groups for valid triple signatures, pinned predecessor mismatch and replay, deleted/modified historical key epochs, forged or revoked signers, disallowed epoch boundaries and forbidden authorizing purposes.

`tests/postgres-third-witness-key-rotation-v5.6.test.js` provisions a disposable PostgreSQL 17 review registry with a restricted, namespace-scoped, SELECT+INSERT role. It proves a forged independent approval is denied before storage, a valid reviewed transition is inserted, replay is refused, the restricted writer cannot UPDATE/DELETE/TRUNCATE or disable triggers, and even the fixture administrator's ordinary DELETE is rejected by the trigger.

## Security limits

- This design **verifies and records** a proposed rotation. It does not issue keys, revoke production keys, update live trusted manifests or authorize activation. Safe manifest publication and production key custody remain separate controlled workstreams.
- The independently pinned predecessor manifest digest, previous rotation number and reviewer public key must be supplied through a trusted out-of-band operator process. A compromised policy provider defeats this check.
- The new manifest's higher evidence floor is accepted as a *signed claimed floor*; this module does not independently prove the underlying third-party checkpoint for the new floor. The v5.5 checkpoint verifier remains a separate prerequisite.
- The last historical key ID is assumed to be the active predecessor selected by trusted policy. An independent separately authenticated effective-date revocation and rotation ceremony is still necessary.
- The reviewer table and PostgreSQL test role exist only in disposable CI; PostgreSQL superusers can bypass triggers and the CI database shares the same server/failure domain as other tests. This does not demonstrate physical or administrative independence.
- The transition certificate is cryptographic evidence, not proof of human approval, quorum or executable release authority.

**Governance remains DRAFT / DENY / GO-13 HOLD. No automatic synchronization, recovery, release, merge, installation or public exposure.**