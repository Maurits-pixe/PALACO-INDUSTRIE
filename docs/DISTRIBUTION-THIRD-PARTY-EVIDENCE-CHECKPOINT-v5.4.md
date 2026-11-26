# PALACO INDUSTRIE — Signed Third-Party Evidence Checkpoint v5.4

**Status: DRAFT / DENY / GO-13 HOLD. No merge or production deployment.**

## Objective

Make a one-sided OR coordinated restore of the primary evidence archive AND its v5.0/v5.3 external reference detectable against a **third signed, read-only observation** that is retained separately. This is an observer design: it cannot prevent coordinated compromise if the independent witness/key trust is also controlled by the attacker.

## Components

`distribution/third-party-evidence-checkpoint-v5.4.js` defines domain-separated canonical observation bytes binding namespace, exact anchor sequence, SHA-256 chain digest, observation timestamp, observer ID and explicit `DENY/HOLD`/`INDEPENDENT_OBSERVATION_NO_AUTHORITY` purpose. A pinned independent Ed25519 public key verifies an archived signature. The verifier queries the current external anchor and the latest signed independent checkpoint via **separate read-only query adapters** and checks exact sequence/digest equality. Missing/unreachable/malformed records, revoked/mismatched key roots, invalid signature, rollback or fork fail closed. It has no signer, writer, repair, restore, release or synchronization API.

`distribution/sql/third-party-evidence-checkpoint-v5.4.sql` creates a **separately provisioned append-only register**. UPDATE, DELETE and TRUNCATE are rejected by database triggers; `(namespace,sequence)` and `(namespace,chain_digest)` uniqueness limits simple replay. PostgreSQL does not verify Ed25519 internally; signature admission and proper independent root provisioning MUST be performed by separately trusted operators/services.

## Verification

`tests/distribution-third-party-evidence-checkpoint-v5.4.test.js` covers signed valid checkpoint, two-store rollback against a later third record, forged/tampered signatures, mismatching heads, revoked roots, outages, invalid format and abort.

`tests/postgres-third-party-evidence-checkpoint-v5.4.test.js` builds three **separate logical PostgreSQL 17 CI databases**. An independently signed checkpoint observes the external anchor at 12. The disposable test simulates a privileged schema restore of BOTH the original receipt metadata source and external anchor to 11. The third witness remains at 12, so the read-only verifier rejects the restored state with `THIRD_CHECKPOINT_ROOT_ROLLBACK_OR_FORK` and permanent `DENY/HOLD`. It also exercises SQL rejection of direct UPDATE, DELETE and TRUNCATE attempts against the third checkpoint.

## Critical trust boundaries

- **The three CI databases share one PostgreSQL server and administrator.** This is a controlled rollback *simulation*, not real independence, disaster-domain separation, custody or protection against a compromised DB superuser restoring all three stores.
- Genuine production separation requires a physically/administratively independent third witness, separately managed backup domain, TLS identity, access policy, signed checkpoint admission and protected immutable key/roster history. No such infrastructure is provisioned by this Draft.
- A third checkpoint is only a signed *observation* of the external anchor. It neither proves every historic receipt without the v5.3 verifier nor grants decision authority. Its underlying signing key must not be managed by the archive operator whose actions it reviews.
- The verifier compares two reads at potentially different instants; honest concurrency can cause HOLD. The test does not establish distributed atomicity or global consensus. No automatic remediation is permitted.
- Missing/invalid third-party checkpoint means BLOCKED, not a fallback to the less independent v5.3 local root. No production credentials, deployment, API ingress, merge or distribution release.

**GO-13 HOLD / authorization DENY. Draft PR #36 only.**