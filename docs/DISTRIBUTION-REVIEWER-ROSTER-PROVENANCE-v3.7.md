# PALACO INDUSTRIE — Reviewer Roster Provenance & Revocation v3.7 (DRAFT / HOLD)

## Scope

`distribution/reviewer-roster-transition.js` provides a read-only verifier for ordered, signed reviewer roster transitions. A separately pinned and non-revoked Ed25519 roster authority signs the canonical revision, namespace, predecessor digest, reviewer IDs, public-key digests and revocation statuses.

A transition requires an independently held **exact previous roster revision and digest**, a strictly sequential next revision and an exact predecessor link. Existing reviewer identities cannot disappear, their key IDs or public keys cannot silently change, and a revoked reviewer cannot return to active. New reviewers can be appended in canonical reviewer-ID order; duplicate reviewer/key identities and invalid keys fail closed. The returned review roots include **only active reviewers**.

`verifyRosterBoundBootstrapDossier()` adds an explicit provenance-bound mode to the v3.5 two-reviewer bootstrap verifier. In this mode it accepts reviewer signing roots **only** from the verified transition. It rejects mismatches between the signed roster digest and `dossier.pinnedRootsDigest`, out-of-scope rosters, missing ancestry, untrusted roster-authority signatures, and revoked reviewers participating in the dossier's signature quorum.

`createDistributionStartupInterlock()` can evaluate this stricter proof when trusted startup code explicitly supplies `reviewEvidence.rosterEvidence`. Even fully verified roster and bootstrap signatures remain diagnostic: `ingress=null`, `readiness=BLOCKED`, `authorization=DENY`, `go13=HOLD`, `mayInstall=false`, `mayPublish=false`.

## Explicit limitations

- The earlier v3.5 verifier is preserved for compatibility when roster evidence is absent; **this is an opt-in stricter provenance mode, not a mandatory global migration**. Production distribution is disabled regardless.
- The roster authority public keys, anchor revision and prior roster digest MUST be independently pinned and durable outside the roster issuer's trust/rollback domain. The module cannot validate their real-world provenance merely because they are supplied by the caller.
- Signing authenticates roster content, not human identity. Administrative enrollment and identity verification of reviewers remain separate duties.
- No production reviewer roster, secure anchor storage, independent service, trusted key provisioning, database mutation, certificate issuance, merge, deployment, public release or operational authorization is performed.

## Tests

Adversarial fixtures test signed sequential transitions, key substitution, deleted reviewers, revoked reactivation, duplicate keys, independent-anchor rollback, malformed keys, forged signatures, two-reviewer quorum binding, revoked reviewer exclusion and startup HOLD invariants.

Draft PR #36, GO-13 HOLD and authorization DENY remain unchanged.
