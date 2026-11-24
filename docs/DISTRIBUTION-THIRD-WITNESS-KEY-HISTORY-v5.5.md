# PALACO INDUSTRIE — Independently Pinned Third Witness Key History v5.5

**Status: Draft PR #36 / authorization DENY / GO-13 HOLD. No merge or deployment.**

## New verification boundary

`distribution/third-witness-key-history-v5.5.js` introduces a second, independently pinned trust input for the v5.4 third-witness observation: a deterministic SHA-256 hash of a key-history manifest and a separately governed minimum witness sequence+digest. The verifier reads the latest third-party checkpoint, checks it against this minimum, verifies the observed timestamp falls within the selected key epoch, then re-verifies Ed25519 and compares the current external head through the existing v5.4 read-only verifier. The constructor accepts the trusted manifest hash explicitly: callers **must obtain it out of band** from a trusted operator and never compute the pinned value from an untrusted database response.

The manifest commits to the exact namespace, independently retained floor sequence and digest, and each historic observer identity, key ID, activation/end timestamps, Ed25519 SPKI public-key fingerprint and enabled/revoked flags. Key IDs must be unique. Any changed roster, valid-time window, public key, pinned high-watermark or revocation status changes the manifest hash and is rejected. All checkpoints are non-authorizing; there is no signing, automatic repair, replication or release API.

## CI verification

`tests/distribution-third-witness-key-history-v5.5.test.js` covers six groups: valid pinned history, three-database coordinated rollback, substituted key history or floor, wrong historic key epoch, tampered signature/unavailable trust sources and invalid setup. The existing live PostgreSQL three-database integration is extended to verify the third checkpoint at revision 12, deliberately restore both primary and external reference to 11, and then recreate **the third database's witness schema** with a correctly signed older checkpoint at 11. The out-of-band pinned manifest at revision 12 remains unchanged and the verifier must return `THIRD_HISTORY_HIGH_WATER_ROLLBACK` with DENY/HOLD. It also rejects a substituted public key.

## Explicit limitations

- The manifest and its pinned SHA-256 digest are CI-memory fixtures today. **No independent production storage, protected out-of-band distribution, KMS, PKI or authenticated operator custody exists yet.** If an attacker can replace the trusted manifest and the separately pinned hash together, the protection disappears.
- This prototype accepts only one currently pinned manifest. Historical key additions/rotation require an independently reviewed and authenticated manifest replacement. Effective-date revocation is represented by bounded epoch windows and a conservative `revoked=false` requirement; signed, independently witnessed revocation/rotation ceremonies are not implemented.
- The pinned floor detects rollback **below the declared floor**, including a signed alternate checkpoint at the same sequence with a mismatched digest. It does not prevent a colluding third witness from producing an alternate checkpoint **above** the pinned floor without a subsequent independent, immutable observation. No anti-equivocation network or globally consistent transparency log is implemented.
- The three CI databases share one PostgreSQL server/admin. This proves a test-only coordinated restore scenario with an external in-memory pin, not physical fault isolation, disaster recovery independence or independent governance.
- The v5.4 witness and v5.3 archive verifiers are separate read-only components. This v5.5 check is not a global distributed transaction, and is not integrated with any public route or a production authority gate.

**There is no merge, release, installation, production credential, database migration or distribution authorization. `DENY / GO-13 HOLD` remains unconditional.**