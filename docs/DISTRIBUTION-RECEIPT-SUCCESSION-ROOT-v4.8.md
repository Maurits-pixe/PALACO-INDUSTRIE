# PALACO INDUSTRIE — Receipt Succession Independent Root v4.8 (DRAFT / HOLD)

## New read-only capability

`distribution/receipt-succession-verifier.js` reads ordered v4.7 receipt records (sequence, nonce, handoff digest and recipient identity) from the existing receipt registry. It enforces a caller-pinned first sequence, consecutive entries, unique nonces and handoff digests, strict schema, and a domain-separated SHA-256 cumulative hash chain. It compares the complete recomputed head against a high-watermark stored by an independently supplied read-only PostgreSQL query adapter. Missing, stale, forged, malformed, unordered or unreachable evidence fails closed.

`distribution/sql/receipt-succession-anchor-v4.8.sql` is an administrator-provisioned schema for an externally managed receipt-chain root. Its update trigger allows only one higher sequence with a changed digest; DELETE and TRUNCATE are forbidden by triggers. The application verifier exposes no mutation, repair, restore, installation or release operation.

## Tests

`tests/distribution-receipt-succession.test.js` verifies cumulative evidence, replay/truncation detection, digest tampering, missing rows, reordered or duplicated entries, unavailable anchor, malformed data and aborted operations.

`tests/postgres-receipt-succession.test.js` uses **two distinct databases within disposable PostgreSQL 17 CI**. The source stores receipts 11 and 12, while the separately stored root advances from sequence 11 to 12 with the expected cumulative digest. A privileged restore recreates the primary source schema with only receipt 11. The independent root stays at 12: verification must return `RECEIPT_CHAIN_ANCHOR_MISMATCH`, `authorization=DENY`, `go13=HOLD`. Direct attempts to roll back, delete or truncate the independent root are rejected by triggers.

## Assumptions / security limitations

- CI databases are separate databases but **share the same PostgreSQL server, administrators and failure domain**. This is a controlled one-sided restore simulation, not organizational or physical independence. A coordinated restore of both stores can evade detection.
- The receipt chain attests to the order and byte-level identity of **stored receipt metadata**, not independently to the authenticity of Ed25519 signatures. v4.7 verifies the signed handoff and receipt at ingestion, and v4.8 does not reconstruct/reverify historic signatures because the existing v4.7 registry stores only nonce, handoff digest, recipient and sequence. Enriched archival evidence and independent cryptographic signature validation remain future work.
- The first sequence and independent root must be pinned outside the restore/signer domain. No automatic root advancement is provided; independently authorized operators must advance the root after reviewed receipt ingestion.
- Large receipt histories are capped at 10,000 rows in the verifier. Beyond that, a separately proven segmented checkpoint/proof design is needed; do not silently truncate the history.
- A successful result is non-authorizing and observational. The two reads are not a distributed atomic snapshot. A privileged PostgreSQL owner can change schemas/triggers; production requires separately administered infrastructure, private roles, pinned TLS, operator audit and durable backups.
- Existing distribution startup interlock remains `ingress:null`. This module adds no HTTP endpoints, live credentials, production migrations or actual distribution authority.

**Governance:** `authorization=DENY`, `go13=HOLD`. Draft PR #36 only. No merge, release, install, public exposure or deployment.