# PALACO INDUSTRIE — External Signed Transfer Dossier History v5.3 (DRAFT / HOLD)

## Complete external handoff evidence

`distribution/sql/signed-evidence-anchor-dossiers-v5.3.sql` adds an immutable, FK-linked external transfer dossier for every v5.1 receipt. The dossier retains the **complete original issuer handoff payload** and **recipient acknowledgement payload**. The existing `transfer_receipts` table already retains both Ed25519 signatures and their key IDs. Read together, the two rows contain the complete cryptographically signed transfer. The SQL migration also replaces the generic receipt-update trigger with a strict mutation-rejection function for **all UPDATE, DELETE, TRUNCATE** operations on both tables.

The opt-in `createSignedEvidenceAnchorReceiver` now inserts the external head CAS, the unique-nonce receipt and the complete dossier **in one PostgreSQL statement** using dependent data-modifying CTEs. A foreign-key violation, missing dossier table, RLS denial, duplicate nonce or other late-stage failure aborts the complete statement (including the head advance). This does not create a distributed transaction with the separate source archive.

## Independent historic verification

`distribution/external-transfer-history-v5.3.js` provides a **read-only** `createExternalTransferHistoryVerifier` using a separately trusted genesis `(namespace, sequence, SHA-256 digest)` and per-sequence independently supplied historic Ed25519 signer roots. It reads the ordered external transfer receipts LEFT JOINed to full dossiers, verifies consecutive anchor transitions, previous/next digests, unique nonces, recipient binding, and both historic signatures against their original signed acceptance time. The final signed chain head must exactly match the current external high-watermark. Missing dossiers, tampering, stale/rolled-back roots, bad signatures, unavailable trust keys, aborted reads, omitted transfer rows and forked histories fail closed.

All outcomes explicitly remain **non-authorizing** (`authorization=DENY`, `go13=HOLD`; no reconciliation, repair, publish, installation or synchronization). The verifier exposes no write methods. The v5.1 and v5.2 read-side semantics remain independent.

## CI evidence

`tests/distribution-external-transfer-history-v5.3.test.js` covers six groups: complete historical verification, missing or forged dossier/signature, missing/duplicated/forked steps, rolled-back or mismatched root, unavailability/changed trust keys, abort and invalid setup.

The disposable PostgreSQL integration `tests/postgres-signed-evidence-anchor-handoff-v5.1.test.js` is expanded to provision the new sidecar, grant a separate namespace-scoped INSERT+SELECT-only role (no UPDATE/DELETE/DDL), verify persisted complete signed handoff and recipient acknowledgement, and independently reverify the external history. It deliberately denies the dossier INSERT policy before a valid transfer to assert that a **late-stage database rejection leaves both the external head and the receipt ledger unchanged**, restores the CI-only policy for a successful append, blocks subsequent replay and mutation, verifies full external history still survives privileged restoration of the primary source, then destroys the external dossier table and confirms verification fails despite an intact external head.

## Unresolved production boundaries

- The SQL schema is an admin-provisioned **Draft contract**, not an applied production migration. Running the upgraded receiver without the v5.3 external dossier table must fail closed.
- Signature validity is relative to **independently supplied historical keys and revocation state**. Effective-date revocation, separately attested human/operator custody and protected key rotation are still not implemented.
- The initial genesis sequence/root must be pinned independently of the external database and cannot simply be read from an attacker-restorable database. This verifier covers only entries after that pinned start.
- The verifier reads the external head and external dossiers separately, not under an independently certified snapshot. Concurrent normal writes can cause a transient HOLD. The stored receipt has not become an executable release token.
- Both CI logical databases run on **one PostgreSQL 17 instance under the same administrator**. This is not independently secured production custody and cannot detect coordinated compromise or backup rollback of all trust roots.
- The v5.3 opt-in receiver is still a process-local trusted module, not an authenticated network service. Database role credentials and raw writes must remain hidden from general-purpose application processes.

**GO-13 HOLD / authorization DENY. Draft PR #36 only. No merge, deployment, publication, installation, production credentials or automatic repair.**