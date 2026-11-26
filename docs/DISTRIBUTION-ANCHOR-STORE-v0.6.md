# PALACO INDUSTRIE — Transactional Anchor Store v0.6 (DRAFT)

The module in distribution/anchor-store.js defines a transactional, fail-closed SQLite compare-and-swap advance for already-provisioned trust checkpoints.

**Not trust-on-first-use:** initializeAnchorSchema(db) creates a schema, but does not create an initial anchor. Provision the first anchor only through a separate, independently authenticated administrative channel.

commitVerifiedAnchor(db, namespace, snapshot, checkpoint, endorsement, pinnedRoots) obtains BEGIN IMMEDIATE, reads the existing anchor, validates sequence and hash continuity, verifies an independent Ed25519 checkpoint endorsement, and atomically conditionally updates the anchor. Any failure rolls back. It must not be called from within another transaction.

**Limitations:** SQLite transactional integrity does not prevent replacing or restoring the entire database file. Strong anti-rollback requires separately protected monotonic storage, independently provisioned pinned roots, recovery procedures, and authenticated release approvals. This module advances trust metadata only and does not itself verify package bytes, install software, or publish releases.

Every result always contains authorization DENY, GO-13 HOLD, mayPublish false and mayInstall false. Tests: node --test tests/distribution-anchor-store.test.js.
