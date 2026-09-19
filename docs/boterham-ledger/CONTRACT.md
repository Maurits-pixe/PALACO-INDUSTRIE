# BOTERHAM Ledger Contract v0.1.0

## Double-entry requirement
The ledger is double-entry. Every committed monetary transaction produces balanced entries. Direct balance mutation is prohibited.

## Lifecycle
PROPOSED → CLASSIFIED → AUTHORIZED → COMMITTED

Exceptional states:
REJECTED, EXPIRED, REVOKED, REVERSED, SUSPENDED.

## Invariants
1. A transaction has exactly one idempotency key within its scope.
2. COMMITTED is the only state that mutates monetary value.
3. Reversal creates new traceable entries; it does not erase history.
4. Expiration is distinct from revocation.
5. Revocation propagates to dependent execution.
6. Every entry identifies currency and currency version.
7. Audit records are append-only wherever technically appropriate.
8. What is signed shall be exactly what is verified.

## Minimum entities
ledger_accounts
ledger_entries
transactions
currencies
currency_versions
audit_events
