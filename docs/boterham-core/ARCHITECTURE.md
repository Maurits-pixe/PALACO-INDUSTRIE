# BOTERHAM Core — Architecture v0.1.0

## Role
BOTERHAM is PALACO's administrative control plane. It orchestrates commerce, wallets, monetary instruments, rewards, HOTSPOT participation, exchange records and compliance evidence.

BOTERHAM does **not** create monetary authority. Authorization remains constitutional and external to administrative convenience.

## Ledger-first invariant
All balance mutations MUST be represented by traceable ledger entries. A balance is a derived state, never an independently editable source of truth.

Minimum transaction properties:
- unique idempotency key
- currency identity and version
- source and destination account
- amount and purpose
- authorization reference
- provenance reference
- UTC timestamp
- lifecycle status
- reversal lineage where applicable

## Core modules
- boterham-core
- boterham-ledger
- boterham-wallet
- boterham-rewards
- boterham-hotspot
- boterham-ieo
- boterham-payments

These are architectural module boundaries first; implementation may remain in the existing repository until extraction is justified by the repository inventory.

## Environments
SANDBOX → PILOT → PRODUCTION

Production monetary execution is fail-closed until classification, authorization, security and operational approval are complete.
