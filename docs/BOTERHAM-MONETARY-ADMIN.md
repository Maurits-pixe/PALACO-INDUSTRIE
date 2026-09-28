# BOTERHAM — Monetary Administration Blueprint v0.1.0

BOTERHAM is PALACO's administrative control plane for commerce, wallets, monetary instruments, Hotspots and future exchange/banking domains.

## Domains

- PEOPLE / Citadel IDs
- PRODUCTS / ELIXERS / Merchandise
- ORDERS / invoices / refunds
- WALLETS / balances / spending profiles
- CURRENCIES / M.C. / M.C.7 / WORLD currencies
- HOTSPOTS / merchant participation
- LEDGER / transaction lineage
- TREASURY / reserves where applicable
- EXCHANGE / future regulated exchange functions
- BANKING / future regulated banking/payment functions
- COMPLIANCE / authorization evidence
- AUDIT / immutable traceability

## Wallet spending profiles

`PHILANTROOP`, `MESCENICAS`, `MISANTROOP`, `BLANCO`.

`BLANCO` is owner-configurable and may contain an IBAN or another permitted destination reference. Sensitive financial data must be minimized and separately protected.

## Loyalty

The loyalty engine supports configurable duration-based rewards and a maximum ceiling. Every reward rule is versioned and produces an auditable calculation record.

## Administrative separation

BOTERHAM can administer and orchestrate. It cannot grant itself monetary authority. Authorization is issued by the constitutional authorization layer.

## Required transaction states

`PROPOSED → CLASSIFIED → AUTHORIZED → COMMITTED`

Exceptional states:
`REJECTED`, `EXPIRED`, `REVOKED`, `REVERSED`, `SUSPENDED`.

No state transition may silently alter financial value.
