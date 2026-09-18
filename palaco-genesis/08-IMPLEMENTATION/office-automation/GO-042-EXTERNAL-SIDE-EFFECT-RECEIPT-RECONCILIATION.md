# ∆ GO-042 — External Side-Effect Receipt + Reconciliation

## Purpose

Make the external network boundary explicit and durable.

An external operation can produce three materially different observations:

- `ACCEPTED`: the external system confirms acceptance;
- `REJECTED`: the external system explicitly rejects the operation;
- `UNKNOWN`: no definitive result is available.

## Canonical rule

`UNKNOWN ≠ SUCCESS`

A timeout, transport interruption, or lost response must never be projected as `COMPLETED`.

## Receipt

Every receipt retains:

- execution identity;
- trace identity;
- external system;
- external reference when available;
- observed outcome;
- exact signed-request digest;
- observation timestamp.

An accepted outcome without an external reference is rejected by the contract.

## Reconciliation

`ACCEPTED → CONFIRMED`

`REJECTED → REJECTED`

`UNKNOWN → PENDING`

Unknown state remains recoverable and can be reconciled later. Reconciliation does not grant authority and does not itself execute a new external action.

## Constitutional boundary

`RECEIPT ≠ AUTHORIZATION`

`RECONCILIATION ≠ EXECUTION`

`UNKNOWN ≠ SUCCESS`

`EXTERNAL ACCEPTANCE ≠ LOCAL ASSUMPTION`

## Verification status

Added Rust contract, PostgreSQL schema, and implementation documentation.

No live PostgreSQL integration run is claimed.
