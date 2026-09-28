# ∆ GO-047 — Administrative Reporting Evidence & Closing Gate

GO-047 introduces a fail-closed evidence gate between reporting and period closure.

## Required evidence

A closing attempt must identify:

- the period;
- reconciliation provenance;
- report provenance;
- unresolved mismatch count;
- unresolved unknown count;
- attributable closing decision.

Ordinary closing requires both unresolved counts to be zero.

## Gate

`OPEN/CLOSING → VERIFY EVIDENCE → CLOSING GATE → CLOSED`

The gate produces durable evidence that the required conditions were checked.
It does not itself create authorization or execute a financial operation.

## Constitutional boundaries

`EVIDENCE ≠ AUTHORIZATION`

`GATE ≠ EXECUTION`

`CLOSING ≠ DELETION`

## Important distinction

A period may not be declared closed merely because a report exists. The
reconciliation evidence and the closing decision must be attributable and
traceable.

Future atomic implementation should lock the period, re-read current
reconciliation state, validate the evidence, persist the gate, and transition
the period in one transaction.

## Status

GO-047 establishes the closing evidence contract and durable gate schema.
No financial transaction, tax filing, or payment execution is introduced.
