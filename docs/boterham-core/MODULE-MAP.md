# BOTERHAM Module Map v0.1.0

| Module | Responsibility | Production gate |
|---|---|---|
| core | orchestration/contracts | authorization |
| ledger | double-entry monetary state | ledger integrity |
| wallet | owner wallet/profile policy | identity + consent |
| rewards | M.C./M.C.7 reward rules | policy + limits |
| hotspot | contracted merchant flows | contract + scope |
| ieo | currency registry/exchange records | classification + authorization |
| payments | external rails adapters | provider + legal/service review |

## Rule
These modules may be implemented incrementally inside PALACO-INDUSTRIE. Extraction into separate repositories requires an explicit architecture decision; no repository proliferation is assumed.
