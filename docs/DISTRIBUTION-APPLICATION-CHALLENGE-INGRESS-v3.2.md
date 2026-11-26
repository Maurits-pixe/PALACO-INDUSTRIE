# PALACO INDUSTRIE — Application Challenge Ingress v3.2 (DRAFT / HOLD)

## Scope

The existing `server.js` has authentication, session, mutations and task routes but **does not implement the `distribution` challenge endpoints**. This update therefore adds a reusable, standalone application-facing adapter; it is **not mounted** in the running HTTP server and must not be described as a production migration.

`distribution/application-challenge-ingress.js` exports `createApplicationChallengeIngress(db,options)`. Construction exclusively uses `createCheckpointGuardedChallengeRegistry` (v3.1) and fails if independently branded continuity and checkpoint gates are unavailable. It also requires trusted `pinnedReceiptRoots` and `minimumReceiptSequence` from server configuration. These trust properties are never read from incoming requests.

## Dispatch policy

Only `POST /api/distribution/challenges/issue` and `POST /api/distribution/challenges/consume` may be dispatched, with exact minimal request-body keys. Any legacy path, malformed shape, attempted caller-supplied registry, bypass flag, receipt roots, sequence or extra parameter is blocked before touching the database or signing services. `close()` fails closed on all future calls. `issue` may return a challenge after all checks; `consume` may validate one, but authorization flags remain DENY / GO-13 HOLD, with no publication or installation permission.

## Security boundaries

This module is a controlled API boundary, **not** a global proof that direct imports of legacy factories are unreachable. Older modules remain exported for backwards compatibility. Static imports, runtime enforcement and deployment wiring must be independently reviewed before any application uses these routes.

Trusted receipt roots must be provisioned through a reviewed independent process; test-only signing keys or attacker-controlled configuration are not secure. The checkpoint witness and chain anchor are still supplied through an interface rather than a genuinely independent external service. The adapter does not authenticate HTTP users, enforce session/CSRF protections, rate-limit clients or start an HTTP server. These requirements must be implemented and security-reviewed at the actual server boundary.

CI tests cover fail-closed construction, exact routing, unknown and bypass paths, independent checkpoint failure, continuity refusal, closed ingress and enforced receipt trust configuration. No merge, deployment, installation or permission change. `authorization=DENY`, `go13=HOLD`.
