# PALACO INDUSTRIE — Closed-by-Default HTTP Distribution Perimeter v3.3 (DRAFT / HOLD)

## Mounted server integration

`server.js` now routes all `/api/distribution/` requests through `distribution/application-challenge-http.js`, **before** its pre-existing application endpoints. Requests must use an exact canonical POST path, have an authenticated existing session, and pass the existing CSRF check. Unknown paths and methods deny. The request body is not read until after authentication, CSRF and configured-ingress verification.

## Current security posture

**The HTTP server deliberately sets `ingress: null`.** This is intentional: the standalone v3.2 branded ingress and v3.1 checkpoint registry are NOT enabled, because independent signing/anchor/storage credentials are not provisioned or security-reviewed. With a valid session and CSRF token, `/api/distribution/challenges/issue` and `/api/distribution/challenges/consume` return 503 and a DENY/HOLD assessment. They cannot issue/consume production challenges. Absent session gives 401 and failed CSRF gives 403. No request body can create an ingress or bypass this closed state.

## Tests and limitations

`tests/distribution-application-challenge-http.test.js` tests session and CSRF failure, no body reads on denial, 503 for both canonical operations, rejected alternative routes, and rejection of forged ingress objects. These are handler-level tests; a real end-to-end HTTP session test and review of deployment-specific proxy normalization remain necessary.

The existing unrelated Citadel, task, auth and mutation APIs are not changed by this distribution route. None are claimed to use the distribution challenge mechanism. All previous `createDurableChallengeRegistry` and other legacy APIs remain importable as internal library modules. No full-codebase proof of their removal or inaccessibility has been made.

## Next required work

Provide independently secured signing keys, anchor service, PostgreSQL authority credentials, approved server-side pinned receipt roots and an authenticated startup lifecycle. Only after independent review can the server be explicitly configured to use a branded v3.2 ingress, followed by end-to-end HTTP auth/CSRF/routing verification. No implied enablement by environment variable or request parameter is allowed.

Governance remains `authorization=DENY`, `GO-13=HOLD`. No merge, deployment, publication, installation or operational authority grant.
