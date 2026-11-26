# PALACO INDUSTRIE — Immutable Distribution Startup Interlock v3.4 (DRAFT / HOLD)

## Goal

Prevent accidental activation of the closed distribution HTTP perimeter by undocumented environment variables or guessed operator release flags.

## What changed

- `distribution/distribution-startup-interlock.js` exports `createDistributionStartupInterlock(environment)` which returns an immutable startup report and `ingress:null`.
- `server.js` constructs the interlock once during startup and feeds its `ingress` to the existing v3.3 HTTP distribution handler; it does not create signing clients, a PostgreSQL pool, a key manager or an independent anchor client.
- If release-looking environment keys such as `PALACO_DISTRIBUTION_ENABLE`, `PALACO_DISTRIBUTION_BYPASS`, `PALACO_GO13_RELEASE`, or `PALACO_AUTHORIZATION` are nonempty, the report records only `UNAUTHORIZED_DISTRIBUTION_STARTUP_OVERRIDE`; it never exposes their values.
- Unit and real HTTP tests confirm neither clean startup nor contradictory release flags activate issue or consume. They remain HTTP 503 after valid session and CSRF, and all governance flags stay DENY/HOLD.

## Security boundary

The interlock is deliberately an **unconditionally closed** gate. It is not an environment-variable-based feature flag and has no runtime unlock method. It provides no external trust anchor service, key storage, identity proof, production issuance, deployment or GO-13 authorization. A future release requires an independently reviewed bootstrap design with protected credentials and attestation that cannot be supplied by an HTTP client or release-looking environment variable.

The interlock does not stop a privileged actor from modifying source code, importing legacy internals or altering a running process. This is a deliberate defense-in-depth startup policy, not an immutable hardware root. Separate supply-chain, review and CI protections remain mandatory.

Draft PR only. No main merge, publication, installation or deployment. All release authorization remains `DENY`; `GO-13 HOLD`.
