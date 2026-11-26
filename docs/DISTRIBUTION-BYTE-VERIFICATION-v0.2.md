# PALACO INDUSTRIE — Byte verification v0.2 (DRAFT)

The byte verifier extends the v0.1 manifest-only assessment without changing its authority boundary.

```js
const { readFileSync } = require('node:fs');
const { verifyDistributionBytes } = require('./distribution/byte-verifier');
const result = verifyDistributionBytes(manifest, readFileSync('/trusted/local/package.zip'));
```

The library **itself performs no filesystem or network I/O**. The caller must supply a `Buffer` or `Uint8Array` that is already obtained from a trusted source. An empty buffer, missing bytes, a size mismatch, a SHA-256 mismatch, or invalid manifest metadata blocks the assessment. The SHA-256 calculation covers precisely the supplied view's bytes.

**Trust limitations:** A matching hash proves consistency against the *provided manifest* only, not authenticity of that manifest, code safety, signature validity, revocation status, or release approval. The caller must retain immutable bytes or reverify immediately before any later consumption. Never treat this output as executable authorization.

Even on a match, results always contain `authorization: DENY`, `go13: HOLD`, `mayPublish: false`, and `mayInstall: false`. No release or installation capability is implemented.

Run: `node --test tests/distribution-manifest-gate.test.js tests/distribution-byte-verifier.test.js`.
