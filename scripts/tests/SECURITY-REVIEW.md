# Security verification, 2026-11-16

Synthetic regression tests use Node 24's TypeScript erasure and mocks; they never access production, DNS, WhatsApp or patient/client data.

Run `node scripts/tests/security-regression.mjs` and `node scripts/tests/socket-regression.mjs`.

Verified: private IP variants, connection DNS pinning, body-read deadline, byte limit, media local-path rejection, URL credential rejection, anonymous socket rejection, own versus other tenant/session rooms through mocked authorization.

Not verified: live NextAuth cookies and chunked cookies, full application build, database-backed authorization, actual WhatsApp payload delivery, deployed revision. `npm ci --ignore-scripts` fails on the preexisting lockfile mismatch (openapi-types, tree-sitter and tree-sitter-json). Full install/build must be completed before merge. These mocks are not end-to-end tests.

Compatibility: private/internal HTTP webhook destinations and redirects are now rejected. Existing deployments relying on private webhook endpoints need a separately reviewed explicit destination design, not a blanket SSRF bypass. Media downloads use an independently pinned HTTP request and do not forward caller credentials.
