# Security verification, 2026-11-16

Synthetic regression tests use Node 24's TypeScript erasure and mocks; they never access production, DNS, WhatsApp or patient/client data.

Run `node scripts/tests/security-regression.mjs` and `node scripts/tests/socket-regression.mjs`.

Verified: private IP variants, connection DNS pinning, body-read deadline, byte limit, media local-path rejection, URL credential rejection, anonymous socket rejection, own versus other tenant/session rooms through mocked authorization.

Not verified: live NextAuth cookies and chunked cookies, database-backed authorization, actual WhatsApp payload delivery, deployed revision. `npm ci --ignore-scripts` fails on the preexisting lockfile mismatch (openapi-types, tree-sitter and tree-sitter-json). An isolated npm install (without changing the lockfile), existing patch-package, Prisma generation, typecheck and Next.js build completed. CI reproducibility via npm ci remains blocked. These mocks are not end-to-end tests.

Compatibility: private/internal HTTP webhook destinations and redirects are now rejected. Existing deployments relying on private webhook endpoints need a separately reviewed explicit destination design, not a blanket SSRF bypass. Media downloads use an independently pinned HTTP request and do not forward caller credentials.

Additional checks: HTTP status 600 safely rejected; background media guard wiring checked; current DB role used rather than stale JWT role. JWT chunks reassembled. Existing already-joined socket rooms are not immediately evicted when access is revoked; this remains a lifecycle limitation requiring explicit design.
