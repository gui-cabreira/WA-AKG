# Security verification, 2026-11-16

Tests: `node scripts/tests/security-regression.mjs` and `node scripts/tests/socket-regression.mjs` (Node 24 TypeScript erasure, mocked network/DB/timers, no production or real WhatsApp messages).

Passed: DNS pinning, private IP variants, body deadline, byte limit, local path rejection, invalid HTTP status, background-media guard wiring; anonymous rejection, foreign room rejection, chunked JWT, stale role, deleted user, already-joined shared-room revocation, API-key rotation, demotion, JWT expiry, DB failure/hang, lease expiry and timer cleanup.

Socket authorization refreshes every 5 seconds. Checks have a 5-second deadline; existing authorization expires after at most 15 seconds without renewal. Revocation is bounded rather than instantaneous and depends on normal event-loop scheduling. A failed or timed-out check disconnects the socket. Tests use fake timers, not real deployment load.

Prisma generation, complete TypeScript check and Next.js production build passed. Core `security.ts` and `socket.ts` lint passed. Full repository lint still reports 319 errors and 178 warnings and is NOT green. Avoid disabling lint rules to hide these.

The preexisting npm lock mismatch was repaired (peer dependency placement including tree-sitter/openapi-types), preserving platform libc metadata. A fresh isolated `npm ci --ignore-scripts` passed. Existing patch-package was separately applied before the build. Package lifecycle scripts are not generally executed by that clean-install check.

Not verified: real identity-provider cookies, DB-backed end-to-end isolation, live WhatsApp delivery, cloud CI, active deployment or retroactive exposure. Private/internal webhook destinations and redirects are rejected; deployments relying on private endpoints need an explicit reviewed destination design, not blanket SSRF bypass.
