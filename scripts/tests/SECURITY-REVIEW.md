# Security verification, 2026-11-16

Tests: `node scripts/tests/security-regression.mjs` and `node scripts/tests/socket-regression.mjs` (Node 24 TypeScript erasure, mocked network/DB/timers, no production or real WhatsApp messages).

Passed: DNS pinning, private IP variants, body deadline, byte limit, local path rejection, invalid HTTP status, background-media guard wiring; anonymous rejection, foreign room rejection, chunked JWT, stale role, deleted user, already-joined shared-room revocation, API-key rotation, demotion, JWT expiry, DB failure/hang, lease expiry and timer cleanup.

Socket authorization refreshes every 5 seconds. Checks have a 5-second deadline; existing authorization expires after at most 15 seconds without renewal. Revocation is bounded rather than instantaneous and depends on normal event-loop scheduling. A failed or timed-out check disconnects the socket. Tests use fake timers, not real deployment load.

Prisma generation, complete TypeScript check and Next.js production build passed. Core `security.ts` and `socket.ts` lint passed. Full repository lint still reports 319 errors and 178 warnings and is NOT green. Avoid disabling lint rules to hide these.

The preexisting npm lock mismatch was repaired (peer dependency placement including tree-sitter/openapi-types), preserving platform libc metadata. A fresh isolated `npm ci --ignore-scripts` passed. Existing patch-package was separately applied before the build. Package lifecycle scripts are not generally executed by that clean-install check.

Not verified: browser login/identity-provider interaction, live WhatsApp delivery, cloud CI, active deployment or retroactive exposure. Private/internal webhook destinations and redirects are rejected; deployments relying on private endpoints need an explicit reviewed destination design, not blanket SSRF bypass.

## Local integrated verification

`node --import tsx scripts/tests/socket-integration.ts` passed against isolated PostgreSQL 18.6 on 127.0.0.1, with the project Prisma schema and actual Socket.IO clients/server and Auth.js encode/decode. Covers two synthetic tenants, wrong/absent credentials, cross-tenant joins/event delivery, signed regular/secure/chunked cookies, stale admin role, revoked sharing, preserved own room, key rotation, JWT expiry and user deletion. Server/database were shut down after testing. No real WhatsApp or production access.

The test refuses non-loopback DATABASE_URL or database names other than `wa_security_test`, and requires AUTH_SECRET starting `synthetic-test`. Prepare the disposable database with Prisma db push, then run. Fixture users are synthetic and cleaned up. The test exercises the socket setup module, not the whole Next.js login browser flow or deployment reverse proxy.
