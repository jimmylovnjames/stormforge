# StormForge

Hybrid C2 + Executor bug-bounty recon framework. The **C2 brain** is a Cloudflare
Worker (dashboard + JSON API, KV + a `ScanOrchestrator` Durable Object). The
**executor** (`executor/`) is an optional standalone Node muscle that polls a
live C2 and shells out to offensive tools (nmap, nuclei, httpx, etc.).

## Cursor Cloud specific instructions

### Scope
- The **Worker C2** is the primary, locally-runnable product. `wrangler dev` uses
  Miniflare to simulate KV + Durable Objects, so **no Cloudflare account or login
  is needed** for local dev/test.
- The **executor is intentionally out of scope** for local setup: it requires
  heavy offensive tooling (nmap/nuclei/subfinder/…) and points at a remote C2. It
  is a plain Node script (`node executor/executor.mjs`); run `node executor/check-tools.mjs`
  to see which tools are installed. Do not try to install the offensive toolchain
  just to run the environment.

### Standard commands (see `package.json` / `docs/DEPLOY.md`)
- Install: `npm install` (root only; `executor/` has no dependencies).
- Typecheck / lint: `npm run typecheck` (`tsc --noEmit`).
- Tests: `npm test` (`vitest run`) — pure unit tests, no network.
- Dev server: `npm run dev` (i.e. `npx wrangler dev`), serves on `http://127.0.0.1:8787`.

### Non-obvious notes
- The dev server binds `127.0.0.1:8787`. It runs Miniflare locally; the
  "out-of-date wrangler" warning on startup is harmless.
- `src/dashboard-html.ts` is **auto-generated** from `dashboard/index.html` via
  `node scripts/build-dashboard.mjs`. Edit the HTML, then regenerate — don't hand-edit
  the `.ts` file. The Worker serves the inlined HTML at `GET /`.
- Full C2 loop without the executor: `POST /api/plan-attack` (or `/api/tasks/dispatch`)
  queues tasks in KV → `GET /api/tasks/poll` drains them (acts as the executor) →
  `POST /api/tasks/complete` submits a `ToolTaskResult`. Findings are only stored if
  each `Finding` includes a stable `id` (used as the KV dedupe/index key); results
  with malformed/idless findings report `findingsCount` but won't appear in
  `GET /api/findings/:program`.
- `POST /api/scan` runs the passive-detection path through the `ScanOrchestrator`
  Durable Object and makes **real outbound HTTP probes** to the seed targets.
- Scope guard: requests are rejected (403) unless `scope.authorized === true` and
  every target matches an `inScope` host pattern (`*.example.com` style wildcards).
