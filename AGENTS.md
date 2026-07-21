# StormForge

Hybrid C2 + Executor bug-bounty recon & vulnerability detection framework. Scope-guarded and non-destructive. See `README.md` for the product overview and `docs/` for deploy/extend/performance notes.

## Cursor Cloud specific instructions

### Components

- **C2 Worker (required, the "brain")** — TypeScript Cloudflare Worker (`src/`, entry `src/index.ts`). Serves the dashboard, REST API (`/api/*`), passive detection checks, the KV-backed task queue, and the report drafter. This is the primary locally-developable/testable service.
- **Executor (optional, the "muscle")** — zero-dependency Node ESM script at `executor/executor.mjs`. Polls the C2 and runs offensive CLI tools (nmap, nuclei, httpx, subfinder, katana, ffuf, sqlmap, gobuster). These tools are intentionally NOT installed here; the executor is meant for a dedicated VPS/Docker against authorized targets. `node executor/check-tools.mjs` reports which tools are present (expected: 0/8 in this env).

### Commands (all from repo root; standard scripts live in `package.json`)

- Lint/typecheck: `npm run typecheck` (`tsc --noEmit`)
- Tests: `npm test` (Vitest, pure-function unit tests — no network)
- Run the Worker: `npm run dev` (or `npx wrangler dev --ip 127.0.0.1 --port 8787`). Ready on `http://127.0.0.1:8787`.

### Non-obvious notes

- **Local dev needs no Cloudflare account.** `wrangler dev` uses Miniflare to simulate the `STORMFORGE_KV` namespace and the `ScanOrchestrator` Durable Object. The KV `id`/`preview_id` in `wrangler.toml` are ignored locally.
- **Miniflare KV persists across dev-server restarts** under `.wrangler/` (gitignored). Findings/tasks you create during testing stick around. Use a fresh `program` name (or delete `.wrangler/`) to get clean report output.
- **Wrangler 3 vs 4:** the pinned devDependency is wrangler `^3.100`; it prints an out-of-date warning but works fine. Do not upgrade as part of setup.
- **Report drafting requires fully-formed `Finding` objects.** `GET /api/report/:program` (via `draftDisclosure`) iterates `finding.reproduction` and `finding.references`; a finding missing those fields throws `Cannot read properties of undefined (reading 'forEach')`. When simulating executor results via `/api/tasks/complete`, include all required `Finding` fields (see `src/types.ts`).
- **Safe end-to-end smoke test (no external probing):** `POST /api/plan-attack` (or `/api/tasks/dispatch`) only plans + enqueues tasks into KV — it does not touch any target. `/api/tasks/dispatch` returns the `taskId`, so you can call `/api/tasks/complete` directly without polling. The passive `POST /api/scan` and the dashboard "Launch Recon" button DO make live HTTP probes to the seed targets — only use against hosts you are authorized to test.
- **Scope guard is enforced server-side:** targets not matching `scope.inScope` (or matching `outOfScope`) are refused with 403. `scope.authorized` must be `true` or requests are rejected.
- The LLM planner is optional; with `LLM_PLANNER_ENDPOINT` empty it falls back to a deterministic heuristic.
- `src/dashboard-html.ts` is auto-generated from `dashboard/index.html` via `node scripts/build-dashboard.mjs`. Edit the HTML and regenerate; do not hand-edit the generated file.
