# StormForge — Grok Operator Runbook

Everything Grok needs to drive StormForge end-to-end. Paste this whole file into
Grok as **Project / Custom Instructions**, or hand it to any agent alongside the
machine-readable schema at `GET {BASE}/openapi.json`.

> **AUTHORIZED TARGETS ONLY.** StormForge never auto-submits to bounty platforms.
> Mutating commands (`plan`, `scan`, `dispatch`) require the literal word
> `authorized` in the message. Never invent authorization; never touch hosts
> outside the user's stated `inScope`.

---

## 1. Connection

- **BASE URL:** `https://stormforge.3ainewzealand.workers.dev` (or the user's own Worker URL).
- **Auth header (all operator/executor calls):** `x-executor-secret: <EXECUTOR_SECRET>`
  The user supplies the secret; never guess it. Passive read endpoints
  (`/api/findings`, `/api/report`, `/api/triage`, `/api/chains`, `/api/checks`, `/api/scan/:id/status`,
  `/api/oast/status`, `/api/oast/results`) do **not** require auth; everything that
  mutates or reveals the audit log does.
- **Content type for POSTs:** `application/json`.

Primary control surface: `POST {BASE}/api/orchestrate` with `{"message":"<command>"}`.
If you cannot make HTTP requests yourself, output the exact `curl` for the user, or
tell them to open `{BASE}/m` (mobile chat UI) and paste the command.

---

## 2. Orchestrate command grammar (`POST /api/orchestrate`)

Body: `{"message":"<command>"}`. Response: `{ "ok": boolean, "text": string, "data"?: any }`.

| Command | Purpose |
|---------|---------|
| `help` | Command cheat-sheet |
| `scan <targets…> authorized program=<id> [platform=<p>] [inScope=a,b] [outOfScope=c]` | Passive scan (Durable Object) |
| `plan <targets…> authorized program=<id> [inScope=…]` | LLM/heuristic attack plan → dispatch executor tasks |
| `dispatch <tool> <target> authorized program=<id> inScope=<host>` | Queue one tool task |
| `status <scanId>` | Passive scan DO progress |
| `tasks <scanId>` | Executor task queue for that scan |
| `findings <program>` | Stored findings (JSON) |
| `report <program>` | Markdown disclosure draft (includes attack chains) |
| `chains <program>` | Correlated attack-chain composites only |
| `audit` | Recent scope/task decisions |

**Rules the parser enforces (so phrase commands accordingly):**
- The word `authorized` MUST be present for `scan` / `plan` / `dispatch`, else the
  command is refused. `authorized=false` anywhere cancels it.
- `program=`, `platform=`, `inScope=`, `outOfScope=`, `scanId=` are `key=value`
  (comma-separated lists, no spaces). `platform` ∈ `hackerone|bugcrowd|immunefi|intigriti|generic` (defaults `generic`).
- Targets are any `http(s)://…` URLs or bare/wildcard hosts (`*.example.com`) in the text.
- Valid tools for `dispatch`: `nmap, nuclei, httpx, subfinder, katana, ffuf, sqlmap, gobuster`.
- If `inScope` is omitted it is derived from the targets/wildcards.

**Examples (send as the `message` value):**
```
help
scan https://api.example.com *.example.com authorized program=my-h1 platform=hackerone
plan https://example.com authorized program=my-h1 inScope=*.example.com,example.com
dispatch httpx https://example.com authorized program=my-h1 inScope=example.com
status 1a2b3c4d-…            # from a prior scan/plan response
tasks 1a2b3c4d-…
findings my-h1
report my-h1
audit
```

**curl form:**
```bash
curl -s -X POST "$BASE/api/orchestrate" \
  -H "x-executor-secret: $SECRET" -H 'content-type: application/json' \
  -d '{"message":"scan https://api.example.com *.example.com authorized program=my-h1"}'
```

---

## 3. Operating loop (what to do, in order)

1. **Start:** `scan …` (passive) or `plan …` (dispatch tools). Both return a `scanId` — remember it.
2. **Passive progress:** `status <scanId>` → phase/probed/findings from the Durable Object.
3. **Active/tool progress:** `tasks <scanId>` → executor queue state. Remote work only
   advances while an **executor is polling** `GET /api/tasks/poll` (see §6). If tasks stay
   `pending`, tell the user their executor isn't running.
4. **Collect:** `findings <program>` (JSON), `report <program>` (Markdown), and
   `chains <program>` (composites).
5. **Prioritize:** `GET {BASE}/api/triage/<program>?format=md&ready=1` → ranked, deduped,
   submit-first queue (severity × confidence × CVSS). This is the "what to file first" view.
   Triage and report also fold correlated **attack chains** (composites like
   source→secret, SSRF→cloud pivot) so escalated narratives rank with raw findings.
6. **Attack chains:** `GET {BASE}/api/chains/<program>` (or `?format=md`) → only the
   derived composites — the "how a hunter would chain these" view. Empty until signals
   co-occur on the same registrable domain.
7. **OAST (if enabled):** after an active scan, `POST {BASE}/api/oast/poll` to correlate
   out-of-band hits, then `GET {BASE}/api/oast/results/<program>`. A hit becomes a
   critical `ssrf-oast-confirmed` finding (also shows in findings/report/triage/chains).

After every action, summarize: the `scanId`, task counts, and the single next step.

---

## 4. Full REST surface (for direct calls / function-calling)

Auth = `x-executor-secret` where noted. `GET {BASE}/openapi.json` is the importable schema.

| Method | Path | Auth | Purpose |
|--------|------|------|---------|
| GET | `/` | – | Dashboard |
| GET | `/m` | – | Mobile chat UI (paste orchestrate commands) |
| GET | `/openapi.json` | – | OpenAPI 3.1 (Grok function-calling import) |
| GET | `/api/grok/instructions` | – | Paste-ready instructions (server-generated) |
| POST | `/api/orchestrate` | ✅ | Natural-language command (see §2) |
| POST | `/api/scan` | –\* | Start passive scan (JSON body, §5) |
| GET | `/api/scan/:id/status` | – | Passive scan DO status |
| POST | `/api/plan-attack` | ✅ | Plan + dispatch tool tasks (JSON body, §5) |
| POST | `/api/tasks/dispatch` | ✅ | Queue one tool task (JSON body, §5) |
| GET | `/api/tasks/poll` | ✅ | Executor leases pending tasks |
| POST | `/api/tasks/complete` | ✅ | Executor submits results (JSON body, §5) |
| GET | `/api/tasks/status/:scanId` | – | Tasks for a scan |
| GET | `/api/findings/:program` | – | Stored findings (JSON) |
| GET | `/api/report/:program` | – | Markdown disclosure (`?submitReady=1`, `?minSeverity=`) |
| GET | `/api/triage/:program` | – | Ranked submit queue (`?format=md`, `?ready=1`, `?limit=N`; includes attack chains) |
| GET | `/api/chains/:program` | – | Correlated attack-chain composites only (`?format=md`) |
| GET | `/api/oast/status` | – | OAST config + tracked-payload counts |
| POST | `/api/oast/poll` | ✅ | Harvest + correlate collaborator interactions |
| GET | `/api/oast/results/:program` | – | Emitted OAST payloads + correlated hits |
| GET | `/api/checks` | – | Registered detection checks |
| GET | `/api/audit` | ✅ | Recent scope/task decisions |

\* `/api/scan` validates scope but is not secret-gated; keep the Worker URL private or
front it with the secret via `/api/orchestrate` for untrusted callers.

---

## 5. Request body shapes

**`POST /api/scan`** (passive):
```json
{
  "scope": {
    "program": "my-h1",
    "platform": "hackerone",
    "inScope": ["*.example.com", "example.com"],
    "outOfScope": ["blog.example.com"],
    "authorized": true,
    "notes": "https://hackerone.com/example/policy"
  },
  "targets": ["https://api.example.com", "https://www.example.com"],
  "extraPaths": ["/custom/path"],
  "scanId": "optional-stable-id"
}
```
Returns `{ "scanId": "...", "status": "running" }`. Max 50 seed targets.

**`POST /api/plan-attack`** (dispatch tools):
```json
{
  "scope": { "program": "my-h1", "platform": "hackerone", "inScope": ["*.example.com"], "outOfScope": [], "authorized": true },
  "targets": ["https://api.example.com"],
  "findings": [ { "checkId": "httpx-tech-detect", "severity": "info", "target": "https://api.example.com", "title": "WordPress", "evidence": "WordPress,PHP" } ]
}
```
`findings` is optional; when present the planner emits finding-driven follow-ups.
Returns `{ scanId, tasksDispatched, plan, source, tasks:[…] }`.

**`POST /api/tasks/dispatch`** (single task): `{ scanId, tool, target, args?, scope, timeoutSec? }`.

**`POST /api/tasks/complete`** (executor only): `{ taskId, result: { exitCode, stdout, stderr, findings[], durationMs, completedAt, timedOut? } }`.

---

## 6. Executor (the "muscle")

Passive checks run in the Worker. Tools (`nmap/nuclei/httpx/subfinder/katana/ffuf/sqlmap/gobuster`)
run on a remote executor that polls the C2. It must be running for `plan`/`dispatch`/hybrid tasks
to progress:
```bash
cd executor/
export STORMFORGE_C2_URL="$BASE"
export EXECUTOR_SECRET="$SECRET"
node executor.mjs           # or: docker build -t stormforge-executor . && docker run …
```
If `tasks <scanId>` shows everything `pending`, the executor isn't polling.

---

## 7. Secrets & environment (deploy-time)

Set via `wrangler secret put <NAME>` (secrets) or `[vars]` in `wrangler.toml`:

| Name | Kind | Purpose |
|------|------|---------|
| `EXECUTOR_SECRET` | secret | Shared secret for operator + executor auth (required in prod) |
| `LLM_PLANNER_ENDPOINT` | var | Grok/xAI (or OpenAI-compatible) chat-completions URL for the planner |
| `LLM_PLANNER_MODEL` | var | e.g. `grok-4` |
| `LLM_PLANNER_API_KEY` | secret | Planner API key (optional; heuristic plan used if unset) |
| `SCAN_MODE` | var | `detect` (passive only) or `hybrid` (passive + dispatch executor) |
| `ACTIVE_TESTING` | var/secret | **RoE-gated.** `true` enables canary active checks (open-redirect, host-header, XSS reflection). OFF by default |
| `OAST_COLLABORATOR_ENDPOINT` | secret | **RoE-gated.** Enables out-of-band SSRF confirmation (see §8) |
| `ALLOW_INSECURE_EXECUTOR` | var | Local dev only — allows missing `EXECUTOR_SECRET`. Never in prod |

To use **Grok as the planner brain**, set `LLM_PLANNER_ENDPOINT` to the xAI chat
completions endpoint, `LLM_PLANNER_MODEL=grok-4`, and `LLM_PLANNER_API_KEY` to your xAI key.

---

## 8. Active testing & OAST (RoE-gated — only when the program permits)

**Gate:** active checks run only when `ACTIVE_TESTING="true"` (or `SCAN_MODE` contains
`active`) **and** the scan's scope is `authorized`. All active probes are GET-only,
scope-checked, rate-limited, and canary-only; host-header probes are cache-busted so no
shared cache is ever poisoned.

- **Open redirect**, **host-header injection**, and **XSS reflection** are confirmed via
  non-resolving / unique canaries and surface as normal findings.
- **JWT exposure** (passive, always on): decodes client-visible JWTs for `alg=none`,
  privileged claims, and path-like `kid` values (replaces the old dumb JWT secret regex).
- **SSRF candidates** (URL/redirect/callback/webhook/file/host params) are tagged
  passively (always on) as `ssrf-candidate` findings and prioritized for OAST.
- **OAST out-of-band confirmation** (DNS + HTTP): set the collaborator secret:
  ```bash
  npx wrangler secret put OAST_COLLABORATOR_ENDPOINT
  ```
  **Value format** (no trailing slash), one of:
  - `https://collab.example.com` → poll `…/poll`, callbacks `<token>.collab.example.com`
  - `https://poll.example.com/base|callback.example.com` → poll `…/base/poll`, callbacks `<token>.callback.example.com`

  **Collaborator must answer** `GET {pollBase}/poll?since=<unix_ms>` with:
  ```json
  { "hits": [ { "host": "<token>.<callbackDomain>", "type": "dns|http|https", "remoteAddress": "203.0.113.10", "timestamp": "2026-01-01T00:00:00Z", "path": "/<token>" } ] }
  ```
  Correlation is by the `<token>` DNS label (or an explicit `id`).

**OAST workflow for Grok:**
```bash
# 1) Run an active scan (canaries injected into SSRF candidates)
curl -s -X POST "$BASE/api/scan" -H 'content-type: application/json' \
  -d '{"scope":{"program":"my-h1","platform":"hackerone","inScope":["*.example.com"],"outOfScope":[],"authorized":true},"targets":["https://api.example.com/fetch?url=x"]}'
# 2) Harvest + correlate interactions (repeat / cron; this is the polling hook)
curl -s -X POST "$BASE/api/oast/poll" -H "x-executor-secret: $SECRET"
# 3) Read results (confirmed SSRF also appears in findings/report/triage)
curl -s "$BASE/api/oast/results/my-h1"
```

---

## 9. Guardrails Grok must always honor

- Refuse and explain if the user omits `authorized` for a mutating command.
- Never add hosts to `inScope` the user didn't authorize; never enable
  `ACTIVE_TESTING`/OAST for a program whose RoE forbids active testing.
- Treat all output as leads: findings are `needsManualReview` until the operator
  verifies. StormForge drafts; the human submits.
- Keep replies short: after each call, report `scanId` / counts / the next command.
