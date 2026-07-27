# StormForge

**Hybrid C2 + Executor bug-bounty recon & vulnerability detection framework.**

Cloudflare Workers (brain/C2) + Remote Node.js Executor (muscle).

> **AUTHORIZED TARGETS ONLY.** You are responsible for staying within each program's rules of engagement.
>
> **Active testing is OFF by default.** Passive checks are always safe/non-destructive. Canary-based active checks (open redirect, host-header reflection) run only when `ACTIVE_TESTING="true"` (or `SCAN_MODE` contains `active`) **and** the scope is authorized — and even then are GET-only, rate-limited, and cache-busted. Enable only for programs whose RoE permits active testing.

---

## Architecture

```
┌──────────────────────────────────────────────────────────────┐
│  Cloudflare Worker (C2)                                       │
│  • LLM-powered attack surface planner                        │
│  • Passive detection (headers, CORS trust bypass, cookies,   │
│    exposed files, OpenAPI/Swagger, GraphQL introspection,    │
│    weak CSP, source maps, secrets, OAuth, authz/IDOR,        │
│    cache deception, subdomain takeover, mixed content /      │
│    missing Subresource Integrity)                            │
│  • Evolved finding→task fan-out (httpx/nuclei/sqlmap/…)      │
│  • Task queue (KV-backed leases)                             │
│  • Findings store + submit-ready report drafter              │
│  • Dashboard + Grok mobile orchestrator (`/m`)               │
└──────────────────────┬───────────────────────────────────────┘
                       │ HTTPS (poll/complete)
┌──────────────────────▼───────────────────────────────────────┐
│  Executor (VPS/Docker)                                        │
│  • Polls C2 for pending tasks                                │
│  • Executes: nmap, nuclei, httpx, subfinder, katana,         │
│    ffuf, sqlmap, gobuster                                    │
│  • Parses tool output into structured findings               │
│  • Reports results back to C2                                │
└──────────────────────────────────────────────────────────────┘
```

## Live Worker

**URL:** `https://stormforge.3ainewzealand.workers.dev`

## API Endpoints

| Method | Path | Purpose |
|--------|------|---------|
| GET | `/` | Dashboard |
| GET | `/m` | Mobile chat UI (Grok companion) |
| GET | `/openapi.json` | OpenAPI for Grok / xAI tools |
| GET | `/api/grok/instructions` | Paste-ready Grok project instructions |
| POST | `/api/orchestrate` | Natural-language orchestrate (auth required) |
| POST | `/api/scan` | Start passive scan |
| GET | `/api/scan/:id/status` | Scan progress |
| POST | `/api/plan-attack` | LLM plans attack surface → dispatches tool tasks |
| POST | `/api/tasks/dispatch` | Manually dispatch a single tool task |
| GET | `/api/tasks/poll` | Executor polls for pending tasks |
| POST | `/api/tasks/complete` | Executor submits results |
| GET | `/api/tasks/status/:scanId` | View all tasks for a scan |
| GET | `/api/findings/:program` | Stored findings |
| GET | `/api/report/:program` | Markdown disclosure draft (includes correlated attack chains) |
| GET | `/api/triage/:program` | Prioritized submit-first queue (JSON; `?format=md`, `?ready=1`, `?limit=N`; includes attack chains) |
| GET | `/api/chains/:program` | Correlated attack-chain composites only (`?format=md`) |
| GET | `/api/oast/status` | OAST config + tracked-payload counts |
| POST | `/api/oast/poll` | Harvest + correlate collaborator interactions (auth required) |
| GET | `/api/oast/results/:program` | Emitted OAST payloads + correlated hits for a program |
| GET | `/api/audit` | Recent scope/task decisions (auth required) |

### Grok mobile

Paste instructions from `/api/grok/instructions` into a Grok Project, or open `/m` on your phone. See [docs/GROK_MOBILE.md](docs/GROK_MOBILE.md).

## Quick Start

### Full scan with executor (authorized targets only)

```bash
# Terminal A — Worker (set a real secret in prod)
export EXECUTOR_SECRET=devsecret
# For local without wrangler secret: also set ALLOW_INSECURE_EXECUTOR=true in wrangler [vars]
npx wrangler dev

# Terminal B — Executor (needs httpx/nuclei/subfinder/katana/ffuf/sqlmap on PATH)
cd executor
export STORMFORGE_C2_URL=http://localhost:8787
export EXECUTOR_SECRET=devsecret
node executor.mjs

# Terminal C — Plan + dispatch (httpbin lab example)
./scripts/e2e-httpbin-example.sh
# or:
curl -sS -X POST "$STORMFORGE_C2_URL/api/plan-attack" \
  -H "content-type: application/json" \
  -H "x-executor-secret: $EXECUTOR_SECRET" \
  -d '{
    "scope": {
      "program": "httpbin-lab",
      "platform": "generic",
      "inScope": ["httpbin.org"],
      "outOfScope": [],
      "authorized": true
    },
    "targets": ["https://httpbin.org"]
  }'
```

Auth is **fail-closed**: without `EXECUTOR_SECRET` (and without `ALLOW_INSECURE_EXECUTOR=true`), poll/complete/plan/dispatch return 401.

### 1. Plan an attack (dispatches tasks to queue)

```bash
curl -X POST https://stormforge.3ainewzealand.workers.dev/api/plan-attack \
  -H "Content-Type: application/json" \
  -H "x-executor-secret: your-secret-here" \
  -d '{
    "scope": {
      "program": "my-target-h1",
      "platform": "hackerone",
      "inScope": ["*.target.com"],
      "outOfScope": ["blog.target.com"],
      "authorized": true,
      "notes": "https://hackerone.com/target/policy"
    },
    "targets": ["https://api.target.com", "https://www.target.com"]
  }'
```

### 2. Run the executor on your VPS

```bash
cd executor/
export STORMFORGE_C2_URL=https://stormforge.3ainewzealand.workers.dev
export EXECUTOR_SECRET=your-secret-here
node executor.mjs
```

### 3. View findings + audit

```bash
curl -H "x-executor-secret: your-secret-here" \
  https://stormforge.3ainewzealand.workers.dev/api/findings/my-target-h1
curl -H "x-executor-secret: your-secret-here" \
  https://stormforge.3ainewzealand.workers.dev/api/audit
curl https://stormforge.3ainewzealand.workers.dev/api/report/my-target-h1
```

## Executor Setup

See `executor/INSTALL.md` for full instructions. Docker recommended:

```bash
cd executor/
docker build -t stormforge-executor .
docker run -d \
  -e STORMFORGE_C2_URL=https://stormforge.3ainewzealand.workers.dev \
  -e EXECUTOR_SECRET=your-secret \
  stormforge-executor
```

## Deploy (Worker)

```bash
npm install
npx wrangler deploy

# Set secrets
npx wrangler secret put EXECUTOR_SECRET
npx wrangler secret put LLM_PLANNER_API_KEY  # optional
```

## OAST (out-of-band SSRF confirmation)

RoE-gated, same switch as active testing. Set the collaborator base as a secret:

```bash
npx wrangler secret put OAST_COLLABORATOR_ENDPOINT
```

**Value format** (one of):

- `https://collab.example.com` — StormForge polls `https://collab.example.com/poll` and callbacks land on `<token>.collab.example.com`.
- `https://poll.example.com/base|callback.example.com` — poll `https://poll.example.com/base/poll`, callbacks on `<token>.callback.example.com` (use when the poll API host differs from the callback domain).

**Collaborator contract** StormForge expects: `GET {pollBase}/poll?since=<unix_ms>` returns JSON:

```json
{ "hits": [
  { "host": "<token>.callback.example.com", "type": "dns|http|https",
    "remoteAddress": "203.0.113.10", "timestamp": "2026-01-01T00:00:00Z", "path": "/<token>" }
] }
```

Correlation is by the `<token>` DNS label (or an explicit `id` field). When active testing is enabled and this secret is set, SSRF candidates receive unique canaries; call `POST /api/oast/poll` (from cron or an autonomous loop) to correlate interactions — a hit raises a submit-ready `ssrf-oast-confirmed` (CWE-918) finding linked to the exact execution, target, and vector.

## License

MIT
