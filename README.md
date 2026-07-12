# StormForge

**Hybrid C2 + Executor bug-bounty recon & vulnerability detection framework.**

Cloudflare Workers (brain/C2) + Remote Node.js Executor (muscle).

> **AUTHORIZED TARGETS ONLY.** You are responsible for staying within each program's rules of engagement.

---

## Architecture

```
┌──────────────────────────────────────────────────────────────┐
│  Cloudflare Worker (C2)                                       │
│  • LLM-powered attack surface planner                        │
│  • Passive detection checks (headers, CORS, exposed files)   │
│  • Task queue (KV-backed)                                    │
│  • Findings store + report drafter                           │
│  • Dashboard UI                                              │
└──────────────────────┬───────────────────────────────────────┘
                       │ HTTPS (poll/complete)
┌──────────────────────▼───────────────────────────────────────┐
│  Executor (VPS/Docker)                                        │
│  • Polls C2 for pending tasks                                │
│  • Executes: nmap, nuclei, httpx, subfinder, katana,         │
│    ffuf, sqlmap, gobuster                                    │
│  • Parses output into structured findings                    │
│  • Reports results back to C2                                │
└──────────────────────────────────────────────────────────────┘
```

## Live Worker

**URL:** `https://stormforge.3ainewzealand.workers.dev`

## API Endpoints

| Method | Path | Purpose |
|--------|------|---------|
| GET | `/` | Dashboard |
| POST | `/api/scan` | Start passive scan |
| GET | `/api/scan/:id/status` | Scan progress |
| POST | `/api/plan-attack` | LLM plans attack surface → dispatches tool tasks |
| POST | `/api/tasks/dispatch` | Manually dispatch a single tool task |
| GET | `/api/tasks/poll` | Executor polls for pending tasks |
| POST | `/api/tasks/complete` | Executor submits results |
| GET | `/api/tasks/status/:scanId` | View all tasks for a scan |
| GET | `/api/findings/:program` | Stored findings |
| GET | `/api/report/:program` | Markdown disclosure draft |
| GET | `/api/checks` | Registered passive checks |

## Quick Start

### 1. Plan an attack (dispatches tasks to queue)

```bash
curl -X POST https://stormforge.3ainewzealand.workers.dev/api/plan-attack \
  -H "Content-Type: application/json" \
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

### 3. View findings

```bash
curl https://stormforge.3ainewzealand.workers.dev/api/findings/my-target-h1
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

## License

MIT
