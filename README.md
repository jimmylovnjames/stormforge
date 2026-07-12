# StormForge

**Scope-guarded, non-destructive bug-bounty recon & vulnerability-detection framework** for Cloudflare Workers + Durable Objects.

StormForge helps you find and cleanly document real vulnerabilities on **assets you are authorized to test**, then drafts submission-ready reports. It is deliberately *passive*: it performs safe `GET`/`HEAD`/`OPTIONS` requests, inspects the responses, and flags issues. It does **not** exploit, weaponize, exfiltrate, evade detection, or touch anything outside the scope you define.

> ⚠️ **Authorized testing only.** You are responsible for staying within each program's rules of engagement. StormForge enforces a scope allowlist on every request, but the authorization is yours to hold.

---

## What it does

| Stage | Module | Behavior |
|-------|--------|----------|
| **Scope guard** | `src/scope/` | Every probe is checked against an in-scope allowlist (with `*.wildcard` + out-of-scope overrides). Out-of-scope = refused before any network I/O. |
| **Recon** | `src/recon/` | Rate-limited probing, passive tech fingerprinting, a conservative sensitive-path wordlist, and redacting secret scanning. |
| **Detection** | `src/detect/` | Pure, unit-tested checks: security headers, exposed files (`.git`/`.env`/backups/actuators), CORS misconfig, insecure cookies, known-CVE version fingerprints. |
| **Findings** | `src/findings/` | Stable-ID dedupe, CVSS severity bands, KV persistence + per-program index. |
| **Reporting** | `src/report/` | Per-finding and full-program Markdown drafts, flavored per platform (HackerOne/Bugcrowd/Immunefi/…). You review and submit. |
| **Planning** | `src/planning/` | *Optional, advisory* LLM that only re-prioritizes which in-scope paths to probe. Degrades to a deterministic heuristic. Never generates or runs exploits. |
| **Orchestration** | `src/do/` | A Durable Object per scan coordinates lifecycle + live progress the dashboard polls. |
| **Dashboard** | `dashboard/index.html` | One-file console: define scope, confirm authorization, launch, watch progress, view findings + report draft. |

Everything the checks do is a **pure function of an HTTP response**, which is why they're fully unit-tested without a network.

## Quick start

```bash
npm install
npm test            # 30 tests, all pure — no network
npm run typecheck
npm run dev         # local Worker at http://127.0.0.1:8787
```

Open `http://127.0.0.1:8787/`, fill in your program scope, tick the authorization box, and launch.

## Deploy

See **[docs/DEPLOY.md](docs/DEPLOY.md)** — creates the KV namespace, wires the Durable Object migration, and deploys. Short version:

```bash
npx wrangler kv namespace create STORMFORGE_KV       # paste the id into wrangler.toml
npx wrangler deploy
# optional advisory planner:
npx wrangler secret put LLM_PLANNER_API_KEY
```

## API

| Method & path | Purpose |
|---|---|
| `GET /` | Dashboard |
| `POST /api/scan` | Start a scan. Refuses if scope isn't `authorized` or any target is out of scope. |
| `GET /api/scan/:id/status` | Live progress + final report |
| `GET /api/findings/:program` | Stored findings for a program |
| `GET /api/report/:program` | Markdown disclosure draft |
| `GET /api/checks` | Registered detection checks |

`POST /api/scan` body:

```json
{
  "scope": {
    "program": "acme-h1",
    "platform": "hackerone",
    "inScope": ["*.acme.com", "api.acme.com"],
    "outOfScope": ["blog.acme.com"],
    "authorized": true,
    "notes": "https://hackerone.com/acme/policy"
  },
  "targets": ["https://api.acme.com", "www.acme.com"]
}
```

## Extending

Add a new detection check in ~20 lines — see **[docs/EXTENDING.md](docs/EXTENDING.md)**. Web3/Immunefi and cloud-infra modules plug into the same `Check` interface; extension points are documented there.

## Design boundaries (what it will never do)

- No active exploitation, fuzzing of injection payloads, or state-changing requests (only `GET`/`HEAD`/`OPTIONS`).
- No requests to hosts outside the declared scope.
- No use, validation, or storage of discovered credentials — secrets are redacted in evidence.
- No auto-submission — every report is drafted for **your** review.

## License

MIT. See `LICENSE`.
