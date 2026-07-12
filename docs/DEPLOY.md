# Deploying StormForge

## Prerequisites

- Node 18+ and a Cloudflare account.
- `npx wrangler login` (or a `CLOUDFLARE_API_TOKEN` env var with Workers + KV edit rights).

## 1. Install & verify locally

```bash
npm install
npm test
npm run typecheck
npm run dev      # http://127.0.0.1:8787
```

Local dev uses Miniflare's simulated KV and Durable Objects, so no cloud resources are needed to try it.

## 2. Create the KV namespace

```bash
npx wrangler kv namespace create STORMFORGE_KV
npx wrangler kv namespace create STORMFORGE_KV --preview
```

Copy the returned `id` and `preview_id` into `wrangler.toml`:

```toml
[[kv_namespaces]]
binding = "STORMFORGE_KV"
id = "<id-from-command>"
preview_id = "<preview-id-from-command>"
```

## 3. Durable Object migration

Already declared in `wrangler.toml`:

```toml
[[migrations]]
tag = "v1"
new_classes = ["ScanOrchestrator"]
```

No action needed — `wrangler deploy` applies it on first deploy.

## 4. (Optional) advisory LLM planner

The planner only re-ranks which in-scope paths to probe. Leave it off and StormForge uses a deterministic heuristic.

```toml
# wrangler.toml
[vars]
LLM_PLANNER_ENDPOINT = "https://api.openai.com/v1/chat/completions"
LLM_PLANNER_MODEL = "gpt-4o-mini"
```

```bash
npx wrangler secret put LLM_PLANNER_API_KEY
```

The endpoint just needs to accept an OpenAI-style `chat/completions` JSON body; point it at any compatible gateway (OpenAI, Grok, a Workers AI proxy, etc.).

## 5. Deploy

```bash
npx wrangler deploy
```

Wrangler prints your `*.workers.dev` URL. Open it, define your program scope, confirm authorization, and launch.

## 6. Recommended production hardening

- **Put the Worker behind Cloudflare Access** so only you can reach the dashboard and API.
- Keep `MAX_RPS` conservative (default 5) to respect target infrastructure and program rate limits.
- Review the KV-stored findings periodically; they persist across scans for dedupe.

## Tuning knobs (`[vars]`)

| Var | Default | Meaning |
|-----|---------|---------|
| `MAX_RPS` | `5` | Global probe rate limit (clamped 1–50). |
| `MAX_CONCURRENCY` | `8` | Parallel probes per scan (clamped 1–32). |
| `SCAN_MODE` | `detect` | Passive detection only. There is no active-exploit mode. |
