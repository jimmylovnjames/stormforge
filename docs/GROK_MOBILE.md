# Grok mobile orchestration

Drive StormForge from the **Grok mobile app** (or any chat client) using natural-language commands.

## How it works

Grok consumer apps cannot reliably register OpenAPI plugins. StormForge therefore exposes:

1. **`POST /api/orchestrate`** — `{ "message": "<command>" }` with header `x-executor-secret`
2. **`GET /api/grok/instructions`** — paste-ready system / project instructions for Grok
3. **`GET /m`** — mobile chat UI that posts the same commands (fallback when Grok cannot HTTP)
4. **`GET /openapi.json`** — schemas for xAI API function-calling / Shortcuts

## Setup in Grok mobile

1. Deploy StormForge (or use your Worker URL).
2. Open `https://<your-worker>/api/grok/instructions` and copy the text.
3. In Grok → **Projects** (or custom instructions), paste that text.
4. Tell Grok your `x-executor-secret` in-chat when you want it to call the API (do not commit secrets).
5. If Grok cannot POST, open `https://<your-worker>/m` on your phone and paste the same commands.

## Command cheat-sheet

Mutating commands **must** include the word `authorized`.

```
help
plan https://target.example authorized program=my-h1 inScope=*.example,target.example
scan https://api.example *.example authorized program=my-h1
dispatch httpx https://target.example authorized program=lab inScope=target.example
status <scanId>
tasks <scanId>
findings <program>
report <program>
audit
```

## Example curl

```bash
curl -sS -X POST "$STORMFORGE_C2_URL/api/orchestrate" \
  -H "content-type: application/json" \
  -H "x-executor-secret: $EXECUTOR_SECRET" \
  -d '{"message":"plan https://httpbin.org authorized program=httpbin-lab inScope=httpbin.org"}'
```

## Safety

- Fail-closed auth on `/api/orchestrate` (same `EXECUTOR_SECRET` as the executor).
- Scope is evaluated before plan / scan / dispatch.
- StormForge never auto-submits to HackerOne / Immunefi / Bugcrowd.
