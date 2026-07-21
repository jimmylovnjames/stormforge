#!/usr/bin/env bash
# End-to-end example: plan + execute against an AUTHORIZED test target (httpbin.org).
#
# Prerequisites:
#   - Worker running locally: ALLOW_INSECURE_EXECUTOR=true EXECUTOR_SECRET=devsecret npx wrangler dev
#   - Tools installed on PATH (at least httpx). See executor/INSTALL.md
#
# Usage:
#   chmod +x scripts/e2e-httpbin-example.sh
#   export STORMFORGE_C2_URL=http://localhost:8787
#   export EXECUTOR_SECRET=devsecret
#   ./scripts/e2e-httpbin-example.sh

set -euo pipefail

C2="${STORMFORGE_C2_URL:-http://localhost:8787}"
SECRET="${EXECUTOR_SECRET:?EXECUTOR_SECRET is required}"

echo "==> Dispatching httpx-only plan against authorized httpbin.org"
curl -sS -X POST "$C2/api/plan-attack" \
  -H "content-type: application/json" \
  -H "x-executor-secret: $SECRET" \
  -d '{
    "scope": {
      "program": "httpbin-lab",
      "platform": "generic",
      "inScope": ["httpbin.org"],
      "outOfScope": [],
      "authorized": true,
      "notes": "Local lab — httpbin.org used as intentional authorized test target"
    },
    "targets": ["https://httpbin.org"],
    "findings": []
  }' | tee /tmp/stormforge-plan.json

echo ""
echo "==> Start executor in another terminal:"
echo "    STORMFORGE_C2_URL=$C2 EXECUTOR_SECRET=$SECRET node executor/executor.mjs"
echo ""
echo "==> Or dispatch a single httpx task:"
curl -sS -X POST "$C2/api/tasks/dispatch" \
  -H "content-type: application/json" \
  -H "x-executor-secret: $SECRET" \
  -d '{
    "scanId": "httpbin-demo",
    "tool": "httpx",
    "target": "https://httpbin.org",
    "args": { "flags": "-silent -status-code -title -tech-detect -json" },
    "scope": {
      "program": "httpbin-lab",
      "platform": "generic",
      "inScope": ["httpbin.org"],
      "outOfScope": [],
      "authorized": true
    },
    "timeoutSec": 60
  }'
echo ""
echo "==> After executor runs: GET $C2/api/findings/httpbin-lab and GET $C2/api/audit"
