# Performance & cost

Rough, order-of-magnitude figures for planning. Actual numbers depend on target latency and your `MAX_RPS` / `MAX_CONCURRENCY` settings.

## Throughput

- **Probe cost:** one safe HTTP request + a handful of pure regex checks (sub-millisecond CPU per probe; the response fetch dominates wall-clock).
- **Default probes per seed host:** ~30 sensitive paths + ~8 API paths + a few planner suggestions ≈ **40 probes/host**.
- **Rate limiting is the governor.** At the default `MAX_RPS=5`, a single seed host (~40 probes) completes in roughly **8–12 s** including target latency. With 10 seed hosts (~400 probes): **~80–100 s**.
- Raising `MAX_RPS` scales throughput linearly until you hit target-side limits or program rate rules — **keep it polite**. `MAX_CONCURRENCY` (default 8) caps in-flight requests so you don't burst past the rate limiter.

## Cloudflare limits & fit

- **Workers CPU:** checks are pure regex over a ≤512 KB body cap; CPU per request is negligible and stays well under Workers limits.
- **Durable Objects:** one DO instance per scan. `waitUntil` runs the scan off the request path; the dashboard polls `/status`. Scans are I/O-bound (awaiting fetches), not CPU-bound, so a single DO comfortably drives a scan.
- **KV:** one write per finding + one index write per batch. For a program with hundreds of findings this is a few hundred writes — trivially within free/paid tiers. Reads on report assembly are one-per-finding; batch or cache if a program grows to thousands.
- **Body cap (512 KB)** bounds memory and decode cost per probe.

## Cost

For typical bug-bounty use (a handful of scans/day):

- **Workers + DO + KV:** effectively free-tier to cents/month. Requests and DO invocations are low; the free tier covers exploratory use.
- **Advisory LLM planner (optional):** one small `chat/completions` call per scan, ~1–2 K tokens. With a mini-class model that's a fraction of a cent per scan. Disabled by default (heuristic fallback = $0).
- **Cost-aware routing:** the LLM is used *only* for planning (path prioritization) — never per-probe — so LLM spend is O(scans), not O(probes).

## Optimization notes

- **Cold start:** the Worker imports are small and tree-shaken; no heavy deps. First request is fast.
- **Dedup by stable ID** avoids re-storing findings across repeat scans of the same asset.
- **Concurrency vs. politeness:** the token-bucket limiter is shared across the whole scan, so concurrency never exceeds your configured RPS regardless of `MAX_CONCURRENCY`.
- **Scaling out:** because each scan is an isolated DO, many programs can scan in parallel without contention — throughput scales with the number of concurrent DOs, each still rate-limited individually.
