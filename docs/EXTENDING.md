# Extending StormForge

The whole detection layer is a list of `Check`s. A check is a **pure function of one HTTP response** — no I/O, no mutation, deterministic. That makes checks trivial to add and to unit-test.

## Add a detection check

1. Create `src/detect/checks/my-check.ts`:

```ts
import type { Check, Finding, ProbeResult } from '../../types.js';
import { makeFindingId } from '../../findings/id.js';

export const myCheck: Check = {
  id: 'my-check',
  title: 'Descriptive title',
  cwe: 'CWE-000',
  run(probe: ProbeResult): Finding[] {
    if (probe.error) return [];
    // inspect probe.status / probe.headers / probe.body ...
    const isVulnerable = /* your passive condition */ false;
    if (!isVulnerable) return [];

    return [{
      id: makeFindingId(this.id, probe.url, 'evidence-key'),
      checkId: this.id,
      title: 'What was found',
      severity: 'medium',
      target: probe.url,
      description: '...',
      evidence: `URL: ${probe.url}\n...`,
      reproduction: ['curl ...', 'observe ...'],
      remediation: '...',
      cwe: 'CWE-000',
      references: ['https://...'],
      needsManualReview: true,   // true = candidate needing human confirmation
      discoveredAt: new Date().toISOString(),
    }];
  },
};
```

2. Register it in `src/detect/registry.ts`:

```ts
import { myCheck } from './checks/my-check.js';
const REGISTRY: Check[] = [ /* ...existing..., */ myCheck ];
```

3. Add a test in `test/checks.test.ts`. Because checks are pure, you just hand them a fabricated `ProbeResult`.

### Rules for a good check

- **Passive only.** Read the response; never craft state-changing or injection requests.
- **Confirm before flagging** where possible (body signature, not just status) to keep false positives low.
- Set `needsManualReview: true` for anything version-based or inference-based.
- Redact secrets in `evidence` (see `src/recon/secrets.ts` `redact()`).

## Add recon paths

Extend `SENSITIVE_PATHS` / `API_PROBE_PATHS` in `src/recon/wordlists.ts`, or pass `extraPaths` in a scan request. Keep it high-signal, not a brute-force dictionary.

## Wire a real CVE feed

`src/detect/checks/version-cve.ts` ships a small illustrative advisory table. To use a real feed:

- Periodically pull an advisory source (e.g. OSV, NVD) into KV via a Cron Trigger.
- Replace the static `ADVISORIES` array with a KV lookup keyed by product.
- Keep `compareVersions` (in `src/util/semver.ts`) for the affected-range logic.

## Extension points for other target classes

The `Check` interface is target-class agnostic. Planned/pluggable modules:

- **Cloud / infra:** add checks that fingerprint exposed buckets (probe well-known object-listing URLs within scope), TLS/DNS misconfig, and leaked keys (reuse the secret scanner). Same passive discipline.
- **Web3 / Immunefi:** this repo's HTTP-response model doesn't fit on-chain analysis directly. Add a sibling `src/chain/` module that pulls verified contract source (e.g. via a block explorer API) and runs static pattern checks (reentrancy, missing access control) that emit the same `Finding` shape, so findings flow through the existing store + report drafter. Keep it read-only.

## Add a report platform flavor

`src/report/drafter.ts` maps `scope.platform` to a label and impact wording. Add a case to `platformLabel` (and any platform-specific section ordering you want) — findings and drafts remain otherwise identical.

## Architecture at a glance

```
Request ─► index.ts (router, scope gate, validation)
             └─► ScanOrchestrator (Durable Object, one per scan)
                   └─► engine/scanner.ts
                         ├─ scope-guard   (refuse out-of-scope)
                         ├─ http-client   (rate-limited safe probes)
                         ├─ planning      (advisory path re-ranking)
                         ├─ detect/registry ─► pure Checks ─► Finding[]
                         └─ findings/store (KV dedupe + persist)
                   status ◄── dashboard polls
report ◄── report/drafter (Markdown, per platform)
```
