// The scan engine: turns a ScanRequest into a ScanReport.
//
// Flow: expand targets -> scope-filter -> bounded-concurrency probe ->
// parse 2xx bodies -> GraphQL introspection follow-ups -> run checks ->
// collect + dedupe findings. Entirely non-destructive (GET/HEAD/OPTIONS only).

import type { Env, Finding, ProbeResult, ScanReport, ScanRequest } from '../types.js';
import { HttpClient, RateLimiter } from '../recon/http-client.js';
import { partitionByScope, hostOf } from '../scope/scope-guard.js';
import { SENSITIVE_PATHS, API_PROBE_PATHS, AUTH_IDOR_PATHS, SECRET_LEAK_PATHS } from '../recon/wordlists.js';
import {
  buildGraphqlIntrospectionUrl,
  parseBodySignals,
  shouldFollowUpGraphqlIntrospection,
} from '../recon/body-parse.js';
import { runChecks } from '../detect/registry.js';
import { PROBE_ORIGIN } from '../detect/checks/cors.js';
import { emptySummary } from '../findings/severity.js';
import { planNextPaths } from '../planning/llm-planner.js';

export interface ScanProgress {
  (event: { phase: string; probed: number; total: number; findings: number }): void;
}

export async function runScan(
  req: ScanRequest,
  env: Env,
  onProgress?: ScanProgress,
): Promise<ScanReport> {
  const scanId = crypto.randomUUID();
  const startedAt = new Date().toISOString();

  const rps = clampNumber(env.MAX_RPS, 5, 1, 50);
  const concurrency = clampNumber(env.MAX_CONCURRENCY, 8, 1, 32);
  const limiter = new RateLimiter(rps);
  const client = new HttpClient(req.scope, limiter);

  // 1. Build the probe URL set from seed targets + path wordlists, scope-filtered.
  const { allowed } = partitionByScope(req.targets, req.scope);
  const urls = buildProbeUrls(allowed, req.extraPaths ?? []);
  const { allowed: allowedUrls } = partitionByScope(urls, req.scope);

  // 2. Probe with bounded concurrency; attach body signals on 2xx.
  const probes: ProbeResult[] = [];
  let probed = 0;
  await mapWithConcurrency(allowedUrls, concurrency, async (url) => {
    const p = await client.probe(url, { headers: { origin: PROBE_ORIGIN } });
    attachSignals(p);
    probes.push(p);
    probed++;
    onProgress?.({ phase: 'probe', probed, total: allowedUrls.length, findings: 0 });
  });

  // 3. Advisory planning pass: probe a few extra suggested paths (still scope-gated).
  const plan = await planNextPaths(probes, env);
  if (plan.suggestedPaths.length) {
    const extraUrls = buildProbeUrls(allowed, plan.suggestedPaths);
    const { allowed: allowedExtra } = partitionByScope(extraUrls, req.scope);
    const fresh = allowedExtra.filter((u) => !probes.some((p) => p.url === u));
    await mapWithConcurrency(fresh, concurrency, async (url) => {
      const p = await client.probe(url, { headers: { origin: PROBE_ORIGIN } });
      attachSignals(p);
      probes.push(p);
      probed++;
      onProgress?.({ phase: 'plan-probe', probed, total: allowedUrls.length + fresh.length, findings: 0 });
    });
  }

  // 4. Safe GraphQL introspection follow-ups (GET + query param only).
  const introspectionUrls = collectGraphqlFollowUps(probes);
  const { allowed: allowedIntrospection } = partitionByScope(introspectionUrls, req.scope);
  const freshIntrospection = allowedIntrospection.filter((u) => !probes.some((p) => p.url === u));
  if (freshIntrospection.length) {
    await mapWithConcurrency(freshIntrospection, concurrency, async (url) => {
      const p = await client.probe(url, {
        headers: {
          origin: PROBE_ORIGIN,
          accept: 'application/json, application/graphql-response+json, text/html',
        },
      });
      attachSignals(p);
      probes.push(p);
      probed++;
      onProgress?.({
        phase: 'graphql-introspect',
        probed,
        total: allowedUrls.length + freshIntrospection.length,
        findings: 0,
      });
    });
  }

  // 5. Run detection checks over all probes.
  const dedup = new Map<string, Finding>();
  for (const probe of probes) {
    const findings = runChecks(probe, { scope: req.scope, siblings: probes });
    for (const f of findings) dedup.set(f.id, f);
  }
  const findings = [...dedup.values()];
  onProgress?.({ phase: 'analyze', probed, total: probes.length, findings: findings.length });

  // 6. Assemble report.
  const summary = emptySummary();
  for (const f of findings) summary[f.severity]++;

  return {
    scanId,
    program: req.scope.program,
    startedAt,
    finishedAt: new Date().toISOString(),
    targetsProbed: probes.length,
    findings,
    summary,
  };
}

/** Parse body signals for successful responses so checks can use confirmed markers. */
export function attachSignals(probe: ProbeResult): void {
  if (probe.error || !probe.body) return;
  if (probe.status < 200 || probe.status >= 300) {
    // Still parse soft GraphQL hints on 4xx (e.g. "Must provide query string").
    if (probe.status >= 400 && probe.status < 500) {
      probe.signals = parseBodySignals(probe.body, probe.headers, probe.status);
    }
    return;
  }
  probe.signals = parseBodySignals(probe.body, probe.headers, probe.status);
}

/** Build introspection follow-up URLs from candidate probes (deduped). */
export function collectGraphqlFollowUps(probes: ProbeResult[]): string[] {
  const out = new Set<string>();
  for (const p of probes) {
    const signals =
      p.signals ??
      (p.body ? parseBodySignals(p.body, p.headers, p.status) : undefined);
    if (!signals) continue;
    if (!shouldFollowUpGraphqlIntrospection(p.url, p.status, signals)) continue;
    try {
      out.add(buildGraphqlIntrospectionUrl(p.finalUrl ?? p.url));
    } catch {
      /* ignore bad URLs */
    }
  }
  return [...out];
}

/** Expand seed hosts/URLs into concrete probe URLs across the path lists. */
function buildProbeUrls(targets: string[], extraPaths: string[]): string[] {
  const urls = new Set<string>();
  const paths = [...API_PROBE_PATHS, ...AUTH_IDOR_PATHS, ...SECRET_LEAK_PATHS, ...SENSITIVE_PATHS, ...extraPaths];
  for (const t of targets) {
    // If the seed already has a path, probe it directly too.
    if (/^https?:\/\/.+\/.+/.test(t)) urls.add(t);
    let host: string;
    try {
      host = hostOf(t);
    } catch {
      continue;
    }
    const base = `https://${host}`;
    for (const p of paths) urls.add(base + p);
  }
  return [...urls];
}

async function mapWithConcurrency<T>(
  items: T[],
  limit: number,
  worker: (item: T) => Promise<void>,
): Promise<void> {
  let index = 0;
  const runners = Array.from({ length: Math.min(limit, items.length) }, async () => {
    while (index < items.length) {
      const current = index++;
      await worker(items[current]);
    }
  });
  await Promise.all(runners);
}

function clampNumber(raw: string, fallback: number, min: number, max: number): number {
  const n = Number(raw);
  if (Number.isNaN(n)) return fallback;
  return Math.max(min, Math.min(max, n));
}
