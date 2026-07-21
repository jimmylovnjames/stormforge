// The scan engine: turns a ScanRequest into a ScanReport.
//
// Flow: expand targets -> scope-filter -> bounded-concurrency probe ->
// parse 2xx bodies -> GraphQL introspection follow-ups -> run checks ->
// collect + dedupe findings. Entirely non-destructive (GET/HEAD/OPTIONS only).

import type { Env, Finding, ProbeResult, ScanReport, ScanRequest } from '../types.js';
import { HttpClient, RateLimiter } from '../recon/http-client.js';
import { partitionByScope, hostOf } from '../scope/scope-guard.js';
import { SENSITIVE_PATHS, API_PROBE_PATHS, AUTH_IDOR_PATHS, SECRET_LEAK_PATHS, BRUTEFORCE_PATHS } from '../recon/wordlists.js';
import {
  buildGraphqlIntrospectionUrl,
  parseBodySignals,
  shouldFollowUpGraphqlIntrospection,
} from '../recon/body-parse.js';
import {
  REFLECTION_PATHS,
  buildInjectionProbeUrls,
  shouldProbeInjection,
} from '../recon/injection-probes.js';
import {
  REDIRECT_SSRF_PATHS,
  buildSsrfRedirectProbeUrls,
  shouldProbeSsrfRedirect,
} from '../recon/ssrf-probes.js';
import {
  CMD_EXEC_PATHS,
  buildCommandInjectionProbeUrls,
  shouldProbeCommandInjection,
} from '../recon/command-probes.js';
import {
  LFI_PATHS,
  buildPathTraversalProbeUrls,
  shouldProbePathTraversal,
} from '../recon/path-traversal-probes.js';
import {
  buildHostHeaderVariants,
  shouldProbeHostHeader,
} from '../recon/host-header-probes.js';
import { runChecks } from '../detect/registry.js';
import { PROBE_ORIGIN } from '../detect/checks/cors.js';
import { emptySummary } from '../findings/severity.js';
import { planNextPaths, planPathsFromFindings } from '../planning/llm-planner.js';

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

  // 5. Safe XSS / SSTI canary follow-ups (GET query params only).
  const injectionUrls = collectInjectionFollowUps(probes);
  const { allowed: allowedInjection } = partitionByScope(injectionUrls, req.scope);
  const freshInjection = allowedInjection.filter((u) => !probes.some((p) => p.url === u));
  if (freshInjection.length) {
    await mapWithConcurrency(freshInjection, concurrency, async (url) => {
      const p = await client.probe(url, {
        headers: {
          origin: PROBE_ORIGIN,
          accept: 'text/html, application/xhtml+xml, application/json;q=0.9, */*;q=0.8',
        },
      });
      attachSignals(p);
      probes.push(p);
      probed++;
      onProgress?.({
        phase: 'injection-probe',
        probed,
        total: probes.length,
        findings: 0,
      });
    });
  }

  // 6. Safe open-redirect / SSRF canary follow-ups (in-scope host + url= params).
  const ssrfUrls = collectSsrfRedirectFollowUps(probes);
  const { allowed: allowedSsrf } = partitionByScope(ssrfUrls.map((x) => x.url), req.scope);
  const allowedSsrfSet = new Set(allowedSsrf);
  const freshSsrf = ssrfUrls.filter((x) => allowedSsrfSet.has(x.url) && !probes.some((p) => p.url === x.url));
  if (freshSsrf.length) {
    await mapWithConcurrency(freshSsrf, concurrency, async (item) => {
      const p = await client.probe(item.url, {
        headers: { origin: PROBE_ORIGIN, accept: 'text/html, application/json;q=0.9, */*;q=0.8' },
        // Manual redirects so Location canaries are visible for open-redirect checks.
        redirect: item.mode === 'redirect' ? false : true,
      });
      attachSignals(p);
      probes.push(p);
      probed++;
      onProgress?.({ phase: 'ssrf-redirect-probe', probed, total: probes.length, findings: 0 });
    });
  }

  // 7. Safe command-injection canary follow-ups (;|& echo / id on exec-like paths).
  const cmdUrls = collectCommandInjectionFollowUps(probes);
  const { allowed: allowedCmd } = partitionByScope(cmdUrls, req.scope);
  const freshCmd = allowedCmd.filter((u) => !probes.some((p) => p.url === u));
  if (freshCmd.length) {
    await mapWithConcurrency(freshCmd, concurrency, async (url) => {
      const p = await client.probe(url, {
        headers: { origin: PROBE_ORIGIN, accept: 'text/plain, text/html, application/json;q=0.9, */*;q=0.8' },
      });
      attachSignals(p);
      probes.push(p);
      probed++;
      onProgress?.({ phase: 'command-injection-probe', probed, total: probes.length, findings: 0 });
    });
  }

  // 8. Path traversal / LFI canaries.
  const lfiUrls = collectPathTraversalFollowUps(probes);
  const { allowed: allowedLfi } = partitionByScope(lfiUrls, req.scope);
  const freshLfi = allowedLfi.filter((u) => !probes.some((p) => p.url === u));
  if (freshLfi.length) {
    await mapWithConcurrency(freshLfi, concurrency, async (url) => {
      const p = await client.probe(url, {
        headers: { origin: PROBE_ORIGIN, accept: 'text/plain, text/html, application/octet-stream;q=0.8, */*;q=0.5' },
      });
      attachSignals(p);
      probes.push(p);
      probed++;
      onProgress?.({ phase: 'path-traversal-probe', probed, total: probes.length, findings: 0 });
    });
  }

  // 9. Host / X-Forwarded-Host poisoning probes on a few live roots.
  const hostVariants = collectHostHeaderFollowUps(probes);
  const { allowed: allowedHostUrls } = partitionByScope(
    hostVariants.map((h) => h.url),
    req.scope,
  );
  const allowedHostSet = new Set(allowedHostUrls);
  const freshHost = hostVariants.filter((h) => allowedHostSet.has(h.url));
  if (freshHost.length) {
    await mapWithConcurrency(freshHost, concurrency, async (item) => {
      const p = await client.probe(item.url, {
        headers: { origin: PROBE_ORIGIN, ...item.headers },
        redirect: false,
      });
      attachSignals(p);
      probes.push(p);
      probed++;
      onProgress?.({ phase: 'host-header-probe', probed, total: probes.length, findings: 0 });
    });
  }

  // 10. Run detection checks over all probes.
  const dedup = new Map<string, Finding>();
  for (const probe of probes) {
    for (const f of runChecks(probe, { scope: req.scope, siblings: probes })) {
      dedup.set(f.id, f);
    }
  }

  // 11. Autonomy second pass: findings → more paths → probe → re-check.
  let findings = [...dedup.values()];
  const fromFindings = planPathsFromFindings(findings);
  if (fromFindings.suggestedPaths.length) {
    const extraUrls = buildProbeUrls(allowed, fromFindings.suggestedPaths);
    const { allowed: allowedExtra2 } = partitionByScope(extraUrls, req.scope);
    const fresh2 = allowedExtra2.filter((u) => !probes.some((p) => p.url === u)).slice(0, 40);
    if (fresh2.length) {
      await mapWithConcurrency(fresh2, concurrency, async (url) => {
        const p = await client.probe(url, { headers: { origin: PROBE_ORIGIN } });
        attachSignals(p);
        probes.push(p);
        probed++;
        onProgress?.({
          phase: 'finding-driven-pass',
          probed,
          total: probes.length,
          findings: findings.length,
        });
      });
      for (const probe of probes.slice(-fresh2.length)) {
        for (const f of runChecks(probe, { scope: req.scope, siblings: probes })) {
          dedup.set(f.id, f);
        }
      }
      findings = [...dedup.values()];
    }
  }

  onProgress?.({ phase: 'analyze', probed, total: probes.length, findings: findings.length });

  // 12. Assemble report.
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

/** Build XSS/SSTI canary follow-up URLs from HTML / reflection candidates. */
export function collectInjectionFollowUps(probes: ProbeResult[]): string[] {
  const out = new Set<string>();
  let budget = 24; // hard cap per scan to stay polite
  for (const p of probes) {
    if (budget <= 0) break;
    if (!shouldProbeInjection(p)) continue;
    const base = p.finalUrl ?? p.url;
    // Prefer path without existing injection noise.
    let cleanBase = base;
    try {
      const u = new URL(base);
      u.search = '';
      cleanBase = u.toString();
    } catch {
      /* keep */
    }
    const built = buildInjectionProbeUrls(cleanBase, 2);
    for (const url of [...built.xss, ...built.ssti]) {
      if (budget <= 0) break;
      out.add(url);
      budget--;
    }
  }
  return [...out];
}

export interface SsrfFollowUp {
  url: string;
  mode: 'redirect' | 'ssrf';
}

/** Build open-redirect + SSRF canary follow-ups (capped). */
export function collectSsrfRedirectFollowUps(probes: ProbeResult[]): SsrfFollowUp[] {
  const out: SsrfFollowUp[] = [];
  const seen = new Set<string>();
  let budget = 20;
  for (const p of probes) {
    if (budget <= 0) break;
    if (!shouldProbeSsrfRedirect(p)) continue;
    let cleanBase = p.finalUrl ?? p.url;
    try {
      const u = new URL(cleanBase);
      u.search = '';
      cleanBase = u.toString();
    } catch {
      /* keep */
    }
    const built = buildSsrfRedirectProbeUrls(cleanBase, 2);
    for (const url of built.openRedirect) {
      if (budget <= 0) break;
      if (seen.has(url)) continue;
      seen.add(url);
      out.push({ url, mode: 'redirect' });
      budget--;
    }
    for (const url of [...built.metadata, ...built.loopback]) {
      if (budget <= 0) break;
      if (seen.has(url)) continue;
      seen.add(url);
      out.push({ url, mode: 'ssrf' });
      budget--;
    }
  }
  return out;
}

/** Build command-injection canary follow-ups for exec-like endpoints (capped). */
export function collectCommandInjectionFollowUps(probes: ProbeResult[]): string[] {
  const out = new Set<string>();
  let budget = 18;
  for (const p of probes) {
    if (budget <= 0) break;
    if (!shouldProbeCommandInjection(p)) continue;
    let cleanBase = p.finalUrl ?? p.url;
    try {
      const u = new URL(cleanBase);
      u.search = '';
      cleanBase = u.toString();
    } catch {
      /* keep */
    }
    for (const url of buildCommandInjectionProbeUrls(cleanBase, 2)) {
      if (budget <= 0) break;
      out.add(url);
      budget--;
    }
  }
  return [...out];
}

export function collectPathTraversalFollowUps(probes: ProbeResult[]): string[] {
  const out = new Set<string>();
  let budget = 16;
  for (const p of probes) {
    if (budget <= 0) break;
    if (!shouldProbePathTraversal(p)) continue;
    let cleanBase = p.finalUrl ?? p.url;
    try {
      const u = new URL(cleanBase);
      u.search = '';
      cleanBase = u.toString();
    } catch {
      /* keep */
    }
    for (const url of buildPathTraversalProbeUrls(cleanBase, 2)) {
      if (budget <= 0) break;
      out.add(url);
      budget--;
    }
  }
  return [...out];
}

export function collectHostHeaderFollowUps(
  probes: ProbeResult[],
): Array<{ url: string; headers: Record<string, string>; kind: string }> {
  const out: Array<{ url: string; headers: Record<string, string>; kind: string }> = [];
  const seen = new Set<string>();
  let budget = 12;
  for (const p of probes) {
    if (budget <= 0) break;
    if (!shouldProbeHostHeader(p)) continue;
    // Prefer site roots and login pages.
    let path = '/';
    try {
      path = new URL(p.url).pathname;
    } catch {
      /* keep */
    }
    if (!(path === '/' || path === '/login' || path === '/api' || path.endsWith('/'))) continue;
    let cleanBase = p.finalUrl ?? p.url;
    try {
      const u = new URL(cleanBase);
      u.pathname = path === '/api' ? '/api' : '/';
      u.search = '';
      cleanBase = u.toString();
    } catch {
      /* keep */
    }
    for (const variant of buildHostHeaderVariants(cleanBase)) {
      const key = `${variant.kind}|${variant.url}`;
      if (seen.has(key)) continue;
      seen.add(key);
      out.push(variant);
      budget--;
      if (budget <= 0) break;
    }
  }
  return out;
}

/** Expand seed hosts/URLs into concrete probe URLs across the path lists. */
function buildProbeUrls(targets: string[], extraPaths: string[]): string[] {
  const urls = new Set<string>();
  const paths = [
    ...API_PROBE_PATHS,
    ...BRUTEFORCE_PATHS,
    ...AUTH_IDOR_PATHS,
    ...REFLECTION_PATHS,
    ...REDIRECT_SSRF_PATHS,
    ...CMD_EXEC_PATHS,
    ...LFI_PATHS,
    ...SECRET_LEAK_PATHS,
    ...SENSITIVE_PATHS,
    ...extraPaths,
  ];
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
