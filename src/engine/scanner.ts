// The scan engine: turns a ScanRequest into a ScanReport.
//
// Flow: expand targets -> scope-filter -> bounded-concurrency probe ->
// GraphQL introspection follow-ups -> CORS bypass probes ->
// run checks -> collect + dedupe findings. Entirely non-destructive.

import type { Env, Finding, ProbeResult, ScanReport, ScanRequest } from '../types.js';
import { HttpClient, RateLimiter } from '../recon/http-client.js';
import { partitionByScope, hostOf, evaluateScope } from '../scope/scope-guard.js';
import { SENSITIVE_PATHS, API_PROBE_PATHS } from '../recon/wordlists.js';
import { runChecks } from '../detect/registry.js';
import { PROBE_ORIGIN, corsBypassOriginFor } from '../detect/checks/cors.js';
import { emptySummary } from '../findings/severity.js';
import { planNextPaths } from '../planning/llm-planner.js';
import {
  parseBodySignals,
  buildGraphqlIntrospectionUrl,
  shouldFollowUpGraphqlIntrospection,
} from '../recon/body-parse.js';
import {
  buildCacheDeceptionUrls,
  shouldProbeCacheDeception,
} from '../recon/cache-probes.js';
import { DOH_ENDPOINT, parseDohResponse } from '../recon/takeover.js';
import { EMAIL_DNS_MARKER, txtStringsFromDoh } from '../recon/dns-email.js';
import type { Scope } from '../types.js';

export interface ScanProgress {
  (event: { phase: string; probed: number; total: number; findings: number }): void;
}

export async function runScan(
  req: ScanRequest,
  env: Env,
  onProgress?: ScanProgress,
): Promise<ScanReport> {
  const scanId = (req.scanId && req.scanId.trim()) || crypto.randomUUID();
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
  const plan = await planNextPaths(probes, env, req.scope.program);
  if (plan.suggestedPaths.length) {
    const extraUrls = buildProbeUrls(allowed, plan.suggestedPaths);
    const { allowed: allowedExtra } = partitionByScope(extraUrls, req.scope);
    const fresh = allowedExtra.filter((u) => !probes.some((p) => p.url === u));
    await mapWithConcurrency(fresh, concurrency, async (url) => {
      const p = await client.probe(url, { headers: { origin: PROBE_ORIGIN } });
      attachSignals(p);
      probes.push(p);
      probed++;
      onProgress?.({
        phase: 'plan-probe',
        probed,
        total: allowedUrls.length + fresh.length,
        findings: 0,
      });
    });
  }

  // 4. Safe GraphQL GET introspection follow-ups (cap).
  const gqlFollowUps = buildGraphqlFollowUps(probes).slice(0, 8);
  if (gqlFollowUps.length) {
    onProgress?.({ phase: 'graphql-introspect', probed, total: probed + gqlFollowUps.length, findings: 0 });
    await mapWithConcurrency(gqlFollowUps, Math.min(4, concurrency), async (url) => {
      const p = await client.probe(url, {
        headers: {
          origin: PROBE_ORIGIN,
          accept: 'application/json, application/graphql-response+json, text/html',
        },
      });
      attachSignals(p);
      probes.push(p);
      probed++;
    });
  }

  // 5. CORS subdomain-trust bypass Origins (ends-with registrable domain).
  const corsTargets = pickCorsBypassTargets(probes).slice(0, 6);
  if (corsTargets.length) {
    onProgress?.({ phase: 'cors-bypass-probe', probed, total: probed + corsTargets.length, findings: 0 });
    await mapWithConcurrency(corsTargets, Math.min(4, concurrency), async ({ url, origin }) => {
      const p = await client.probe(url, { headers: { origin } });
      attachSignals(p);
      probes.push(p);
      probed++;
    });
  }

  // 6. Cache deception path suffixes on sensitive surfaces (cap).
  const cacheUrls = buildCacheFollowUps(probes, req.scope).slice(0, 10);
  if (cacheUrls.length) {
    onProgress?.({ phase: 'cache-deception', probed, total: probed + cacheUrls.length, findings: 0 });
    await mapWithConcurrency(cacheUrls, Math.min(4, concurrency), async (url) => {
      const p = await client.probe(url, { headers: { origin: PROBE_ORIGIN } });
      attachSignals(p);
      probes.push(p);
      probed++;
    });
  }

  // 7. DoH takeover lookups for in-scope hosts (cap).
  const dohHosts = pickTakeoverHosts(allowed, probes).slice(0, 8);
  if (dohHosts.length) {
    onProgress?.({ phase: 'takeover-doh', probed, total: probed + dohHosts.length, findings: 0 });
    await mapWithConcurrency(dohHosts, Math.min(4, concurrency), async (host) => {
      const synthetic = await lookupTakeoverDns(host);
      if (synthetic) {
        probes.push(synthetic);
        probed++;
      }
    });
  }

  // 7b. Email-auth (SPF/DMARC) DoH TXT lookups for in-scope apex domains (cap).
  const emailDomains = pickEmailDomains(allowed).slice(0, 5);
  if (emailDomains.length) {
    onProgress?.({ phase: 'email-dns', probed, total: probed + emailDomains.length, findings: 0 });
    await mapWithConcurrency(emailDomains, Math.min(4, concurrency), async (domain) => {
      const synthetic = await lookupEmailDns(domain);
      if (synthetic) {
        probes.push(synthetic);
        probed++;
      }
    });
  }

  // 8. Run detection checks over all probes.
  const dedup = new Map<string, Finding>();
  for (const probe of probes) {
    const findings = runChecks(probe, { scope: req.scope, siblings: probes });
    for (const f of findings) dedup.set(f.id, f);
  }
  const findings = [...dedup.values()];
  onProgress?.({ phase: 'analyze', probed, total: probes.length, findings: findings.length });

  // 9. Assemble report.
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

function attachSignals(probe: ProbeResult): void {
  if (probe.error || !probe.body) return;
  if (probe.status < 200 || probe.status >= 500) return;
  probe.signals = parseBodySignals(probe.body, probe.headers, probe.status);
}

function buildGraphqlFollowUps(probes: ProbeResult[]): string[] {
  const out: string[] = [];
  const seen = new Set<string>();
  for (const p of probes) {
    const signals = p.signals ?? parseBodySignals(p.body, p.headers, p.status);
    if (!shouldFollowUpGraphqlIntrospection(p.url, p.status, signals)) continue;
    try {
      const next = buildGraphqlIntrospectionUrl(p.finalUrl ?? p.url);
      if (seen.has(next) || probes.some((x) => x.url === next)) continue;
      seen.add(next);
      out.push(next);
    } catch {
      /* skip bad URL */
    }
  }
  return out;
}

function pickCorsBypassTargets(probes: ProbeResult[]): Array<{ url: string; origin: string }> {
  const out: Array<{ url: string; origin: string }> = [];
  const seenHost = new Set<string>();
  for (const p of probes) {
    if (p.error || p.status === 0) continue;
    if (p.status < 200 || p.status >= 500) continue;
    let host: string;
    try {
      host = hostOf(p.url);
    } catch {
      continue;
    }
    if (seenHost.has(host)) continue;
    const origin = corsBypassOriginFor(p.url);
    if (!origin) continue;
    const path = (() => {
      try {
        return new URL(p.url).pathname;
      } catch {
        return '/';
      }
    })();
    if (!(path === '/' || path.startsWith('/api') || path.includes('login') || path.includes('graphql'))) {
      continue;
    }
    seenHost.add(host);
    out.push({ url: p.url, origin });
  }
  return out;
}

function buildCacheFollowUps(probes: ProbeResult[], scope: Scope): string[] {
  const out: string[] = [];
  const seen = new Set<string>();
  for (const p of probes) {
    if (!shouldProbeCacheDeception(p)) continue;
    for (const u of buildCacheDeceptionUrls(p.finalUrl ?? p.url)) {
      if (seen.has(u)) continue;
      if (!evaluateScope(u, scope).allowed) continue;
      seen.add(u);
      out.push(u);
    }
  }
  return out;
}

function pickTakeoverHosts(seedTargets: string[], probes: ProbeResult[]): string[] {
  const hosts = new Set<string>();
  for (const t of seedTargets) {
    try {
      hosts.add(hostOf(t));
    } catch {
      /* skip */
    }
  }
  for (const p of probes) {
    try {
      const h = hostOf(p.url);
      // Prefer non-apex subdomains for takeover signal.
      if (h.split('.').length >= 3) hosts.add(h);
    } catch {
      /* skip */
    }
  }
  return [...hosts];
}

async function lookupTakeoverDns(host: string): Promise<ProbeResult | null> {
  try {
    const url = `${DOH_ENDPOINT}?name=${encodeURIComponent(host)}&type=CNAME`;
    const res = await fetch(url, {
      headers: { accept: 'application/dns-json' },
    });
    if (!res.ok) return null;
    const json = (await res.json()) as {
      Status?: number;
      Answer?: Array<{ type: number; data: string }>;
    };
    // Also fetch A if CNAME present — DoH often returns CNAME chain; request A for emptiness.
    const aUrl = `${DOH_ENDPOINT}?name=${encodeURIComponent(host)}&type=A`;
    const aRes = await fetch(aUrl, { headers: { accept: 'application/dns-json' } });
    const aJson = aRes.ok
      ? ((await aRes.json()) as { Status?: number; Answer?: Array<{ type: number; data: string }> })
      : { Status: json.Status, Answer: [] };

    const cnameLookup = parseDohResponse(host, json);
    const aLookup = parseDohResponse(host, aJson);
    const merged = {
      host,
      cname: cnameLookup.cname,
      aRecords: aLookup.aRecords,
      nxdomain: aLookup.nxdomain || cnameLookup.nxdomain,
    };

    return {
      url: `https://${host}/`,
      method: 'GET',
      status: 200,
      headers: { 'x-stormforge-dns': 'takeover-lookup', 'content-type': 'application/json' },
      body: JSON.stringify(merged),
      elapsedMs: 0,
    };
  } catch {
    return null;
  }
}

/** Registrable (apex) domains for in-scope seed targets, de-duplicated. */
function pickEmailDomains(seedTargets: string[]): string[] {
  const domains = new Set<string>();
  for (const t of seedTargets) {
    let host: string;
    try {
      host = hostOf(t);
    } catch {
      continue;
    }
    const parts = host.split('.').filter(Boolean);
    if (parts.length >= 2) domains.add(parts.slice(-2).join('.'));
  }
  return [...domains];
}

/** DoH TXT lookup for SPF (apex) + DMARC (_dmarc) → synthetic email-DNS probe. */
async function lookupEmailDns(domain: string): Promise<ProbeResult | null> {
  try {
    const [spfTxts, dmarcTxts] = await Promise.all([
      dohTxt(domain),
      dohTxt(`_dmarc.${domain}`),
    ]);
    return {
      url: `https://${domain}/`,
      method: 'GET',
      status: 200,
      headers: { 'x-stormforge-dns': EMAIL_DNS_MARKER, 'content-type': 'application/json' },
      body: JSON.stringify({ domain, spfTxts, dmarcTxts }),
      elapsedMs: 0,
    };
  } catch {
    return null;
  }
}

async function dohTxt(name: string): Promise<string[]> {
  const url = `${DOH_ENDPOINT}?name=${encodeURIComponent(name)}&type=TXT`;
  const res = await fetch(url, { headers: { accept: 'application/dns-json' } });
  if (!res.ok) return [];
  const json = (await res.json()) as { Answer?: Array<{ type: number; data: string }> };
  return txtStringsFromDoh(json);
}

/** Expand seed hosts/URLs into concrete probe URLs across the path lists. */
function buildProbeUrls(targets: string[], extraPaths: string[]): string[] {
  const urls = new Set<string>();
  const paths = [...API_PROBE_PATHS, ...SENSITIVE_PATHS, ...extraPaths];
  for (const t of targets) {
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
  const runners = Array.from({ length: Math.min(limit, items.length || 1) }, async () => {
    while (index < items.length) {
      const current = index++;
      await worker(items[current]!);
    }
  });
  await Promise.all(runners);
}

function clampNumber(raw: string, fallback: number, min: number, max: number): number {
  const n = Number(raw);
  if (Number.isNaN(n)) return fallback;
  return Math.max(min, Math.min(max, n));
}
