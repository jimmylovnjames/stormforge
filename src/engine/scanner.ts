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
import { buildSchemaIdorFollowUps } from '../recon/openapi-extract.js';
import { buildGraphqlIdorFollowUps } from '../recon/graphql-extract.js';
import {
  authSessionConfigured,
  authProbeHeaders,
  DIFF_MARKER_HEADER,
  DIFF_PAIR_HEADER,
} from '../detect/checks/auth-differential.js';
import { DOH_ENDPOINT, parseDohResponse } from '../recon/takeover.js';
import { EMAIL_DNS_MARKER, txtStringsFromDoh } from '../recon/dns-email.js';
import {
  activeTestingEnabled,
  buildOpenRedirectProbes,
  buildHostHeaderProbes,
  buildXssReflectionProbes,
  ACTIVE_MARKER_HEADER,
  ACTIVE_CANARY_HEADER,
  ACTIVE_PARAM_HEADER,
} from '../recon/active-probes.js';
import { auditLog } from '../audit/log.js';
import { oastConfigured, parseCollaborator, newOastToken, buildOastPayload } from '../oast/collaborator.js';
import { OastStore } from '../oast/store.js';
import { detectSsrfCandidates } from '../detect/checks/ssrf-candidate.js';
import type { OastPayload } from '../oast/types.js';
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

  // 6b. OpenAPI IDOR-shaped path materialization (GET-only, scope-gated).
  const schemaIdorUrls = buildSchemaIdorFollowUps(probes, req.scope, 20);
  if (schemaIdorUrls.length) {
    onProgress?.({ phase: 'schema-idor', probed, total: probed + schemaIdorUrls.length, findings: 0 });
    await mapWithConcurrency(schemaIdorUrls, Math.min(4, concurrency), async (url) => {
      const p = await client.probe(url, {
        headers: { origin: PROBE_ORIGIN, accept: 'application/json, text/plain, */*' },
      });
      attachSignals(p);
      probes.push(p);
      probed++;
    });
  }

  // 6c. GraphQL IDOR-shaped Query field materialization (GET-only).
  const gqlIdorUrls = buildGraphqlIdorFollowUps(probes, req.scope, 16);
  if (gqlIdorUrls.length) {
    onProgress?.({ phase: 'graphql-idor', probed, total: probed + gqlIdorUrls.length, findings: 0 });
    await mapWithConcurrency(gqlIdorUrls, Math.min(4, concurrency), async (url) => {
      const p = await client.probe(url, {
        headers: {
          origin: PROBE_ORIGIN,
          accept: 'application/json, application/graphql-response+json',
        },
      });
      attachSignals(p);
      probes.push(p);
      probed++;
    });
  }

  // 6d. Authenticated differential probing (requires SCAN_COOKIE / SCAN_AUTHORIZATION).
  if (authSessionConfigured(env.SCAN_COOKIE, env.SCAN_AUTHORIZATION) && req.scope.authorized) {
    const authHeaders = authProbeHeaders(env.SCAN_COOKIE, env.SCAN_AUTHORIZATION);
    const diffTargets = pickDifferentialTargets(allowed, probes).slice(0, 12);
    if (diffTargets.length) {
      await auditLog(env, {
        action: 'scan.started',
        detail: `Auth differential enabled (${diffTargets.length} URL(s)) — operator session, GET-only`,
        program: req.scope.program,
        meta: { scanId, differential: true, targets: diffTargets.length },
      });
      onProgress?.({ phase: 'auth-differential', probed, total: probed + diffTargets.length * 2, findings: 0 });
      await mapWithConcurrency(diffTargets, Math.min(3, concurrency), async (url) => {
        if (!evaluateScope(url, req.scope).allowed) return;
        const pair = url;
        const unauth = await client.probe(url, {
          headers: { accept: 'application/json, text/html, */*' },
        });
        unauth.headers[DIFF_MARKER_HEADER] = 'unauth';
        unauth.headers[DIFF_PAIR_HEADER] = pair;
        attachSignals(unauth);
        probes.push(unauth);
        probed++;

        const auth = await client.probe(url, {
          headers: { ...authHeaders, accept: 'application/json, text/html, */*' },
        });
        auth.headers[DIFF_MARKER_HEADER] = 'auth';
        auth.headers[DIFF_PAIR_HEADER] = pair;
        attachSignals(auth);
        probes.push(auth);
        probed++;
      });
    }
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

  // 7c. RoE-GATED active checks (canary open-redirect + host-header). OFF unless
  //     ACTIVE_TESTING=true / SCAN_MODE contains "active" AND scope authorized.
  if (activeTestingEnabled(env, req.scope)) {
    const activeBases = pickActiveBaseUrls(allowed, probes).slice(0, 6);
    await auditLog(env, {
      action: 'scan.started',
      detail: `ACTIVE testing enabled (${activeBases.length} base URL(s)) — canary, non-destructive`,
      program: req.scope.program,
      meta: { scanId, active: true, bases: activeBases.length },
    });

    const redirectProbes = buildOpenRedirectProbes(activeBases, 12);
    if (redirectProbes.length) {
      onProgress?.({ phase: 'active-open-redirect', probed, total: probed + redirectProbes.length, findings: 0 });
      await mapWithConcurrency(redirectProbes, Math.min(4, concurrency), async ({ url, param }) => {
        if (!evaluateScope(url, req.scope).allowed) return;
        const p = await client.probe(url, { redirect: false });
        p.headers[ACTIVE_MARKER_HEADER] = 'open-redirect';
        p.headers[ACTIVE_PARAM_HEADER] = param;
        attachSignals(p);
        probes.push(p);
        probed++;
      });
    }

    const hostProbes = buildHostHeaderProbes(activeBases, 8);
    if (hostProbes.length) {
      onProgress?.({ phase: 'active-host-header', probed, total: probed + hostProbes.length, findings: 0 });
      await mapWithConcurrency(hostProbes, Math.min(4, concurrency), async ({ url, headers, canary }) => {
        if (!evaluateScope(url, req.scope).allowed) return;
        const p = await client.probe(url, { headers, redirect: false });
        p.headers[ACTIVE_MARKER_HEADER] = 'host-header';
        p.headers[ACTIVE_CANARY_HEADER] = canary;
        attachSignals(p);
        probes.push(p);
        probed++;
      });
    }

    const xssProbes = buildXssReflectionProbes(activeBases, 12);
    if (xssProbes.length) {
      onProgress?.({ phase: 'active-xss-reflection', probed, total: probed + xssProbes.length, findings: 0 });
      await mapWithConcurrency(xssProbes, Math.min(4, concurrency), async ({ url, param, canary }) => {
        if (!evaluateScope(url, req.scope).allowed) return;
        const p = await client.probe(url, { redirect: false });
        p.headers[ACTIVE_MARKER_HEADER] = 'xss-reflection';
        p.headers[ACTIVE_PARAM_HEADER] = param;
        p.headers[ACTIVE_CANARY_HEADER] = canary;
        attachSignals(p);
        probes.push(p);
        probed++;
      });
    }

    // 7d. OAST: inject unique canaries into SSRF candidates (param + header
    //     vectors) so blind interactions can be correlated later via /api/oast/poll.
    if (oastConfigured(env)) {
      const cfg = parseCollaborator(env);
      if (cfg) {
        const store = new OastStore(env.STORMFORGE_KV);
        const emissions = buildOastEmissions(collectSsrfCandidateUrls(allowed, probes), 24);
        if (emissions.length) {
          onProgress?.({ phase: 'oast-ssrf', probed, total: probed + emissions.length, findings: 0 });
          let emitted = 0;
          await mapWithConcurrency(emissions, Math.min(4, concurrency), async (em) => {
            if (!evaluateScope(em.requestUrl, req.scope).allowed) return;
            const token = newOastToken();
            const payload = buildOastPayload(cfg, token);
            const record: OastPayload = {
              token,
              url: payload.url,
              host: payload.host,
              scanId,
              program: req.scope.program,
              target: em.target,
              vector: em.vector,
              createdAt: new Date().toISOString(),
            };
            await store.registerPayload(record);
            const requestUrl = em.injectIntoQuery
              ? setParam(em.requestUrl, em.paramName!, payload.url)
              : em.requestUrl;
            const headers = em.header ? { [em.header]: em.headerUsesHost ? payload.host : payload.url } : undefined;
            // Fire-and-forget: the OAST hit (not this response) is the signal.
            await client.probe(requestUrl, { headers, redirect: false }).catch(() => undefined);
            emitted++;
          });
          await auditLog(env, {
            action: 'plan.attack',
            detail: `OAST emitted ${emitted} SSRF canary payload(s)`,
            program: req.scope.program,
            meta: { scanId, oast: true, emitted },
          });
        }
      }
    }
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

/** In-scope base URLs to run active canary checks against (seeds + redirect-prone paths). */
function pickActiveBaseUrls(seedTargets: string[], probes: ProbeResult[]): string[] {
  const bases = new Set<string>();
  for (const t of seedTargets) {
    try {
      const u = new URL(t.includes('://') ? t : `https://${t}`);
      if (u.pathname && u.pathname !== '/') bases.add(`${u.origin}${u.pathname}`);
      bases.add(`${u.origin}/`);
    } catch {
      /* skip */
    }
  }
  for (const p of probes) {
    if (bases.size >= 12) break;
    if (p.error || p.status < 200 || p.status >= 400) continue;
    try {
      const u = new URL(p.finalUrl ?? p.url);
      if (/login|logout|redirect|sso|oauth|auth|account|return|continue/.test(u.pathname.toLowerCase())) {
        bases.add(`${u.origin}${u.pathname}`);
      }
    } catch {
      /* skip */
    }
  }
  return [...bases];
}

/** Auth surfaces worth dual-probing when SCAN_COOKIE / SCAN_AUTHORIZATION is set. */
function pickDifferentialTargets(seedTargets: string[], probes: ProbeResult[]): string[] {
  const out: string[] = [];
  const seen = new Set<string>();
  const consider = (raw: string) => {
    try {
      const u = new URL(raw.includes('://') ? raw : `https://${raw}`);
      const path = u.pathname.toLowerCase();
      const interesting =
        path === '/' ||
        path === '/api' ||
        /\/(?:api|v\d+|graphql|me|profile|account|settings|dashboard|users?|orders?|admin)(?:\/|$)/i.test(path) ||
        /[?&]query=/.test(u.search);
      if (!interesting) return;
      u.hash = '';
      const href = u.toString();
      if (seen.has(href)) return;
      seen.add(href);
      out.push(href);
    } catch {
      /* skip */
    }
  };
  for (const t of seedTargets) consider(t);
  for (const p of probes) {
    if (out.length >= 16) break;
    if (p.error || p.status === 0) continue;
    // Prefer schema-idor / graphql-idor follow-ups already probed.
    if ((p.headers['x-stormforge-diff'] ?? '')) continue;
    consider(p.finalUrl ?? p.url);
  }
  return out;
}

interface OastEmission {
  /** The endpoint being tested (for the payload record). */
  target: string;
  /** Vector label, e.g. "param:url" or "header:Referer". */
  vector: string;
  /** URL the probe is sent to (param injected at emit time, or base for headers). */
  requestUrl: string;
  injectIntoQuery: boolean;
  paramName?: string;
  header?: string;
  /** When true the header carries the bare callback host (not the full URL). */
  headerUsesHost?: boolean;
}

/** URLs (seeds + probed) that expose SSRF-candidate params, with their params. */
function collectSsrfCandidateUrls(
  seedTargets: string[],
  probes: ProbeResult[],
): Array<{ url: string; params: string[] }> {
  const map = new Map<string, Set<string>>();
  const consider = (u: string) => {
    const cands = detectSsrfCandidates(u);
    if (!cands.length) return;
    const set = map.get(u) ?? new Set<string>();
    for (const c of cands) set.add(c.param);
    map.set(u, set);
  };
  for (const t of seedTargets) consider(t.includes('://') ? t : `https://${t}`);
  for (const p of probes) {
    if (p.error) continue;
    consider(p.finalUrl ?? p.url);
  }
  return [...map.entries()].map(([url, set]) => ({ url, params: [...set] }));
}

/** Plan OAST emissions: per-param injections first, then a few header vectors. */
function buildOastEmissions(
  candidates: Array<{ url: string; params: string[] }>,
  cap: number,
): OastEmission[] {
  const out: OastEmission[] = [];
  for (const c of candidates) {
    for (const param of c.params) {
      if (out.length >= cap) return out;
      out.push({ target: c.url, vector: `param:${param}`, requestUrl: c.url, injectIntoQuery: true, paramName: param });
    }
  }
  // Header-based SSRF vectors on distinct in-scope origins (bounded).
  const origins = new Set<string>();
  for (const c of candidates) {
    try {
      origins.add(`${new URL(c.url).origin}/`);
    } catch {
      /* skip */
    }
  }
  const HEADER_VECTORS: Array<{ header: string; usesHost?: boolean }> = [
    { header: 'referer' },
    { header: 'x-original-url' },
    { header: 'x-forwarded-for', usesHost: true },
  ];
  for (const origin of [...origins].slice(0, 3)) {
    for (const hv of HEADER_VECTORS) {
      if (out.length >= cap) return out;
      out.push({ target: origin, vector: `header:${hv.header}`, requestUrl: origin, injectIntoQuery: false, header: hv.header, headerUsesHost: hv.usesHost });
    }
  }
  return out;
}

function setParam(url: string, name: string, value: string): string {
  try {
    const u = new URL(url);
    u.searchParams.set(name, value);
    return u.toString();
  } catch {
    return url;
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
