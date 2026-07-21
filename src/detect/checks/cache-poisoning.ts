// Unkeyed-header web cache poisoning confirmation (CWE-444).
// Pure: expects a clean GET whose siblings include a poison probe with the same canary.

import type { Check, Finding, ProbeResult } from '../../types.js';
import { makeFindingId } from '../../findings/id.js';
import { hasCacheableResponse } from '../../recon/cache-deception-probes.js';
import {
  CACHE_POISON_CANARY_PREFIX,
  cleanResponseContainsCanary,
  urlCarriesCachePoisonCanary,
} from '../../recon/cache-poison-probes.js';

export const cachePoisoningCheck: Check = {
  id: 'cache-poisoning',
  title: 'Unkeyed-header web cache poisoning',
  cwe: 'CWE-444',
  run(probe: ProbeResult, ctx): Finding[] {
    if (probe.error || !probe.body) return [];
    if (probe.status < 200 || probe.status >= 400) return [];
    // Evaluate the clean (unpoisoned) response.
    if (!hasCacheableResponse(probe.headers)) return [];

    const canaries = findSiblingCanaries(ctx.siblings ?? [], probe.url);
    if (!canaries.length) {
      // Soft: body already contains a StormForge cache-poison canary without siblings.
      if (probe.body.includes(CACHE_POISON_CANARY_PREFIX) && /HIT|age:\s*[1-9]/i.test(JSON.stringify(probe.headers))) {
        return [makeFinding(probe, extractCanary(probe.body) ?? `${CACHE_POISON_CANARY_PREFIX}?`, 'body-only')];
      }
      return [];
    }

    for (const { canary, poison } of canaries) {
      if (!cleanResponseContainsCanary(probe.body, probe.headers, canary)) continue;
      // Prefer cases where poison response also showed the canary (stored) or clean is HIT.
      const cacheHint =
        /hit/i.test(probe.headers['x-cache'] ?? '') ||
        /hit/i.test(probe.headers['cf-cache-status'] ?? '') ||
        Number(probe.headers['age'] ?? '0') > 0;
      if (!cacheHint && !poison.body.includes(canary)) continue;
      return [makeFinding(probe, canary, poison.url)];
    }
    return [];
  },
};

function findSiblingCanaries(
  siblings: ProbeResult[],
  cleanUrl: string,
): Array<{ canary: string; poison: ProbeResult }> {
  const out: Array<{ canary: string; poison: ProbeResult }> = [];
  let cleanOrigin = '';
  let cleanPath = '';
  try {
    const u = new URL(cleanUrl);
    cleanOrigin = u.origin;
    cleanPath = u.pathname;
  } catch {
    return [];
  }
  for (const s of siblings) {
    if (s.url !== cleanUrl && !sameEntry(s.url, cleanOrigin, cleanPath)) continue;
    const marked = s.headers['x-stormforge-poison'];
    if (marked && urlCarriesCachePoisonCanary(marked)) {
      out.push({ canary: marked, poison: s });
      continue;
    }
    // Infer from Location / body of poison response.
    const fromBody = extractCanary(s.body);
    if (fromBody) out.push({ canary: fromBody, poison: s });
  }
  return out;
}

function sameEntry(url: string, origin: string, path: string): boolean {
  try {
    const u = new URL(url);
    return u.origin === origin && u.pathname === path;
  } catch {
    return false;
  }
}

function extractCanary(text: string): string | null {
  const m = text.match(new RegExp(`${CACHE_POISON_CANARY_PREFIX}[a-z0-9]+`, 'i'));
  return m?.[0] ?? null;
}

function makeFinding(probe: ProbeResult, canary: string, poisonRef: string): Finding {
  return {
    id: makeFindingId('cache-poisoning', probe.url, canary),
    checkId: 'cache-poisoning',
    title: 'Unkeyed-header web cache poisoning confirmed',
    severity: 'high',
    target: probe.url,
    description:
      'A clean GET for a cacheable URL reflected an attacker-controlled canary previously injected via an unkeyed header (e.g. X-Forwarded-Host). This confirms web cache poisoning — subsequent visitors can receive attacker-controlled content or redirects.',
    evidence: [
      `Clean URL: ${probe.url}`,
      `Canary: ${canary}`,
      `Poison ref: ${poisonRef}`,
      `Cache-Control: ${probe.headers['cache-control'] ?? '<absent>'}`,
      `X-Cache/CF: ${probe.headers['x-cache'] ?? probe.headers['cf-cache-status'] ?? '<absent>'}`,
      `Age: ${probe.headers['age'] ?? '<absent>'}`,
      `Body preview: ${probe.body.slice(0, 220).replace(/\s+/g, ' ')}`,
    ].join('\n'),
    reproduction: [
      `curl -s -H 'X-Forwarded-Host: ${canary}' '${probe.url}'`,
      `curl -s '${probe.url}'`,
      'Confirm the clean response still contains the canary and cache headers show HIT/Age',
    ],
    remediation:
      'Include unkeyed headers in the cache key (or strip them); do not trust X-Forwarded-Host / X-Original-URL for absolute URLs; disable caching of responses that embed Host-derived values.',
    cwe: 'CWE-444',
    references: [
      'https://cwe.mitre.org/data/definitions/444.html',
      'https://portswigger.net/research/practical-web-cache-poisoning',
    ],
    needsManualReview: true,
    discoveredAt: new Date().toISOString(),
  };
}
