// HTTP Parameter Pollution detection (CWE-235).
// Pure over ProbeResult + siblings baseline comparison.

import type { Check, Finding, ProbeResult } from '../../types.js';
import { makeFindingId } from '../../findings/id.js';
import {
  HPP_CANARY,
  hasHppBehavioralDelta,
  hasHppCanaryReflection,
  urlCarriesHppPayload,
} from '../../recon/hpp-probes.js';

export const hppCheck: Check = {
  id: 'http-parameter-pollution',
  title: 'HTTP Parameter Pollution (HPP)',
  cwe: 'CWE-235',
  run(probe: ProbeResult, ctx): Finding[] {
    if (probe.error || !probe.body) return [];
    if (!urlCarriesHppPayload(probe.url)) return [];
    if (probe.status < 200 || probe.status >= 500) return [];

    const baseline = findBaselineSibling(probe, ctx.siblings ?? []);
    const canaryHit = hasHppCanaryReflection(probe.body, probe.url);
    const delta = hasHppBehavioralDelta(probe, baseline);

    if (!canaryHit && !delta) return [];

    const severity: Finding['severity'] =
      delta &&
      (/"role"\s*:\s*"admin"|"isAdmin"\s*:\s*true/i.test(probe.body) ||
        (baseline && probe.status !== baseline.status))
        ? 'high'
        : 'medium';

    return [
      {
        id: makeFindingId(this.id, probe.url, canaryHit ? 'canary' : 'delta'),
        checkId: this.id,
        title: canaryHit
          ? 'HTTP Parameter Pollution — duplicate param value accepted'
          : 'HTTP Parameter Pollution — behavioral delta vs single-param baseline',
        severity,
        target: probe.url,
        description:
          'Duplicate query parameters produced a different backend interpretation (canary reflection and/or response delta vs the single-param baseline). HPP can enable auth bypass, WAF evasion, or inconsistent access-control decisions.',
        evidence: [
          `Polluted URL: ${probe.url}`,
          `Status: ${probe.status}`,
          `Canary (${HPP_CANARY}) reflected: ${canaryHit}`,
          `Baseline URL: ${baseline?.url ?? '<none>'}`,
          `Baseline status: ${baseline?.status ?? '<n/a>'}`,
          `Behavioral delta: ${delta}`,
          `Body preview: ${preview(probe.body)}`,
        ].join('\n'),
        reproduction: [
          baseline
            ? `curl -s '${baseline.url}'`
            : `curl -s '${stripDuplicate(probe.url)}'`,
          `curl -s '${probe.url}'`,
          'Compare status, identity fields, and privilege markers — do not modify data',
        ],
        remediation:
          'Normalize query parsing: reject duplicate parameters, or explicitly define first-wins/last-wins and validate a single authoritative value server-side before authorization.',
        cwe: 'CWE-235',
        references: [
          'https://cwe.mitre.org/data/definitions/235.html',
          'https://owasp.org/www-community/attacks/HTTP_Parameter_Pollution',
        ],
        needsManualReview: true,
        discoveredAt: new Date().toISOString(),
      },
    ];
  },
};

function findBaselineSibling(polluted: ProbeResult, siblings: ProbeResult[]): ProbeResult | undefined {
  let best: ProbeResult | undefined;
  let bestScore = -1;
  let pollutedPath = '';
  let pollutedOrigin = '';
  try {
    const u = new URL(polluted.url);
    pollutedPath = u.pathname;
    pollutedOrigin = u.origin;
  } catch {
    return undefined;
  }

  for (const s of siblings) {
    if (s.url === polluted.url) continue;
    if (urlCarriesHppPayload(s.url)) continue;
    try {
      const u = new URL(s.url);
      if (u.origin !== pollutedOrigin || u.pathname !== pollutedPath) continue;
      let score = 1;
      if (s.status >= 200 && s.status < 300) score += 1;
      if (u.searchParams.size === 1) score += 2;
      if (score > bestScore) {
        bestScore = score;
        best = s;
      }
    } catch {
      /* skip */
    }
  }
  return best;
}

function stripDuplicate(url: string): string {
  try {
    const u = new URL(url);
    const seen = new Set<string>();
    const next = new URL(u.toString());
    next.search = '';
    for (const [k, v] of u.searchParams) {
      if (seen.has(k)) continue;
      if (v === HPP_CANARY) continue;
      seen.add(k);
      next.searchParams.set(k, v);
    }
    return next.toString();
  } catch {
    return url;
  }
}

function preview(body: string): string {
  return body.slice(0, 240).replace(/\s+/g, ' ');
}
