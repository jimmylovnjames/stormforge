// CORS misconfiguration detection.
//
// Passive: inspects Access-Control-* headers on the fetched response. The
// orchestrator sends an `Origin` probe header (and optionally a subdomain-trust
// bypass Origin) so reflection can be observed without exploitation.

import type { Check, Finding, ProbeResult } from '../../types.js';
import { makeFindingId } from '../../findings/id.js';

/** The probe Origin the orchestrator injects; checks look for its reflection. */
export const PROBE_ORIGIN = 'https://stormforge-probe.example';

/** Prefix used for ends-with / subdomain-trust bypass Origins. */
export const CORS_BYPASS_LABEL = 'stormforge-cors';

/** Build `https://stormforge-cors.<registrable>` for a target URL. */
export function corsBypassOriginFor(targetUrl: string): string | null {
  try {
    const base = registrableHint(new URL(targetUrl).hostname);
    if (!base) return null;
    return `https://${CORS_BYPASS_LABEL}.${base}`;
  } catch {
    return null;
  }
}

export const corsCheck: Check = {
  id: 'cors-misconfig',
  title: 'CORS misconfiguration',
  cwe: 'CWE-942',
  run(probe: ProbeResult): Finding[] {
    if (probe.error || probe.status === 0) return [];
    const acao = probe.headers['access-control-allow-origin'];
    if (!acao) return [];

    const acac = (probe.headers['access-control-allow-credentials'] ?? '').toLowerCase() === 'true';
    const bypassOrigin = corsBypassOriginFor(probe.url);
    let severity: Finding['severity'] | null = null;
    let detail = '';
    let requestOrigin = PROBE_ORIGIN;

    if (acao === '*' && acac) {
      severity = 'medium';
      detail = 'Wildcard origin combined with credentials.';
    } else if (acao === PROBE_ORIGIN) {
      severity = acac ? 'high' : 'medium';
      detail = acac
        ? 'Arbitrary Origin reflected WITH credentials — cross-origin reads of authenticated responses are possible.'
        : 'Arbitrary Origin reflected. Impact depends on whether sensitive data is returned.';
    } else if (bypassOrigin && acao === bypassOrigin) {
      requestOrigin = bypassOrigin;
      severity = acac ? 'high' : 'medium';
      detail = acac
        ? 'Ends-with / subdomain Origin trust bypass WITH credentials — any attacker-controlled sibling subdomain can read authenticated responses.'
        : 'Ends-with / subdomain Origin trust bypass — attacker-controlled sibling hosts under the registrable domain are trusted.';
    } else if (acao === 'null') {
      severity = acac ? 'medium' : 'low';
      detail = '`null` origin is allowed, which sandboxed/document contexts can spoof.';
    }

    if (!severity) return [];

    return [
      {
        id: makeFindingId(this.id, probe.url, `${acao}|${acac}`),
        checkId: this.id,
        title: `CORS misconfiguration (${detail.split('.')[0]})`,
        severity,
        target: probe.url,
        description: `The endpoint returns permissive CORS headers. ${detail}`,
        evidence: `URL: ${probe.url}\nRequest Origin: ${requestOrigin}\nAccess-Control-Allow-Origin: ${acao}\nAccess-Control-Allow-Credentials: ${acac}`,
        reproduction: [
          `curl -s -H 'Origin: ${requestOrigin}' -I ${probe.url}`,
          'Observe the Access-Control-Allow-Origin / -Credentials headers reflect the attacker origin',
          'Manually confirm the endpoint returns sensitive, authenticated data before reporting',
        ],
        remediation:
          'Reflect Origin only from an explicit allowlist of trusted origins; never use ends-with domain matching; never combine credentialed responses with a reflected or wildcard origin.',
        cwe: 'CWE-942',
        references: ['https://cwe.mitre.org/data/definitions/942.html'],
        needsManualReview: true,
        evidenceGrade: 'canary',
        confidence: severity === 'high' ? 0.9 : 0.75,
        submitReady: severity === 'high',
        source: 'worker',
        discoveredAt: new Date().toISOString(),
      },
    ];
  },
};

function registrableHint(host: string): string | null {
  const parts = host.toLowerCase().split('.').filter(Boolean);
  if (parts.length < 2) return null;
  return parts.slice(-2).join('.');
}
