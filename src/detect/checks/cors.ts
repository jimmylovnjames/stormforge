// CORS misconfiguration detection.
//
// Passive: inspects Access-Control-* headers on the fetched response. The
// orchestrator sends an `Origin` probe header so reflection can be observed
// without any exploitation.

import type { Check, Finding, ProbeResult } from '../../types.js';
import { makeFindingId } from '../../findings/id.js';

/** The probe Origin the orchestrator injects; checks look for its reflection. */
export const PROBE_ORIGIN = 'https://stormforge-probe.example';

export const corsCheck: Check = {
  id: 'cors-misconfig',
  title: 'CORS misconfiguration',
  cwe: 'CWE-942',
  run(probe: ProbeResult): Finding[] {
    if (probe.error || probe.status === 0) return [];
    const acao = probe.headers['access-control-allow-origin'];
    if (!acao) return [];

    const acac = (probe.headers['access-control-allow-credentials'] ?? '').toLowerCase() === 'true';
    let severity: Finding['severity'] | null = null;
    let detail = '';

    if (acao === '*' && acac) {
      // Invalid+dangerous combo (browsers reject, but signals intent/misconfig).
      severity = 'medium';
      detail = 'Wildcard origin combined with credentials.';
    } else if (acao === PROBE_ORIGIN) {
      // Server reflects arbitrary Origin.
      severity = acac ? 'high' : 'medium';
      detail = acac
        ? 'Arbitrary Origin reflected WITH credentials — cross-origin reads of authenticated responses are possible.'
        : 'Arbitrary Origin reflected. Impact depends on whether sensitive data is returned.';
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
        evidence: `URL: ${probe.url}\nRequest Origin: ${PROBE_ORIGIN}\nAccess-Control-Allow-Origin: ${acao}\nAccess-Control-Allow-Credentials: ${acac}`,
        reproduction: [
          `curl -s -H 'Origin: ${PROBE_ORIGIN}' -I ${probe.url}`,
          'Observe the Access-Control-Allow-Origin / -Credentials headers reflect the attacker origin',
          'Manually confirm the endpoint returns sensitive, authenticated data before reporting',
        ],
        remediation:
          'Reflect Origin only from an allowlist of trusted origins; never combine credentialed responses with a reflected or wildcard origin.',
        cwe: 'CWE-942',
        references: ['https://cwe.mitre.org/data/definitions/942.html'],
        needsManualReview: true,
        discoveredAt: new Date().toISOString(),
      },
    ];
  },
};
