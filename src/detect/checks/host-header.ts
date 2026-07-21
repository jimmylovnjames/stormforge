// Host header injection / cache poisoning signals.

import type { Check, Finding, ProbeResult } from '../../types.js';
import { makeFindingId } from '../../findings/id.js';
import {
  HOST_CANARY,
  cachePoisoningSignals,
  hostHeaderReflected,
} from '../../recon/host-header-probes.js';

export const hostHeaderCheck: Check = {
  id: 'host-header-injection',
  title: 'Host header injection / cache poisoning',
  cwe: 'CWE-644',
  run(probe: ProbeResult): Finding[] {
    if (probe.error) return [];
    const findings: Finding[] = [];

    // Only flag when our canary was used (URL or we detect canary in response from poisoned probe).
    // Poisoned probes keep original URL; canary appears in body/Location.
    if (hostHeaderReflected(probe)) {
      const cache = cachePoisoningSignals(probe.headers);
      const severity = cache.length ? 'high' : 'high';
      findings.push({
        id: makeFindingId(this.id, probe.url, cache.length ? 'cache' : 'reflect'),
        checkId: this.id,
        title: cache.length
          ? 'Host/X-Forwarded-Host reflection with cache signals (poisoning risk)'
          : 'Host / X-Forwarded-Host header reflected in response',
        severity,
        target: probe.url,
        description:
          `The application reflected \`${HOST_CANARY}\` from a Host or X-Forwarded-Host probe into the body or Location header. This enables password-reset poisoning, cache poisoning, and routing attacks.`,
        evidence: `URL: ${probe.url}\nStatus: ${probe.status}\nCanary: ${HOST_CANARY}\nLocation: ${probe.headers['location'] ?? '<absent>'}\nCache signals: ${cache.join(', ') || 'none'}\nBody preview: ${(probe.body || '').slice(0, 200).replace(/\s+/g, ' ')}`,
        reproduction: [
          `curl -sI -H 'Host: ${HOST_CANARY}' '${probe.url}'`,
          `curl -sI -H 'X-Forwarded-Host: ${HOST_CANARY}' '${probe.url}'`,
          'Confirm the canary appears in Location, links, or absolute URLs',
        ],
        remediation:
          'Ignore untrusted Host/X-Forwarded-* except from the edge; configure a static trusted host allowlist; include Host in Vary / cache keys when absolute URLs are generated.',
        cwe: 'CWE-644',
        references: [
          'https://cwe.mitre.org/data/definitions/644.html',
          'https://portswigger.net/web-security/host-header',
        ],
        needsManualReview: cache.length === 0,
        discoveredAt: new Date().toISOString(),
      });
    }

    return findings;
  },
};
