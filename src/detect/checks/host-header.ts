// Host-header injection (active, canary-confirmed, cache-safe). Reads the active
// host-header probe and confirms when our injected X-Forwarded-Host canary is
// reflected into an absolute URL / Location — the precondition for web cache
// poisoning and password-reset poisoning.

import type { Check, Finding, ProbeResult } from '../../types.js';
import { makeFindingId } from '../../findings/id.js';
import {
  ACTIVE_MARKER_HEADER,
  ACTIVE_CANARY_HEADER,
  CANARY_HOST,
  redirectHostOf,
  bodyReflectsCanary,
} from '../../recon/active-probes.js';

export const hostHeaderCheck: Check = {
  id: 'host-header-injection',
  title: 'Host header injection (cache/reset poisoning surface)',
  cwe: 'CWE-644',
  run(probe: ProbeResult): Finding[] {
    if ((probe.headers[ACTIVE_MARKER_HEADER] ?? '') !== 'host-header') return [];
    const canary = probe.headers[ACTIVE_CANARY_HEADER] || CANARY_HOST;

    const location = probe.headers['location'] ?? '';
    const inLocation = !!location && redirectHostOf(location) === canary.toLowerCase();
    const inBody = bodyReflectsCanary(probe.body, canary);
    if (!inLocation && !inBody) return [];

    // If it reflects AND the response looks cacheable, the poisoning risk is real.
    const cacheable = /public|max-age=[1-9]/i.test(probe.headers['cache-control'] ?? '') ||
      (probe.headers['x-cache'] ?? probe.headers['cf-cache-status'] ?? '').toLowerCase().includes('hit');
    const severity: Finding['severity'] = cacheable ? 'high' : 'medium';

    return [
      {
        id: makeFindingId(this.id, probe.url, inLocation ? 'location' : 'body'),
        checkId: this.id,
        title: cacheable
          ? 'Host header injection reflected into a cacheable response'
          : 'Host header injection (X-Forwarded-Host reflected)',
        severity,
        target: probe.url,
        description: `An attacker-controlled \`X-Forwarded-Host\` value was reflected into ${inLocation ? 'the redirect Location' : 'an absolute URL in the response body'}. This is the precondition for web cache poisoning and password-reset poisoning (reset links built from the spoofed host).${cacheable ? ' The response also advertises cacheability, raising the impact.' : ''}`,
        evidence: `URL: ${probe.url}\nStatus: ${probe.status}\nInjected X-Forwarded-Host: ${canary}\nReflected in: ${inLocation ? 'Location header' : 'response body'}\nCache-Control: ${probe.headers['cache-control'] ?? '<absent>'}\nX-Cache: ${probe.headers['x-cache'] ?? probe.headers['cf-cache-status'] ?? '<absent>'}`,
        reproduction: [
          `curl -s -D- -o /dev/null '${probe.url}' -H 'X-Forwarded-Host: ${canary}'`,
          `Confirm ${canary} is reflected in the Location header or an absolute URL in the body`,
          'For reset poisoning: trigger a password reset with this header and inspect the emailed link (do not target real users)',
        ],
        remediation:
          'Derive absolute URLs from a fixed, server-configured canonical host — never from client-supplied Host / X-Forwarded-Host. Ignore or validate forwarding headers at the edge and exclude them from the cache key when honored.',
        cwe: 'CWE-644',
        references: [
          'https://cwe.mitre.org/data/definitions/644.html',
          'https://portswigger.net/web-security/host-header',
          'https://portswigger.net/web-security/web-cache-poisoning',
        ],
        needsManualReview: true,
        evidenceGrade: 'canary',
        confidence: cacheable ? 0.85 : 0.75,
        submitReady: false,
        source: 'worker',
        discoveredAt: new Date().toISOString(),
      },
    ];
  },
};
