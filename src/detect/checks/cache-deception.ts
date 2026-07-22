// Path-based web cache deception detection.

import type { Check, Finding, ProbeResult } from '../../types.js';
import { makeFindingId } from '../../findings/id.js';
import { hasCacheableResponse, looksLikeDynamicContent } from '../../recon/cache-probes.js';

export const cacheDeceptionCheck: Check = {
  id: 'cache-deception',
  title: 'Web cache deception',
  cwe: 'CWE-444',
  run(probe: ProbeResult): Finding[] {
    if (probe.error || !probe.body) return [];
    if (probe.status < 200 || probe.status >= 400) return [];

    if (!/\.(?:css|js|ico|jpg|png|svg|woff|map)|%0[ad]\.css|;\.css|\.\.%2f.*\.css|\/\.css/i.test(probe.url)) {
      return [];
    }
    if (!looksLikeDynamicContent(probe.body, probe.headers)) return [];
    if (!hasCacheableResponse(probe.headers)) return [];

    return [
      {
        id: makeFindingId(this.id, probe.url, 'path'),
        checkId: this.id,
        title: 'Web cache deception — dynamic content cached under static path',
        severity: 'high',
        target: probe.url,
        description:
          'A sensitive/dynamic response (account markers, email/username JSON, or session UI) was returned for a URL with a static-looking suffix (e.g. `.css`) and cache headers indicate it is cacheable. An attacker can cause a victim’s personalized response to be stored and later retrieved (account takeover / data leak).',
        evidence: `URL: ${probe.url}\nStatus: ${probe.status}\nCache-Control: ${probe.headers['cache-control'] ?? '<absent>'}\nX-Cache/Age: ${probe.headers['x-cache'] ?? probe.headers['cf-cache-status'] ?? probe.headers['age'] ?? '<absent>'}\nVary: ${probe.headers['vary'] ?? '<absent>'}\nBody preview: ${probe.body.slice(0, 220).replace(/\s+/g, ' ')}`,
        reproduction: [
          `curl -sI '${probe.url}'`,
          `curl -s '${probe.url}' | head`,
          'Confirm dynamic markers + cache HIT/Age without Vary: Cookie',
        ],
        remediation:
          'Normalize paths before cache keying; never cache authenticated responses; include Cookie/Authorization in Vary or use Cache-Control: private, no-store for account pages.',
        cwe: 'CWE-444',
        references: [
          'https://cwe.mitre.org/data/definitions/444.html',
          'https://portswigger.net/web-security/web-cache-deception',
        ],
        needsManualReview: true,
        evidenceGrade: 'fingerprint',
        confidence: 0.78,
        submitReady: false,
        source: 'worker',
        discoveredAt: new Date().toISOString(),
      },
    ];
  },
};
