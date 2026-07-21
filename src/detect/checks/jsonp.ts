// JSONP callback reflection — CORS bypass via GET callback wrapping.

import type { Check, Finding, ProbeResult } from '../../types.js';
import { makeFindingId } from '../../findings/id.js';
import {
  JSONP_CANARY,
  hasJsonpWrapper,
  urlCarriesJsonpCanary,
} from '../../recon/jsonp-probes.js';

const SENSITIVE =
  /"(?:email|user_email|mail)"\s*:\s*"[^"]+@[^"]+"|"role"\s*:\s*"(?:admin|root)"|"access_token"\s*:|"api[_-]?key"\s*:/i;

export const jsonpCheck: Check = {
  id: 'jsonp-callback',
  title: 'JSONP callback reflection',
  cwe: 'CWE-942',
  run(probe: ProbeResult): Finding[] {
    if (probe.error || !probe.body) return [];
    if (probe.status < 200 || probe.status >= 300) return [];
    const url = probe.finalUrl ?? probe.url;
    if (!urlCarriesJsonpCanary(url) || !hasJsonpWrapper(probe.body, url)) return [];

    const sensitive = SENSITIVE.test(probe.body);
    const ct = (probe.headers['content-type'] ?? '').toLowerCase();
    const scripty =
      ct.includes('javascript') ||
      ct.includes('ecmascript') ||
      ct.includes('json') ||
      /^\s*(?:\/\*[\s\S]*?\*\/\s*)?\w+\s*\(/.test(probe.body);

    if (!scripty && !sensitive) return [];

    return [
      {
        id: makeFindingId(this.id, probe.url, 'jsonp'),
        checkId: this.id,
        title: sensitive
          ? 'JSONP endpoint reflects callback and wraps sensitive JSON'
          : 'JSONP callback reflection enables cross-origin data read',
        severity: sensitive ? 'high' : 'medium',
        target: probe.url,
        description: sensitive
          ? 'A unique JSONP callback name was reflected as a function wrapper around a JSON payload containing account/token markers. Cross-origin pages can invoke this callback to exfiltrate data, bypassing CORS.'
          : 'A unique JSONP callback name was reflected as a JavaScript function wrapper. Attackers can load the endpoint cross-origin via <script> and read the wrapped response, bypassing CORS restrictions.',
        evidence: `URL: ${probe.url}\nStatus: ${probe.status}\nContent-Type: ${ct || '<none>'}\nCanary: ${JSONP_CANARY}\nSensitive markers: ${sensitive}\nBody preview: ${preview(probe.body)}`,
        reproduction: [
          `curl -sG '${stripCallback(url)}' --data-urlencode 'callback=${JSONP_CANARY}'`,
          `Confirm the response begins with ${JSONP_CANARY}(…)` ,
        ],
        remediation:
          'Disable JSONP; use CORS with an explicit allowlist and credentialed fetch only where required. Never reflect arbitrary callback names.',
        cwe: 'CWE-942',
        references: [
          'https://cwe.mitre.org/data/definitions/942.html',
          'https://owasp.org/www-community/vulnerabilities/Insufficient_Cross-Origin_Resource_Sharing',
        ],
        needsManualReview: !sensitive,
        evidenceGrade: sensitive ? 'canary' : 'fingerprint',
        confidence: sensitive ? 0.85 : 0.72,
        submitReady: sensitive,
        source: 'worker',
        discoveredAt: new Date().toISOString(),
      },
    ];
  },
};

function preview(body: string): string {
  return body.slice(0, 220).replace(/\s+/g, ' ');
}

function stripCallback(url: string): string {
  try {
    const u = new URL(url);
    for (const p of ['callback', 'jsonp', 'cb', '_callback']) u.searchParams.delete(p);
    return u.toString();
  } catch {
    return url;
  }
}
