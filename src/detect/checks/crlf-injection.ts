// CRLF / HTTP response-splitting detection from header canaries.

import type { Check, Finding, ProbeResult } from '../../types.js';
import { makeFindingId } from '../../findings/id.js';
import {
  CRLF_CANARY_HEADER,
  CRLF_CANARY_VALUE,
  hasCrlfHeaderInjection,
  urlCarriesCrlfPayload,
} from '../../recon/crlf-probes.js';

export const crlfInjectionCheck: Check = {
  id: 'crlf-header-injection',
  title: 'CRLF / HTTP response splitting',
  cwe: 'CWE-113',
  run(probe: ProbeResult): Finding[] {
    if (probe.error) return [];
    if (!urlCarriesCrlfPayload(probe.url)) return [];
    if (!hasCrlfHeaderInjection(probe.headers)) return [];

    return [
      {
        id: makeFindingId(this.id, probe.url, 'hdr'),
        checkId: this.id,
        title: 'CRLF injection — attacker-controlled response header',
        severity: 'high',
        target: probe.url,
        description:
          `A CRLF sequence (%0d%0a) in a query parameter injected a response header (\`${CRLF_CANARY_HEADER}\` / Set-Cookie). This enables HTTP response splitting, session fixation via Set-Cookie, cache poisoning, and XSS via injected headers.`,
        evidence: `URL: ${probe.url}\nStatus: ${probe.status}\nInjected header: ${CRLF_CANARY_HEADER}: ${probe.headers[CRLF_CANARY_HEADER] ?? '(via Set-Cookie)'}\nCanary: ${CRLF_CANARY_VALUE}\nSet-Cookie: ${(probe.headers['set-cookie'] ?? '').slice(0, 120)}`,
        reproduction: [
          `curl -sI '${probe.url}'`,
          `Confirm response includes '${CRLF_CANARY_HEADER}: ${CRLF_CANARY_VALUE}' (or Set-Cookie sfCrlf=…)`,
        ],
        remediation:
          'Reject CR/LF in header-influencing inputs; encode/validate redirect and filename parameters; never write raw user input into response headers.',
        cwe: 'CWE-113',
        references: [
          'https://cwe.mitre.org/data/definitions/113.html',
          'https://owasp.org/www-community/vulnerabilities/HTTP_Response_Splitting',
        ],
        needsManualReview: false,
        discoveredAt: new Date().toISOString(),
      },
    ];
  },
};
