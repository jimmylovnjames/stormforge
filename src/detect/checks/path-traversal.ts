// Path traversal / LFI detection from safe GET canaries.

import type { Check, Finding, ProbeResult } from '../../types.js';
import { makeFindingId } from '../../findings/id.js';
import { hasPathTraversalSuccess, urlCarriesLfiPayload } from '../../recon/path-traversal-probes.js';

export const pathTraversalCheck: Check = {
  id: 'path-traversal',
  title: 'Path traversal / LFI',
  cwe: 'CWE-22',
  run(probe: ProbeResult): Finding[] {
    if (probe.error || !probe.body) return [];
    if (probe.status < 200 || probe.status >= 400) return [];
    if (!hasPathTraversalSuccess(probe.body, probe.url)) return [];

    return [
      {
        id: makeFindingId(this.id, probe.url, 'lfi'),
        checkId: this.id,
        title: 'Path traversal / local file inclusion',
        severity: 'critical',
        target: probe.url,
        description:
          'A traversal/LFI canary caused the response to include OS file content (e.g. `/etc/passwd` or `win.ini`). This confirms arbitrary file read and often escalates to RCE.',
        evidence: `URL: ${probe.url}\nStatus: ${probe.status}\nLFI param present: ${urlCarriesLfiPayload(probe.url)}\nBody preview: ${probe.body.slice(0, 220).replace(/\s+/g, ' ')}`,
        reproduction: [
          `curl -sG '${strip(probe.url)}' --data-urlencode 'file=../../../../../../etc/passwd'`,
          'Confirm root:x:0:0: (or win.ini [extensions]) appears in the body',
        ],
        remediation:
          'Resolve and allowlist file paths under a document root; reject `..` and absolute paths; never concatenate user input into filesystem APIs.',
        cwe: 'CWE-22',
        references: [
          'https://cwe.mitre.org/data/definitions/22.html',
          'https://owasp.org/www-community/attacks/Path_Traversal',
        ],
        needsManualReview: false,
        discoveredAt: new Date().toISOString(),
      },
    ];
  },
};

function strip(url: string): string {
  try {
    const u = new URL(url);
    u.search = '';
    return u.toString();
  } catch {
    return url.split('?')[0] ?? url;
  }
}
