// SQL injection detection from safe GET error/fingerprint canaries.

import type { Check, Finding, ProbeResult } from '../../types.js';
import { makeFindingId } from '../../findings/id.js';
import {
  SQL_CANARY,
  hasSqlErrorFingerprint,
  urlCarriesSqlPayload,
} from '../../recon/sql-probes.js';

export const sqlInjectionCheck: Check = {
  id: 'sql-injection-error',
  title: 'SQL injection (error-based)',
  cwe: 'CWE-89',
  run(probe: ProbeResult): Finding[] {
    if (probe.error || !probe.body) return [];
    if (probe.status === 0) return [];
    if (!urlCarriesSqlPayload(probe.url) && !urlCarriesSqlPayload(probe.finalUrl ?? '')) return [];
    if (!hasSqlErrorFingerprint(probe.body)) return [];

    const confirmed = probe.body.includes(SQL_CANARY) || /sql syntax|SQLSTATE|ORA-\d{5}/i.test(probe.body);

    return [
      {
        id: makeFindingId(this.id, probe.url, 'db-error'),
        checkId: this.id,
        title: 'SQL injection — database error fingerprint in response',
        severity: 'critical',
        target: probe.url,
        description:
          'A SQL metacharacter / canary payload in a query parameter caused the application to return a database engine error. This strongly indicates unsanitized SQL concatenation (CWE-89) and often escalates to data exfiltration.',
        evidence: `URL: ${probe.url}\nStatus: ${probe.status}\nCanary: ${SQL_CANARY}\nFingerprint: database error\nBody preview: ${probe.body.slice(0, 280).replace(/\s+/g, ' ')}`,
        reproduction: [
          `curl -sG '${strip(probe.url)}' --data-urlencode "id='"`,
          'Confirm a SQL/DB engine error appears in the response body',
        ],
        remediation:
          'Use parameterized queries / prepared statements exclusively; never concatenate user input into SQL; return generic errors to clients.',
        cwe: 'CWE-89',
        references: [
          'https://cwe.mitre.org/data/definitions/89.html',
          'https://owasp.org/www-community/attacks/SQL_Injection',
        ],
        needsManualReview: !confirmed,
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
