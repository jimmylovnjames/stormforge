// robots.txt Disallow disclosure of sensitive paths (passive).

import type { Check, Finding, ProbeResult } from '../../types.js';
import { makeFindingId } from '../../findings/id.js';
import { extractRobotsPaths, sensitiveRobotsPaths } from '../../recon/robots-sitemap.js';

export const robotsDisclosureCheck: Check = {
  id: 'robots-disclosure',
  title: 'robots.txt sensitive path disclosure',
  cwe: 'CWE-200',
  run(probe: ProbeResult): Finding[] {
    if (probe.error || !probe.body) return [];
    if (probe.status < 200 || probe.status >= 300) return [];
    const path = safePath(probe.url);
    const looksRobots =
      path.endsWith('/robots.txt') ||
      (/^\s*User-agent:/im.test(probe.body) && /^\s*Disallow:/im.test(probe.body));
    if (!looksRobots) return [];

    const all = extractRobotsPaths(probe.body);
    const sensitive = sensitiveRobotsPaths(all);
    if (!sensitive.length) return [];

    return [
      {
        id: makeFindingId(this.id, probe.url, sensitive.slice(0, 3).join(',')),
        checkId: this.id,
        title: 'robots.txt discloses sensitive Disallow paths',
        severity: 'low',
        target: probe.url,
        description:
          'robots.txt lists Disallow entries that reveal sensitive or high-value paths (admin, backups, VCS, env). Attackers use these as a free recon map even when crawling is "blocked".',
        evidence: `URL: ${probe.url}\nStatus: ${probe.status}\npaths: ${sensitive.join(', ')}`,
        reproduction: [`curl -s '${probe.url}'`, 'Inspect Disallow lines for admin/backup/.git/.env paths'],
        remediation:
          'Avoid advertising sensitive paths in robots.txt; protect them with auth and do not rely on Disallow for security.',
        cwe: 'CWE-200',
        references: [
          'https://cwe.mitre.org/data/definitions/200.html',
          'https://www.rfc-editor.org/rfc/rfc9309.html',
        ],
        needsManualReview: true,
        evidenceGrade: 'fingerprint',
        confidence: 0.7,
        submitReady: false,
        source: 'worker',
        discoveredAt: new Date().toISOString(),
      },
    ];
  },
};

function safePath(url: string): string {
  try {
    return new URL(url).pathname.toLowerCase();
  } catch {
    return url.toLowerCase();
  }
}
