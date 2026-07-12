// Known-CVE version fingerprint flagging.
//
// Purely informational: matches a fingerprinted product/version against a small
// static advisory table and flags it for manual confirmation. Does NOT attempt
// to exploit or even verify exploitability — it just surfaces the lead.

import type { Check, Finding, ProbeResult } from '../../types.js';
import { fingerprint } from '../../recon/fingerprint.js';
import { makeFindingId } from '../../findings/id.js';
import { compareVersions } from '../../util/semver.js';

interface Advisory {
  product: string;
  /** Versions strictly below this are considered affected. */
  fixedIn: string;
  cve: string;
  title: string;
  severity: Finding['severity'];
}

// Small illustrative table. Extend from a real feed (see docs/EXTENDING.md).
const ADVISORIES: Advisory[] = [
  { product: 'nginx', fixedIn: '1.21.0', cve: 'CVE-2021-23017', title: 'nginx resolver off-by-one', severity: 'high' },
  { product: 'Apache', fixedIn: '2.4.51', cve: 'CVE-2021-42013', title: 'Apache path traversal / RCE', severity: 'critical' },
  { product: 'jQuery', fixedIn: '3.5.0', cve: 'CVE-2020-11023', title: 'jQuery XSS via HTML manipulation', severity: 'medium' },
  { product: 'WordPress', fixedIn: '5.8.3', cve: 'CVE-2022-21661', title: 'WordPress SQL injection (WP_Query)', severity: 'high' },
];

export const versionCveCheck: Check = {
  id: 'known-cve-version',
  title: 'Outdated component with known CVE',
  cwe: 'CWE-1035',
  run(probe: ProbeResult): Finding[] {
    if (probe.error) return [];
    const tech = fingerprint(probe);
    const findings: Finding[] = [];

    for (const t of tech) {
      if (!t.version) continue;
      for (const adv of ADVISORIES) {
        if (adv.product.toLowerCase() !== t.product.toLowerCase()) continue;
        if (compareVersions(t.version, adv.fixedIn) >= 0) continue; // patched
        findings.push({
          id: makeFindingId(this.id, probe.url, `${adv.cve}:${t.version}`),
          checkId: this.id,
          title: `${t.product} ${t.version} — ${adv.title} (${adv.cve})`,
          severity: adv.severity,
          target: probe.url,
          description: `Fingerprinting indicates ${t.product} ${t.version}, which is below the fixed version ${adv.fixedIn} for ${adv.cve}. Version-based detection can be inaccurate (backports, banner spoofing) — confirm before reporting.`,
          evidence: `URL: ${probe.url}\nDetected: ${t.product} ${t.version} (source ${t.source})\nAdvisory: ${adv.cve}, fixed in ${adv.fixedIn}`,
          reproduction: [
            `Fetch ${probe.url}`,
            `Observe version banner: ${t.product} ${t.version}`,
            `Cross-reference ${adv.cve}; verify the instance is genuinely affected (not a backported fix)`,
          ],
          remediation: `Upgrade ${t.product} to ${adv.fixedIn} or later.`,
          cwe: 'CWE-1035',
          references: [`https://nvd.nist.gov/vuln/detail/${adv.cve}`],
          needsManualReview: true,
          discoveredAt: new Date().toISOString(),
        });
      }
    }
    return findings;
  },
};
