// Subdomain takeover detection from scanner-attached DNS signals.

import type { Check, Finding, ProbeResult } from '../../types.js';
import { makeFindingId } from '../../findings/id.js';
import { isTakeoverCandidate, type DnsLookupResult } from '../../recon/takeover.js';

export const subdomainTakeoverCheck: Check = {
  id: 'subdomain-takeover',
  title: 'Subdomain takeover (dangling CNAME)',
  cwe: 'CWE-284',
  run(probe: ProbeResult): Finding[] {
    if (probe.error) return [];
    // Synthetic DNS probes are tagged by the scanner.
    if ((probe.headers['x-stormforge-dns'] ?? '') !== 'takeover-lookup') return [];
    let lookup: DnsLookupResult;
    try {
      lookup = JSON.parse(probe.body) as DnsLookupResult;
    } catch {
      return [];
    }
    const hit = isTakeoverCandidate(lookup);
    if (!hit) return [];

    return [
      {
        id: makeFindingId(this.id, lookup.host, hit.service),
        checkId: this.id,
        title: `Possible subdomain takeover — ${lookup.host} → ${hit.service}`,
        severity: hit.severity,
        target: `https://${lookup.host}/`,
        description:
          `DNS CNAME for \`${lookup.host}\` points to \`${hit.cname}\` (${hit.service}) but the name does not resolve to an A/AAAA address (NXDOMAIN/empty). This is the classic dangling-DNS subdomain takeover signal — an attacker who claims the upstream resource can serve content on your subdomain.`,
        evidence: `Host: ${lookup.host}\nCNAME: ${hit.cname}\nService: ${hit.service}\nA/AAAA: ${lookup.aRecords.join(', ') || '<none>'}\nNXDOMAIN: ${lookup.nxdomain}`,
        reproduction: [
          `dig CNAME ${lookup.host} +short`,
          `dig A ${lookup.host} +short`,
          `dig AAAA ${lookup.host} +short`,
          `Confirm CNAME → ${hit.cname} with no resolving address, then verify the ${hit.service} resource is unclaimed`,
        ],
        remediation:
          'Remove the dangling CNAME, or claim/recreate the upstream service resource and lock ownership. Prefer provider-verified domain controls.',
        cwe: 'CWE-284',
        references: [
          'https://cwe.mitre.org/data/definitions/284.html',
          'https://owasp.org/www-community/vulnerabilities/Unclaimed_Subdomain_Takeover',
          'https://github.com/EdOverflow/can-i-take-over-xyz',
        ],
        needsManualReview: true,
        discoveredAt: new Date().toISOString(),
      },
    ];
  },
};
