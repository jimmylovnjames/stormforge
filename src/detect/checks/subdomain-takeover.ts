// Subdomain takeover detection from DNS signals and HTTP body fingerprints.

import type { Check, Finding, ProbeResult } from '../../types.js';
import { makeFindingId } from '../../findings/id.js';
import {
  isTakeoverCandidate,
  matchTakeoverBody,
  type DnsLookupResult,
} from '../../recon/takeover.js';

export const subdomainTakeoverCheck: Check = {
  id: 'subdomain-takeover',
  title: 'Subdomain takeover (dangling CNAME / unclaimed service)',
  cwe: 'CWE-284',
  run(probe: ProbeResult): Finding[] {
    if (probe.error) return [];
    const findings: Finding[] = [];

    if ((probe.headers['x-stormforge-dns'] ?? '') === 'takeover-lookup') {
      let lookup: DnsLookupResult;
      try {
        lookup = JSON.parse(probe.body) as DnsLookupResult;
      } catch {
        return [];
      }
      const hit = isTakeoverCandidate(lookup);
      if (!hit) return [];

      findings.push({
        id: makeFindingId(this.id, lookup.host, hit.service),
        checkId: this.id,
        title: `Possible subdomain takeover — ${lookup.host} → ${hit.service}`,
        severity: hit.severity,
        target: `https://${lookup.host}/`,
        description: `DNS CNAME for \`${lookup.host}\` points to \`${hit.cname}\` (${hit.service}) but the name does not resolve to an A/AAAA address (NXDOMAIN/empty). This is the classic dangling-DNS subdomain takeover signal — an attacker who claims the upstream resource can serve content on your subdomain.`,
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
        evidenceGrade: 'fingerprint',
        confidence: 0.8,
        submitReady: false,
        source: 'worker',
        discoveredAt: new Date().toISOString(),
      });
      return findings;
    }

    if (!probe.body) return [];
    if (probe.status !== 0 && probe.status < 200) return [];
    const bodyHit = matchTakeoverBody(probe.body);
    if (!bodyHit) return [];

    // Avoid flagging on primary app roots that happen to include error strings.
    let host = '';
    try {
      host = new URL(probe.finalUrl ?? probe.url).hostname;
    } catch {
      return [];
    }

    findings.push({
      id: makeFindingId(this.id, host, `body:${bodyHit.service}`),
      checkId: this.id,
      title: `Possible unclaimed ${bodyHit.service} page on ${host}`,
      severity: bodyHit.severity,
      target: probe.finalUrl ?? probe.url,
      description: `HTTP response body matches a known unclaimed ${bodyHit.service} fingerprint. This often indicates a dangling DNS / abandoned SaaS binding — confirm with DNS and provider claim status before reporting.`,
      evidence: `URL: ${probe.url}\nStatus: ${probe.status}\nService: ${bodyHit.service}\nBody preview: ${probe.body.slice(0, 200).replace(/\s+/g, ' ')}`,
      reproduction: [
        `curl -sI '${probe.url}'`,
        `curl -s '${probe.url}' | head`,
        `dig CNAME ${host} +short`,
        `Verify the ${bodyHit.service} resource is unclaimed`,
      ],
      remediation:
        'Remove dangling DNS records or reclaim the upstream SaaS project; enable provider domain verification.',
      cwe: 'CWE-284',
      references: [
        'https://github.com/EdOverflow/can-i-take-over-xyz',
        'https://owasp.org/www-community/vulnerabilities/Unclaimed_Subdomain_Takeover',
      ],
      needsManualReview: true,
      evidenceGrade: 'fingerprint',
      confidence: 0.7,
      submitReady: false,
      source: 'worker',
      discoveredAt: new Date().toISOString(),
    });

    return findings;
  },
};
