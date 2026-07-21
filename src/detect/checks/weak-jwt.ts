// Weak / unsafe JWT detection (alg=none, empty signature, dangerous kid).
// Passive: inspects JWTs already present in response bodies or Set-Cookie.
// Never attempts to forge, brute-force, or use the token.

import type { Check, Finding, ProbeResult } from '../../types.js';
import { makeFindingId } from '../../findings/id.js';
import type { WeakJwtIssue } from '../../recon/jwt.js';
import { analyzeWeakJwt, findJwtCandidates, redactJwt } from '../../recon/jwt.js';

export const weakJwtCheck: Check = {
  id: 'weak-jwt',
  title: 'Weak or unsafe JWT',
  cwe: 'CWE-347',
  run(probe: ProbeResult): Finding[] {
    if (probe.error) return [];

    const haystacks: { source: string; text: string }[] = [];
    if (probe.body) haystacks.push({ source: 'body', text: probe.body });
    const setCookie = probe.headers['set-cookie'];
    if (setCookie) haystacks.push({ source: 'set-cookie', text: setCookie });
    // Some APIs echo Authorization in custom response headers (misconfig).
    for (const h of ['authorization', 'x-auth-token', 'x-access-token']) {
      if (probe.headers[h]) haystacks.push({ source: `header:${h}`, text: probe.headers[h] });
    }

    const findings: Finding[] = [];
    const seen = new Set<string>();

    for (const { source, text } of haystacks) {
      for (const token of findJwtCandidates(text)) {
        const issues = analyzeWeakJwt(token);
        for (const issue of issues) {
          const key = `${issue.kind}:${redactJwt(token)}`;
          if (seen.has(key)) continue;
          seen.add(key);

          findings.push({
            id: makeFindingId(this.id, probe.url, key),
            checkId: this.id,
            title: weakTitle(issue.kind),
            severity: issue.severity,
            target: probe.url,
            description: `${issue.detail} Token observed in ${source}. Attackers may forge arbitrary claims if the server accepts this token shape.`,
            evidence: `URL: ${probe.url}\nSource: ${source}\nIssue: ${issue.kind}\nRedacted JWT: ${redactJwt(token)}\nDetail: ${issue.detail}`,
            reproduction: [
              `Fetch ${probe.url}`,
              `Locate the JWT in ${source}`,
              'Decode the header (base64url) and confirm the weak alg / empty signature / dangerous kid — do not use the token against production beyond authorized testing',
            ],
            remediation:
              'Reject alg=none and empty signatures server-side; pin allowed algorithms (e.g. RS256/ES256); validate kid against an allowlist; rotate any exposed signing material.',
            cwe: 'CWE-347',
            references: [
              'https://cwe.mitre.org/data/definitions/347.html',
              'https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/',
              'https://portswigger.net/web-security/jwt',
            ],
            needsManualReview: issue.kind === 'path-traversal-kid',
            discoveredAt: new Date().toISOString(),
          });
        }
      }
    }

    return findings;
  },
};

function weakTitle(kind: WeakJwtIssue['kind']): string {
  switch (kind) {
    case 'alg-none':
      return 'JWT with alg=none (unsigned token accepted/issued)';
    case 'empty-signature':
      return 'JWT with empty signature segment';
    case 'two-segment-unsigned':
      return 'Unsigned two-segment JWT issued';
    case 'path-traversal-kid':
      return 'JWT kid contains path-traversal characters';
    case 'alg-empty':
      return 'JWT with empty alg header';
    default: {
      const _exhaustive: never = kind;
      return `Weak JWT (${_exhaustive})`;
    }
  }
}
