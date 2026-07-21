// OAuth / OIDC callback misconfiguration signals (safe GET only).

import type { Check, Finding, ProbeResult } from '../../types.js';
import { makeFindingId } from '../../findings/id.js';

const OAUTH_PATH =
  /\/(?:oauth|oidc|auth)\/(?:callback|redirect|authorize|token)|\/login\/oauth|\/signin\/(?:oauth|callback)/i;

const TOKEN_IN_URL =
  /[?#&](?:access_token|id_token|refresh_token|token)=([A-Za-z0-9._\-~+]{20,})/;

const OPEN_REDIRECT_PARAM =
  /[?&](?:redirect_uri|return_to|next|callback|redirect)=https?%3a%2f%2f|redirect_uri=https?:\/\//i;

export const oauthMisconfigCheck: Check = {
  id: 'oauth-misconfig',
  title: 'OAuth / OIDC callback misconfiguration',
  cwe: 'CWE-601',
  run(probe: ProbeResult): Finding[] {
    if (probe.error) return [];
    const findings: Finding[] = [];
    const url = probe.finalUrl ?? probe.url;
    const pathOk = OAUTH_PATH.test(url) || OAUTH_PATH.test(safePath(url));

    // Token leakage in URL (fragment/query) — high when present on any response.
    const tokenHit = TOKEN_IN_URL.exec(url) || TOKEN_IN_URL.exec(probe.headers['location'] ?? '');
    if (tokenHit) {
      findings.push({
        id: makeFindingId(this.id, probe.url, 'token-in-url'),
        checkId: this.id,
        title: 'OAuth token exposed in URL',
        severity: 'high',
        target: stripToken(url),
        description:
          'An OAuth/OIDC access_token or id_token appears in the URL query/fragment or Location header. Tokens in URLs leak via Referer, logs, and browser history.',
        evidence: `URL: ${stripToken(url)}\nStatus: ${probe.status}\nToken param present: yes (redacted)`,
        reproduction: [
          'Complete an OAuth login and inspect the callback URL',
          'Confirm access_token / id_token appears in query or fragment',
        ],
        remediation:
          'Use the authorization code flow with tokens only in POST body / response JSON; never place tokens in URLs; set Referrer-Policy.',
        cwe: 'CWE-598',
        references: [
          'https://datatracker.ietf.org/doc/html/rfc9700',
          'https://owasp.org/www-community/vulnerabilities/Insufficient_Session-ID_Length',
        ],
        needsManualReview: false,
        evidenceGrade: 'canary',
        confidence: 0.88,
        submitReady: true,
        source: 'worker',
        discoveredAt: new Date().toISOString(),
      });
    }

    // Open redirect_uri on OAuth endpoints.
    if (pathOk && OPEN_REDIRECT_PARAM.test(url) && (probe.status >= 300 && probe.status < 400)) {
      const loc = probe.headers['location'] ?? '';
      if (/^https?:\/\//i.test(loc) && !sameSite(url, loc)) {
        findings.push({
          id: makeFindingId(this.id, probe.url, 'redirect-uri'),
          checkId: this.id,
          title: 'OAuth redirect_uri open redirect',
          severity: 'high',
          target: probe.url,
          description:
            'An OAuth/OIDC endpoint followed an absolute redirect_uri / next parameter to a different site. This enables token/code theft via attacker-controlled callbacks.',
          evidence: `URL: ${probe.url}\nStatus: ${probe.status}\nLocation: ${loc.slice(0, 200)}`,
          reproduction: [
            `curl -sI '${probe.url}'`,
            'Confirm Location points off-site while remaining an OAuth callback path',
          ],
          remediation:
            'Allowlist exact redirect_uri values per client; reject absolute external URLs; prefer exact-string match over prefix match.',
          cwe: 'CWE-601',
          references: [
            'https://cwe.mitre.org/data/definitions/601.html',
            'https://datatracker.ietf.org/doc/html/rfc6749#section-3.1.2',
          ],
          needsManualReview: true,
          evidenceGrade: 'fingerprint',
          confidence: 0.7,
          submitReady: false,
          source: 'worker',
          discoveredAt: new Date().toISOString(),
        });
      }
    }

    return findings;
  },
};

function safePath(url: string): string {
  try {
    return new URL(url).pathname;
  } catch {
    return url;
  }
}

function stripToken(url: string): string {
  try {
    const u = new URL(url);
    for (const k of ['access_token', 'id_token', 'refresh_token', 'token']) {
      if (u.searchParams.has(k)) u.searchParams.set(k, '[REDACTED]');
    }
    return u.toString().replace(/([#&]access_token=)[^&]+/i, '$1[REDACTED]');
  } catch {
    return url.replace(/(access_token|id_token|refresh_token)=([^&\s]+)/gi, '$1=[REDACTED]');
  }
}

function sameSite(a: string, b: string): boolean {
  try {
    const ha = new URL(a).hostname.split('.').slice(-2).join('.');
    const hb = new URL(b).hostname.split('.').slice(-2).join('.');
    return ha === hb;
  } catch {
    return false;
  }
}
