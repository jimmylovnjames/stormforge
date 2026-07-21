// WebSocket + SAML/OIDC surface discovery (safe GET/HEAD signals only).

import type { Check, Finding, ProbeResult } from '../../types.js';
import { makeFindingId } from '../../findings/id.js';

const OIDC_PATH = /\/\.well-known\/(?:openid-configuration|oauth-authorization-server)/i;
const SAML_PATH = /\/(?:saml|sso|auth)\/.*metadata|federationmetadata|\/adfs\//i;
const WS_PATH = /\/(?:ws|wss|websocket|socket\.io|cable|realtime|mqtt)(?:\/|\?|$)/i;

export const wsSamlDiscoveryCheck: Check = {
  id: 'ws-saml-discovery',
  title: 'WebSocket / SAML / OIDC surface discovery',
  cwe: 'CWE-200',
  run(probe: ProbeResult): Finding[] {
    if (probe.error) return [];
    const findings: Finding[] = [];
    const url = probe.finalUrl ?? probe.url;
    const path = safePath(url);
    const headers = probe.headers;
    const body = probe.body ?? '';
    const ct = (headers['content-type'] ?? '').toLowerCase();

    // ── OIDC / OAuth AS discovery document ───────────────────────────────
    if (
      (OIDC_PATH.test(url) || OIDC_PATH.test(path) || looksOidcJson(body, ct)) &&
      isOidcDiscovery(body)
    ) {
      findings.push({
        id: makeFindingId(this.id, probe.url, 'oidc-discovery'),
        checkId: this.id,
        title: 'OIDC / OAuth discovery document exposed',
        severity: 'low',
        target: probe.url,
        description:
          'An OpenID Connect or OAuth authorization-server discovery document is publicly reachable. It maps issuer, authorize/token, and JWKS endpoints that guide auth-focused follow-up (redirect_uri, token leakage, weak JWKS).',
        evidence: `URL: ${probe.url}\nStatus: ${probe.status}\nBody preview: ${preview(body)}`,
        reproduction: [`curl -s '${probe.url}'`, 'Confirm issuer, authorization_endpoint, and jwks_uri'],
        remediation:
          'Ensure discovery is intentional for public clients; lock down admin/metadata siblings; review redirect_uri allowlists and JWKS key strength.',
        cwe: 'CWE-200',
        references: [
          'https://openid.net/specs/openid-connect-discovery-1_0.html',
          'https://datatracker.ietf.org/doc/html/rfc8414',
        ],
        needsManualReview: true,
        evidenceGrade: 'fingerprint',
        confidence: 0.75,
        submitReady: false,
        source: 'worker',
        discoveredAt: new Date().toISOString(),
      });
    }

    // ── SAML metadata ────────────────────────────────────────────────────
    if ((SAML_PATH.test(url) || SAML_PATH.test(path) || looksSaml(body)) && isSamlMetadata(body)) {
      findings.push({
        id: makeFindingId(this.id, probe.url, 'saml-metadata'),
        checkId: this.id,
        title: 'SAML metadata document exposed',
        severity: 'low',
        target: probe.url,
        description:
          'SAML 2.0 metadata (EntityDescriptor / IDPSSODescriptor) is reachable without auth. Metadata reveals ACS URLs, certificates, and entity IDs used in SSO attacks (assertion forging follow-up, ACS open redirect).',
        evidence: `URL: ${probe.url}\nStatus: ${probe.status}\nBody preview: ${preview(body)}`,
        reproduction: [`curl -s '${probe.url}'`, 'Confirm EntityDescriptor and SSO/ACS endpoints'],
        remediation:
          'Publish only required metadata; protect private keys; validate ACS URLs strictly; prefer signed AuthnRequests where supported.',
        cwe: 'CWE-200',
        references: [
          'https://docs.oasis-open.org/security/saml/v2.0/saml-metadata-2.0-os.pdf',
          'https://cwe.mitre.org/data/definitions/200.html',
        ],
        needsManualReview: true,
        evidenceGrade: 'fingerprint',
        confidence: 0.78,
        submitReady: false,
        source: 'worker',
        discoveredAt: new Date().toISOString(),
      });
    }

    // ── WebSocket / socket.io surfaces ───────────────────────────────────
    const upgrade = (headers['upgrade'] ?? '').toLowerCase();
    const wsAccept = headers['sec-websocket-accept'];
    const socketIo =
      WS_PATH.test(url) ||
      WS_PATH.test(path) ||
      /"upgrades"\s*:\s*\[[^\]]*websocket/i.test(body) ||
      /\bsocket\.io\b/i.test(body.slice(0, 400));

    if (
      upgrade.includes('websocket') ||
      wsAccept ||
      probe.status === 101 ||
      (socketIo && (probe.status >= 200 && probe.status < 500))
    ) {
      // Avoid noise on generic 404 HTML for /ws guesses
      if (
        upgrade.includes('websocket') ||
        wsAccept ||
        probe.status === 101 ||
        /"upgrades"\s*:\s*\[[^\]]*websocket/i.test(body) ||
        (socketIo && !isGenericMiss(probe.status, body, ct))
      ) {
        findings.push({
          id: makeFindingId(this.id, probe.url, 'websocket'),
          checkId: this.id,
          title: 'WebSocket / realtime endpoint discovered',
          severity: 'info',
          target: probe.url,
          description:
            'A WebSocket upgrade or socket.io/realtime polling endpoint is exposed. Realtime channels often skip the same auth/CORS checks as HTTP APIs and warrant authenticated follow-up (message injection, subscription IDOR).',
          evidence: `URL: ${probe.url}\nStatus: ${probe.status}\nUpgrade: ${headers['upgrade'] ?? '<none>'}\nSec-WebSocket-Accept: ${wsAccept ? 'present' : '<none>'}\nBody preview: ${preview(body)}`,
          reproduction: [
            `curl -sI '${probe.url}'`,
            'Inspect Upgrade / socket.io handshake; follow up with authorized WS clients only',
          ],
          remediation:
            'Authenticate WebSocket handshakes; authorize per-channel subscriptions; rate-limit and validate message schemas.',
          cwe: 'CWE-306',
          references: [
            'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/10-Testing_WebSockets',
          ],
          needsManualReview: true,
          evidenceGrade: 'fingerprint',
          confidence: 0.65,
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

function preview(body: string): string {
  return body.slice(0, 240).replace(/\s+/g, ' ');
}

function looksOidcJson(body: string, ct: string): boolean {
  return ct.includes('json') || /^\s*\{/.test(body);
}

function isOidcDiscovery(body: string): boolean {
  if (!body || body.length > 200_000) return false;
  try {
    const j = JSON.parse(body);
    return (
      typeof j === 'object' &&
      j !== null &&
      typeof (j as { issuer?: unknown }).issuer === 'string' &&
      (typeof (j as { jwks_uri?: unknown }).jwks_uri === 'string' ||
        typeof (j as { authorization_endpoint?: unknown }).authorization_endpoint === 'string')
    );
  } catch {
    return (
      /"issuer"\s*:/.test(body) &&
      (/"jwks_uri"\s*:/.test(body) || /"authorization_endpoint"\s*:/.test(body))
    );
  }
}

function looksSaml(body: string): boolean {
  return /EntityDescriptor|IDPSSODescriptor|SPSSODescriptor/i.test(body);
}

function isSamlMetadata(body: string): boolean {
  return (
    /<EntityDescriptor[\s>]/i.test(body) &&
    /(?:IDPSSODescriptor|SPSSODescriptor|SPSSODescriptor|AssertionConsumerService)/i.test(body)
  );
}

function isGenericMiss(status: number, body: string, ct: string): boolean {
  if (status === 404 || status === 403) return true;
  if (ct.includes('text/html') && /not found|404|page not found/i.test(body.slice(0, 500))) return true;
  return false;
}
