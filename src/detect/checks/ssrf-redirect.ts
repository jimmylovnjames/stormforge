// Open redirect + SSRF detection (including cloud metadata exposure).
//
// Uses safe GET canaries on in-scope hosts only. Confirmed open redirects and
// cloud metadata body signatures are high/critical. Never contacts IMDS from
// the Worker directly.

import type { Check, Finding, ProbeResult } from '../../types.js';
import { makeFindingId } from '../../findings/id.js';
import {
  REDIRECT_CANARY_HOST,
  REDIRECT_CANARY_URL,
  detectCloudMetadataExposure,
  hasOpenRedirectToCanary,
  hasSsrfFetchSignal,
  urlCarriesMetadataTarget,
  urlCarriesLoopbackTarget,
  urlCarriesRedirectCanary,
} from '../../recon/ssrf-probes.js';
import { urlCarriesBlindCanary, type CanaryHit } from '../../recon/canary.js';

/** Confirmed blind SSRF when the Worker canary received an outbound hit. */
export function makeBlindSsrfFinding(
  probeUrl: string,
  canaryUrl: string,
  hit: CanaryHit,
): Finding {
  return {
    id: makeFindingId('ssrf-blind-canary', probeUrl, hit.token),
    checkId: 'ssrf-blind-canary',
    title: 'Confirmed blind SSRF — OAST canary hit',
    severity: 'critical',
    target: probeUrl,
    description:
      'The target fetched StormForge’s out-of-band canary URL after a user-controlled URL parameter was supplied. This confirms server-side request forgery (blind SSRF).',
    evidence: `Probe: ${probeUrl}\nCanary: ${canaryUrl}\nHit at: ${hit.hitAt}\nHit method: ${hit.method}\nHit UA: ${hit.userAgent}\nCF-Connecting-IP: ${hit.cfConnectingIp ?? '<unknown>'}`,
    reproduction: [
      `curl -s '${probeUrl}'`,
      `Confirm a hit appears on GET ${canaryUrl} (or Worker KV canary:hit:${hit.token})`,
      'Do not pivot to internal services beyond authorized testing',
    ],
    remediation:
      'Block user-controlled server-side fetches or enforce a strict destination allowlist (deny RFC1918, link-local, metadata, and arbitrary external hosts).',
    cwe: 'CWE-918',
    references: [
      'https://cwe.mitre.org/data/definitions/918.html',
      'https://owasp.org/www-community/attacks/Server_Side_Request_Forgery',
    ],
    needsManualReview: false,
    discoveredAt: new Date().toISOString(),
  };
}

export const ssrfRedirectCheck: Check = {
  id: 'ssrf-open-redirect',
  title: 'SSRF / open redirect / cloud metadata',
  cwe: 'CWE-918',
  run(probe: ProbeResult): Finding[] {
    if (probe.error) return [];
    const findings: Finding[] = [];

    // ── Open redirect to external canary ──────────────────────────────────
    if (hasOpenRedirectToCanary(probe)) {
      findings.push({
        id: makeFindingId(this.id, probe.url, 'open-redirect'),
        checkId: this.id,
        title: 'Open redirect to attacker-controlled URL',
        severity: 'high',
        target: probe.url,
        description:
          `A redirect/URL parameter accepted an external destination (${REDIRECT_CANARY_HOST}) and the application redirected (Location/final URL/meta). Open redirects enable phishing, token theft, and SSRF chains.`,
        evidence: `URL: ${probe.url}\nStatus: ${probe.status}\nLocation: ${probe.headers['location'] ?? '<absent>'}\nFinal-URL: ${probe.finalUrl ?? '<same>'}\nCanary: ${REDIRECT_CANARY_URL}`,
        reproduction: [
          `curl -sI '${stripParams(probe.url)}?url=${encodeURIComponent(REDIRECT_CANARY_URL)}'`,
          `Confirm Location (or followed URL) points to ${REDIRECT_CANARY_HOST}`,
        ],
        remediation:
          'Allowlist redirect destinations (relative paths or trusted hosts only); never reflect arbitrary absolute URLs into Location / meta refresh.',
        cwe: 'CWE-601',
        references: [
          'https://cwe.mitre.org/data/definitions/601.html',
          'https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html',
        ],
        needsManualReview: false,
        discoveredAt: new Date().toISOString(),
      });
    }

    // ── Cloud metadata exposure (SSRF / misconfig) ────────────────────────
    if (probe.body) {
      const cloud = detectCloudMetadataExposure(probe.body);
      if (cloud) {
        const viaProbe = urlCarriesMetadataTarget(probe.url);
        findings.push({
          id: makeFindingId(this.id, probe.url, `metadata:${cloud}`),
          checkId: this.id,
          title:
            cloud === 'aws' && /AccessKeyId/i.test(probe.body)
              ? 'Cloud metadata credentials exposed (AWS IAM)'
              : `Cloud instance metadata exposed (${cloud.toUpperCase()})`,
          severity: 'critical',
          target: probe.url,
          description: viaProbe
            ? `A URL parameter pointing at cloud metadata returned ${cloud.toUpperCase()} instance metadata content. This is a confirmed SSRF-to-IMDS sink and can yield temporary cloud credentials and host compromise.`
            : `The response body contains ${cloud.toUpperCase()} instance metadata signatures. If reachable without auth, this is equivalent to SSRF-to-IMDS / metadata disclosure.`,
          evidence: `URL: ${probe.url}\nStatus: ${probe.status}\nCloud: ${cloud}\nVia metadata canary param: ${viaProbe}\nBody preview: ${preview(probe.body)}`,
          reproduction: [
            viaProbe
              ? `curl -s '${stripParams(probe.url)}?url=${encodeURIComponent('http://169.254.169.254/latest/meta-data/')}'`
              : `curl -s '${probe.url}'`,
            'Confirm AMI/instance/project metadata or AccessKeyId appears — do not use any credentials',
          ],
          remediation:
            'Block link-local and metadata hosts in server-side fetchers; require IMDSv2/hop limits; never return raw metadata to clients; enforce egress allowlists.',
          cwe: 'CWE-918',
          references: [
            'https://cwe.mitre.org/data/definitions/918.html',
            'https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instancedata-data-retrieval.html',
            'https://owasp.org/www-community/attacks/Server_Side_Request_Forgery',
          ],
          needsManualReview: false,
          discoveredAt: new Date().toISOString(),
        });
      }
    }

    // ── Soft SSRF: fetch errors / loopback after canary ───────────────────
    if (probe.body && hasSsrfFetchSignal(probe.body, probe.url)) {
      findings.push({
        id: makeFindingId(this.id, probe.url, 'ssrf-fetch-signal'),
        checkId: this.id,
        title: 'Possible SSRF — server fetched internal/metadata URL',
        severity: 'high',
        target: probe.url,
        description:
          'After supplying a loopback or cloud-metadata URL in a parameter, the response shows connection/metadata fetch errors or internal hostnames. This strongly suggests a server-side request (SSRF) sink.',
        evidence: `URL: ${probe.url}\nStatus: ${probe.status}\nMetadata param: ${urlCarriesMetadataTarget(probe.url)}\nLoopback param: ${urlCarriesLoopbackTarget(probe.url)}\nBody preview: ${preview(probe.body)}`,
        reproduction: [
          `curl -s '${stripParams(probe.url)}?url=${encodeURIComponent('http://127.0.0.1/')}'`,
          'Observe error text referencing localhost / 169.254.169.254 / connection failures',
        ],
        remediation:
          'Disable user-controlled server-side fetches or restrict destinations with a strict allowlist (deny RFC1918, link-local, metadata).',
        cwe: 'CWE-918',
        references: ['https://cwe.mitre.org/data/definitions/918.html'],
        needsManualReview: true,
        discoveredAt: new Date().toISOString(),
      });
    }

    // ── Passive: redirect param reflected into Location without canary ────
    if (!urlCarriesRedirectCanary(probe.url) && isExternalLocationReflection(probe)) {
      findings.push({
        id: makeFindingId(this.id, probe.url, 'location-reflect'),
        checkId: this.id,
        title: 'Redirect parameter reflected into Location header',
        severity: 'high',
        target: probe.url,
        description:
          'An absolute URL supplied via a redirect-related query parameter appears in the Location header. This is an open-redirect candidate.',
        evidence: `URL: ${probe.url}\nStatus: ${probe.status}\nLocation: ${probe.headers['location'] ?? '<absent>'}`,
        reproduction: [
          `curl -sI '${probe.url}'`,
          'Confirm Location mirrors the user-supplied absolute URL',
        ],
        remediation: 'Allowlist redirect targets; reject absolute external URLs unless explicitly trusted.',
        cwe: 'CWE-601',
        references: ['https://cwe.mitre.org/data/definitions/601.html'],
        needsManualReview: true,
        discoveredAt: new Date().toISOString(),
      });
    }

    // ── Blind OAST canary echo (soft — confirmed hits are added by scanner via KV) ──
    if (probe.body && urlCarriesBlindCanary(probe.url) && /\/api\/canary\/[a-f0-9]{16,}/i.test(probe.body)) {
      findings.push({
        id: makeFindingId(this.id, probe.url, 'blind-canary-echo'),
        checkId: this.id,
        title: 'Possible SSRF — blind canary URL echoed in response',
        severity: 'medium',
        target: probe.url,
        description:
          'A Worker OAST canary URL supplied in a fetch/redirect parameter was reflected in the response body. Await canary hit confirmation for a high-confidence SSRF finding.',
        evidence: `URL: ${probe.url}\nStatus: ${probe.status}\nBody preview: ${preview(probe.body)}`,
        reproduction: [
          `curl -s '${probe.url}'`,
          'Confirm the canary URL is reflected; check Worker /api/canary hit logs for outbound fetch',
        ],
        remediation:
          'Disable user-controlled server-side fetches or restrict destinations with a strict allowlist.',
        cwe: 'CWE-918',
        references: ['https://cwe.mitre.org/data/definitions/918.html'],
        needsManualReview: true,
        discoveredAt: new Date().toISOString(),
      });
    }

    return findings;
  },
};

function isExternalLocationReflection(probe: ProbeResult): boolean {
  const location = probe.headers['location'];
  if (!location) return false;
  if (!/^https?:\/\//i.test(location)) return false;
  let locHost: string;
  try {
    locHost = new URL(location).hostname.toLowerCase();
  } catch {
    return false;
  }
  let reqHost: string;
  try {
    reqHost = new URL(probe.url).hostname.toLowerCase();
  } catch {
    return false;
  }
  if (locHost === reqHost) return false;

  // Param value must match Location (decoded).
  try {
    const u = new URL(probe.url);
    for (const v of u.searchParams.values()) {
      if (!v) continue;
      if (v === location || v.includes(locHost) || location.includes(v)) return true;
    }
  } catch {
    return false;
  }
  return false;
}

function stripParams(url: string): string {
  try {
    const u = new URL(url);
    u.search = '';
    return u.toString();
  } catch {
    return url.split('?')[0] ?? url;
  }
}

function preview(body: string): string {
  return body.slice(0, 240).replace(/\s+/g, ' ');
}
