// Open redirect (active, canary-confirmed). Reads the active open-redirect probe
// emitted by the scanner and confirms when the response redirects to our canary.

import type { Check, Finding, ProbeResult } from '../../types.js';
import { makeFindingId } from '../../findings/id.js';
import {
  ACTIVE_MARKER_HEADER,
  ACTIVE_PARAM_HEADER,
  CANARY_HOST,
  isCanaryRedirect,
  bodyReflectsCanary,
} from '../../recon/active-probes.js';

export const openRedirectCheck: Check = {
  id: 'open-redirect',
  title: 'Open redirect',
  cwe: 'CWE-601',
  run(probe: ProbeResult): Finding[] {
    if ((probe.headers[ACTIVE_MARKER_HEADER] ?? '') !== 'open-redirect') return [];
    const canaryHost = CANARY_HOST;
    const param = probe.headers[ACTIVE_PARAM_HEADER] ?? 'redirect';
    const location = probe.headers['location'] ?? '';

    const viaLocation = probe.status >= 300 && probe.status < 400 && isCanaryRedirect(location, canaryHost);
    // Meta-refresh / JS redirect to the canary in a 2xx body is also an open redirect.
    const viaBody = probe.status >= 200 && probe.status < 300 && bodyReflectsCanary(probe.body, canaryHost);
    if (!viaLocation && !viaBody) return [];

    const mechanism = viaLocation ? `HTTP ${probe.status} Location` : 'meta/JS redirect in body';
    return [
      {
        id: makeFindingId(this.id, probe.url, param),
        checkId: this.id,
        title: `Open redirect via \`${param}\` parameter`,
        severity: 'medium',
        target: probe.url,
        description: `The \`${param}\` parameter controls the redirect destination: a request with an attacker-supplied absolute URL was followed to an external host (${mechanism}). Open redirects enable phishing and can escalate to OAuth token/code theft when the endpoint is a login/callback.`,
        evidence: `URL: ${probe.url}\nStatus: ${probe.status}\nParameter: ${param}\nCanary host: ${canaryHost}\n${viaLocation ? `Location: ${location.slice(0, 200)}` : `Body reflected canary as an absolute URL`}`,
        reproduction: [
          `curl -sI '${probe.url}'`,
          `Confirm the response redirects to the ${canaryHost} canary host you supplied in \`${param}\``,
          'Swap the canary for any attacker-controlled URL to demonstrate impact (phishing / OAuth theft)',
        ],
        remediation:
          'Do not redirect to user-supplied absolute URLs. Allowlist relative paths or an explicit set of trusted destinations; reject external hosts and protocol-relative values.',
        cwe: 'CWE-601',
        references: [
          'https://cwe.mitre.org/data/definitions/601.html',
          'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/04-Testing_for_Client-side_URL_Redirect',
        ],
        needsManualReview: true,
        evidenceGrade: 'canary',
        confidence: viaLocation ? 0.9 : 0.75,
        submitReady: viaLocation,
        source: 'worker',
        discoveredAt: new Date().toISOString(),
      },
    ];
  },
};
