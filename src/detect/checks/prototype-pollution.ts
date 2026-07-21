// Prototype pollution + mass-assignment detection from safe GET canaries.

import type { Check, Finding, ProbeResult } from '../../types.js';
import { makeFindingId } from '../../findings/id.js';
import {
  PP_CANARY_KEY,
  PP_CANARY_VALUE,
  hasMassAssignmentSignal,
  hasPrototypePollutionReflection,
  urlCarriesPpPayload,
} from '../../recon/pp-probes.js';

export const prototypePollutionCheck: Check = {
  id: 'prototype-pollution',
  title: 'Prototype pollution / mass assignment',
  cwe: 'CWE-1321',
  run(probe: ProbeResult): Finding[] {
    if (probe.error || !probe.body) return [];
    if (probe.status < 200 || probe.status >= 500) return [];

    const findings: Finding[] = [];

    if (hasPrototypePollutionReflection(probe.body, probe.url)) {
      findings.push({
        id: makeFindingId(this.id, probe.url, 'pp'),
        checkId: this.id,
        title: 'Prototype pollution — polluted property reflected in JSON',
        severity: 'high',
        target: probe.url,
        description:
          `A GET __proto__/constructor[prototype] canary caused \`${PP_CANARY_KEY}=${PP_CANARY_VALUE}\` to appear as an object property in the response. This indicates prototype pollution (CWE-1321), which can escalate to RCE, auth bypass, or denial of service depending on gadget chains.`,
        evidence: `URL: ${probe.url}\nStatus: ${probe.status}\nCanary key: ${PP_CANARY_KEY}\nCanary value: ${PP_CANARY_VALUE}\nBody preview: ${probe.body.slice(0, 240).replace(/\s+/g, ' ')}`,
        reproduction: [
          `curl -s '${strip(probe.url)}?__proto__[${PP_CANARY_KEY}]=${PP_CANARY_VALUE}'`,
          `Confirm JSON contains "${PP_CANARY_KEY}":"${PP_CANARY_VALUE}"`,
        ],
        remediation:
          'Use Object.create(null) / Map for dictionaries; block __proto__ and constructor paths in query/body parsers; freeze prototypes; upgrade vulnerable merge/clone libraries.',
        cwe: 'CWE-1321',
        references: [
          'https://cwe.mitre.org/data/definitions/1321.html',
          'https://portswigger.net/web-security/prototype-pollution',
        ],
        needsManualReview: false,
        discoveredAt: new Date().toISOString(),
      });
    }

    if (hasMassAssignmentSignal(probe.body, probe.url)) {
      findings.push({
        id: makeFindingId(this.id, probe.url, 'mass'),
        checkId: this.id,
        title: 'Mass assignment — privileged field accepted from query',
        severity: 'high',
        target: probe.url,
        description:
          'Privileged fields (isAdmin / role=admin) supplied via query parameters appear accepted in the JSON response. This is mass assignment (CWE-915) and can lead to privilege escalation.',
        evidence: `URL: ${probe.url}\nStatus: ${probe.status}\nBody preview: ${probe.body.slice(0, 240).replace(/\s+/g, ' ')}`,
        reproduction: [
          `curl -s '${strip(probe.url)}?isAdmin=true&role=admin'`,
          'Confirm response JSON includes isAdmin:true or role:"admin"',
        ],
        remediation:
          'Allowlist writable fields per endpoint; never bind raw request params to privileged model attributes.',
        cwe: 'CWE-915',
        references: [
          'https://cwe.mitre.org/data/definitions/915.html',
          'https://owasp.org/www-community/vulnerabilities/Mass_Assignment',
        ],
        needsManualReview: true,
        discoveredAt: new Date().toISOString(),
      });
    }

    // Avoid empty when URL didn't carry payload (passive false path)
    if (!findings.length && !urlCarriesPpPayload(probe.url)) return [];
    return findings;
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
