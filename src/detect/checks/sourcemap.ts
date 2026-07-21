// JavaScript/CSS source map exposure (comment + confirmed .map bodies).

import type { Check, Finding, ProbeResult } from '../../types.js';
import { makeFindingId } from '../../findings/id.js';
import {
  extractSourceMappingUrls,
  hasSourcesContent,
  isSourceMapJson,
} from '../../recon/sourcemap-probes.js';

export const sourcemapCheck: Check = {
  id: 'sourcemap-exposure',
  title: 'JavaScript source map exposure',
  cwe: 'CWE-540',
  run(probe: ProbeResult): Finding[] {
    if (probe.error || !probe.body) return [];
    if (probe.status < 200 || probe.status >= 300) return [];

    const findings: Finding[] = [];
    const url = probe.finalUrl ?? probe.url;
    const path = safePath(url);
    const ct = (probe.headers['content-type'] ?? '').toLowerCase();

    // Confirmed .map JSON
    if (
      (path.endsWith('.map') || ct.includes('json') || ct.includes('sourcemap')) &&
      isSourceMapJson(probe.body)
    ) {
      const withContent = hasSourcesContent(probe.body);
      findings.push({
        id: makeFindingId(this.id, probe.url, withContent ? 'sourcesContent' : 'map'),
        checkId: this.id,
        title: withContent
          ? 'Source map exposes original sourcesContent'
          : 'Source map JSON publicly accessible',
        severity: withContent ? 'medium' : 'low',
        target: probe.url,
        description: withContent
          ? 'A production source map includes sourcesContent (original source). This often leaks internal paths, comments, and secrets that minification hid.'
          : 'A version-3 source map is publicly reachable. Even without sourcesContent, `sources` paths reveal internal structure and aid targeted attacks.',
        evidence: `URL: ${probe.url}\nStatus: ${probe.status}\nsourcesContent: ${withContent}\nBody preview: ${preview(probe.body)}`,
        reproduction: [`curl -s '${probe.url}'`, 'Confirm version:3 and sources / sourcesContent'],
        remediation:
          'Do not deploy .map files to production (or restrict them); strip sourceMappingURL from bundles; never embed secrets in client source.',
        cwe: 'CWE-540',
        references: [
          'https://cwe.mitre.org/data/definitions/540.html',
          'https://developer.mozilla.org/en-US/docs/Tools/Debugger/How_to/Use_a_source_map',
        ],
        needsManualReview: !withContent,
        evidenceGrade: 'fingerprint',
        confidence: withContent ? 0.82 : 0.7,
        submitReady: withContent,
        source: 'worker',
        discoveredAt: new Date().toISOString(),
      });
      return findings;
    }

    // JS/CSS advertising a map URL
    const maps = extractSourceMappingUrls(probe.body, url);
    if (maps.length) {
      findings.push({
        id: makeFindingId(this.id, probe.url, 'comment'),
        checkId: this.id,
        title: 'Bundle advertises sourceMappingURL',
        severity: 'info',
        target: probe.url,
        description:
          'The response contains a sourceMappingURL comment pointing at a .map file. If that map is reachable, original source and secrets may leak.',
        evidence: `URL: ${probe.url}\nStatus: ${probe.status}\nmaps: ${maps.slice(0, 5).join(', ')}\nBody preview: ${preview(probe.body)}`,
        reproduction: [
          `curl -s '${probe.url}' | tail`,
          `Fetch map URL(s): ${maps.slice(0, 2).join(', ')}`,
        ],
        remediation: 'Remove sourceMappingURL from production assets and block public access to .map files.',
        cwe: 'CWE-540',
        references: ['https://cwe.mitre.org/data/definitions/540.html'],
        needsManualReview: true,
        evidenceGrade: 'fingerprint',
        confidence: 0.6,
        submitReady: false,
        source: 'worker',
        discoveredAt: new Date().toISOString(),
      });
    }

    return findings;
  },
};

function safePath(url: string): string {
  try {
    return new URL(url).pathname.toLowerCase();
  } catch {
    return url.toLowerCase();
  }
}

function preview(body: string): string {
  return body.slice(0, 220).replace(/\s+/g, ' ');
}
