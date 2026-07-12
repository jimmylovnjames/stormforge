// Passive technology fingerprinting from response headers and body markers.
// Read-only: infers stack/versions to feed the version-CVE check. No probing
// beyond the response already fetched.

import type { ProbeResult } from '../types.js';

export interface TechMatch {
  product: string;
  version?: string;
  source: string; // where we saw it
}

interface HeaderRule {
  header: string;
  product: string;
  /** Capture group 1 = version, if present. */
  versionRegex?: RegExp;
}

const HEADER_RULES: HeaderRule[] = [
  { header: 'server', product: 'nginx', versionRegex: /nginx\/([\d.]+)/i },
  { header: 'server', product: 'Apache', versionRegex: /Apache\/([\d.]+)/i },
  { header: 'server', product: 'Microsoft-IIS', versionRegex: /IIS\/([\d.]+)/i },
  { header: 'x-powered-by', product: 'PHP', versionRegex: /PHP\/([\d.]+)/i },
  { header: 'x-powered-by', product: 'Express' },
  { header: 'x-powered-by', product: 'ASP.NET' },
  { header: 'x-generator', product: 'Drupal', versionRegex: /Drupal ([\d.]+)/i },
  { header: 'x-drupal-cache', product: 'Drupal' },
];

const BODY_RULES: { product: string; regex: RegExp }[] = [
  { product: 'WordPress', regex: /<meta name="generator" content="WordPress ([\d.]+)"/i },
  { product: 'Drupal', regex: /Drupal ([\d.]+)/i },
  { product: 'jQuery', regex: /jquery[-.]?([\d.]+)(?:\.min)?\.js/i },
];

export function fingerprint(probe: ProbeResult): TechMatch[] {
  const out: TechMatch[] = [];
  const seen = new Set<string>();

  const add = (m: TechMatch) => {
    const key = `${m.product}@${m.version ?? '?'}`;
    if (!seen.has(key)) {
      seen.add(key);
      out.push(m);
    }
  };

  for (const rule of HEADER_RULES) {
    const value = probe.headers[rule.header];
    if (!value) continue;
    if (rule.versionRegex) {
      const m = value.match(rule.versionRegex);
      if (m) add({ product: rule.product, version: m[1], source: `header:${rule.header}` });
      else if (value.toLowerCase().includes(rule.product.toLowerCase()))
        add({ product: rule.product, source: `header:${rule.header}` });
    } else {
      add({ product: rule.product, source: `header:${rule.header}` });
    }
  }

  if (probe.body) {
    for (const rule of BODY_RULES) {
      const m = probe.body.match(rule.regex);
      if (m) add({ product: rule.product, version: m[1], source: 'body' });
    }
  }

  return out;
}
