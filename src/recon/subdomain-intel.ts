// Rank and parse subdomain enumeration output for smarter follow-ups.

const HIGH_VALUE = [
  'api',
  'admin',
  'staging',
  'stage',
  'dev',
  'test',
  'qa',
  'internal',
  'portal',
  'auth',
  'sso',
  'vpn',
  'git',
  'jenkins',
  'grafana',
  'kibana',
  'dashboard',
  'manage',
  'backend',
  'graphql',
];

const LOW_VALUE = ['www', 'cdn', 'static', 'img', 'images', 'assets', 'mail', 'mx', 'ns1', 'ns2'];

/** Extract hostnames under an optional apex from tool stdout / evidence. */
export function parseSubdomains(text: string, apex?: string): string[] {
  if (!text) return [];
  const out: string[] = [];
  const seen = new Set<string>();
  for (const line of text.split(/\n/)) {
    for (const m of line.matchAll(/(?:https?:\/\/)?([a-z0-9._-]+\.[a-z]{2,})(?:[:/\s]|$)/gi)) {
      const host = m[1]!.toLowerCase().replace(/\.$/, '');
      if (!host.includes('.')) continue;
      if (apex) {
        const a = apex.toLowerCase().replace(/^\*\./, '');
        if (host !== a && !host.endsWith(`.${a}`)) continue;
      }
      if (seen.has(host)) continue;
      seen.add(host);
      out.push(host);
    }
  }
  return out;
}

export function scoreSubdomain(host: string): number {
  const labels = host.toLowerCase().split('.');
  const leaf = labels[0] ?? '';
  let score = 1;
  if (HIGH_VALUE.includes(leaf)) score += 10;
  if (HIGH_VALUE.some((h) => leaf.includes(h))) score += 6;
  if (LOW_VALUE.includes(leaf)) score -= 3;
  if (labels.length >= 4) score += 2; // deeper subdomains often interesting
  if (/^\d/.test(leaf)) score -= 1;
  return score;
}

/** Highest-value hosts first, capped. Prefers positive-score hosts. */
export function rankSubdomains(hosts: string[], cap = 8): string[] {
  const scored = [...new Set(hosts.map((h) => h.toLowerCase()))]
    .map((h) => ({ h, s: scoreSubdomain(h) }))
    .sort((a, b) => b.s - a.s || a.h.localeCompare(b.h));
  const positive = scored.filter((x) => x.s > 0);
  const picked = (positive.length >= Math.min(cap, 1) ? positive : scored).slice(0, cap);
  return picked.map((x) => x.h);
}
