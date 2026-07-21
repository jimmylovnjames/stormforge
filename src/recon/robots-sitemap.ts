// Parse robots.txt Disallow and sitemap.xml <loc> into probe pathnames.

const MAX = 40;

/** Extract Disallow pathnames from a robots.txt body. */
export function extractRobotsPaths(body: string): string[] {
  if (!body) return [];
  const out = new Set<string>();
  for (const line of body.split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;
    const m = trimmed.match(/^Disallow:\s*(\/\S*)/i);
    if (!m?.[1] || m[1] === '/') continue;
    // Strip trailing wildcards / query for probing seeds
    const path = m[1].replace(/\*.*$/, '').replace(/\$$/, '');
    if (path.startsWith('/')) out.add(path);
    if (out.size >= MAX) break;
  }
  return [...out];
}

/** Extract same-origin (or relative) pathnames from sitemap <loc> entries. */
export function extractSitemapLocPaths(body: string, baseUrl: string): string[] {
  if (!body) return [];
  let base: URL;
  try {
    base = new URL(baseUrl);
  } catch {
    return [];
  }
  const out = new Set<string>();
  const re = /<loc>\s*([^<]+?)\s*<\/loc>/gi;
  let m: RegExpExecArray | null;
  while ((m = re.exec(body)) !== null) {
    const raw = m[1]!.trim();
    if (!raw) continue;
    try {
      const abs = new URL(raw, base);
      if (abs.protocol !== 'http:' && abs.protocol !== 'https:') continue;
      // Prefer same-host; relative locs already resolve against base.
      if (abs.hostname !== base.hostname && abs.hostname !== `www.${base.hostname}`) {
        // Also allow sibling if apex matches last two labels
        const a = abs.hostname.split('.').slice(-2).join('.');
        const b = base.hostname.split('.').slice(-2).join('.');
        if (a !== b) continue;
      }
      if (abs.pathname && abs.pathname !== '/') out.add(abs.pathname);
    } catch {
      /* skip */
    }
    if (out.size >= MAX) break;
  }
  return [...out];
}

/** Paths that robots Disallow often accidentally advertise as sensitive. */
const SENSITIVE =
  /(?:^|\/)(?:\.git|\.env|\.svn|\.hg|admin|backup|private|internal|secret|config|debug|phpmyadmin|wp-admin|actuator|manage|staging|tmp|dump|db)(?:\/|$|\.)/i;

export function isSensitiveRobotsPath(path: string): boolean {
  return SENSITIVE.test(path);
}

export function sensitiveRobotsPaths(paths: string[]): string[] {
  return paths.filter(isSensitiveRobotsPath).slice(0, 20);
}
