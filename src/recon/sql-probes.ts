// Safe GET SQL-injection canary helpers (error / fingerprint only — no dumps).

/** Unique comment marker embedded in payloads for correlation. */
export const SQL_CANARY = 'sfSql9f3a7c';

/** Lightweight payloads that provoke DB errors without UNION dumps or shells. */
export const SQL_ERROR_PAYLOADS = [
  `'`,
  `"`,
  `' OR '${SQL_CANARY}'='${SQL_CANARY}`,
  `" OR "${SQL_CANARY}"="${SQL_CANARY}`,
  `1' AND '${SQL_CANARY}'='${SQL_CANARY}`,
  `1);-- /*${SQL_CANARY}*/`,
  `' WAITFOR DELAY '0:0:0'-- /*${SQL_CANARY}*/`,
] as const;

export const SQL_PARAM_NAMES = [
  'id',
  'user_id',
  'uid',
  'item',
  'product',
  'cat',
  'category',
  'sort',
  'order',
  'q',
  'search',
  'filter',
  'page',
  'offset',
] as const;

export const SQL_PATHS: string[] = [
  '/search',
  '/api/search',
  '/api/users',
  '/api/v1/users',
  '/api/v1/items',
  '/api/products',
  '/product',
  '/products',
  '/item',
  '/items',
  '/user',
  '/users',
  '/catalog',
  '/query',
  '/api/query',
];

/** High-confidence DB error fingerprints (engine-specific). */
const DB_ERROR_PATTERNS: RegExp[] = [
  /you have an error in your sql syntax/i,
  /warning: mysql_/i,
  /mysql_fetch_/i,
  /pg_query\(/i,
  /postgresql.*error/i,
  /org\.postgresql\.util\.psqlexception/i,
  /unclosed quotation mark after the character string/i,
  /microsoft ole db provider for sql server/i,
  /odbc sql server driver/i,
  /sqlstate\[/i,
  /ora-\d{5}/i,
  /sqlite3?\.OperationalError/i,
  /SQLiteException/i,
  /syntax error at or near/i,
  /quoted string not properly terminated/i,
  /SQLSyntaxErrorException/i,
  /com\.mysql\.jdbc/i,
  /MariaDB/i,
  /near ".*": syntax error/i,
];

export function buildSqlInjectionProbeUrls(baseUrl: string, maxParams = 2): string[] {
  const out: string[] = [];
  try {
    for (const param of SQL_PARAM_NAMES.slice(0, maxParams)) {
      for (const payload of SQL_ERROR_PAYLOADS.slice(0, 4)) {
        const u = new URL(baseUrl);
        for (const p of SQL_PARAM_NAMES) u.searchParams.delete(p);
        u.searchParams.set(param, payload);
        out.push(u.toString());
      }
    }
  } catch {
    return [];
  }
  return out;
}

export function urlCarriesSqlPayload(url: string): boolean {
  try {
    for (const v of new URL(url).searchParams.values()) {
      if (v.includes(SQL_CANARY) || /['"]\s*(or|and)\s*/i.test(v) || v === "'" || v === '"') {
        return true;
      }
      if (/waitfor\s+delay/i.test(v) || /\/\*sfSql/.test(v)) return true;
    }
  } catch {
    return /sfSql9f3a7c|['"]/.test(url);
  }
  return false;
}

export function hasSqlErrorFingerprint(body: string): boolean {
  if (!body || body.length < 8) return false;
  return DB_ERROR_PATTERNS.some((re) => re.test(body));
}

export function shouldProbeSqlInjection(probe: {
  url: string;
  status: number;
  headers: Record<string, string>;
  body: string;
  error?: string;
}): boolean {
  if (probe.error || probe.status === 0) return false;
  const path = safePath(probe.url);
  if (SQL_PATHS.some((p) => path === p || path.endsWith(p))) return true;
  if (/[?&](?:id|user_id|uid|item|product|cat|sort|order|q|search|filter)=/i.test(probe.url)) {
    return true;
  }
  // Live API JSON surfaces are high-value for id= params.
  const ct = (probe.headers['content-type'] ?? '').toLowerCase();
  if (ct.includes('json') && path.startsWith('/api') && probe.status >= 200 && probe.status < 500) {
    return true;
  }
  return false;
}

function safePath(url: string): string {
  try {
    return new URL(url).pathname.toLowerCase();
  } catch {
    return url.toLowerCase();
  }
}
