// Safe GET injection / reflection probe helpers.
// Unique canaries only — no exploit payloads that execute against the operator.
// Math canaries use uncommon products to keep SSTI false positives low.

/** Unique marker unlikely to appear in normal page content. */
export const XSS_CANARY = 'sfXss9f3a7c';

/**
 * Reflection probe: if the server echoes this intact (unescaped), the page is
 * vulnerable to reflected XSS. Does not include event-handler exploit code.
 */
export const XSS_PAYLOAD = `"><${XSS_CANARY}>`;

/** SSTI expression — evaluates to SSTI_RESULT in common template engines. */
export const SSTI_EXPR = '{{881*721}}';
export const SSTI_RESULT = '635201'; // 881 * 721

/** Alternate SSTI forms for engines that ignore Jinja/Twig braces. */
export const SSTI_EXPR_ALT = '${881*721}';
export const SSTI_EXPR_ERB = '<%=881*721%>';

/** Query param names commonly reflected into HTML/JSON. */
export const REFLECTION_PARAM_NAMES = [
  'q',
  'query',
  'search',
  's',
  'keyword',
  'name',
  'message',
  'error',
  'redirect',
  'url',
  'next',
  'return',
  'callback',
  'input',
  'text',
] as const;

export interface InjectionProbeUrls {
  xss: string[];
  ssti: string[];
}

/** Build capped XSS + SSTI follow-up GET URLs for a base endpoint. */
export function buildInjectionProbeUrls(baseUrl: string, maxParams = 3): InjectionProbeUrls {
  const xss: string[] = [];
  const ssti: string[] = [];
  try {
    for (const param of REFLECTION_PARAM_NAMES.slice(0, maxParams)) {
      const uXss = new URL(baseUrl);
      // Drop prior injection params to keep requests small.
      for (const p of REFLECTION_PARAM_NAMES) uXss.searchParams.delete(p);
      uXss.searchParams.set(param, XSS_PAYLOAD);
      xss.push(uXss.toString());

      const uSsti = new URL(baseUrl);
      for (const p of REFLECTION_PARAM_NAMES) uSsti.searchParams.delete(p);
      uSsti.searchParams.set(param, SSTI_EXPR);
      ssti.push(uSsti.toString());
    }
  } catch {
    return { xss: [], ssti: [] };
  }
  return { xss, ssti };
}

export function urlCarriesXssCanary(url: string): boolean {
  try {
    const u = new URL(url);
    for (const v of u.searchParams.values()) {
      if (v.includes(XSS_CANARY) || v.includes(XSS_PAYLOAD)) return true;
    }
  } catch {
    return url.includes(XSS_CANARY);
  }
  return false;
}

export function urlCarriesSstiCanary(url: string): boolean {
  try {
    const u = new URL(url);
    for (const v of u.searchParams.values()) {
      if (v.includes('881*721') || v.includes(SSTI_EXPR) || v.includes(SSTI_EXPR_ALT)) return true;
    }
  } catch {
    return url.includes('881*721');
  }
  return false;
}

/**
 * True when the XSS canary appears in the body without HTML entity escaping.
 * Confirmed reflected XSS signal (high confidence).
 */
export function hasUnescapedXssReflection(body: string): boolean {
  if (!body.includes(XSS_CANARY)) return false;
  // Intact payload reflection (strongest).
  if (body.includes(XSS_PAYLOAD)) return true;
  if (body.includes(`<${XSS_CANARY}>`)) return true;
  // Canary inside an unescaped attribute break or raw text context.
  if (new RegExp(`["'][^"'<]{0,40}${XSS_CANARY}`).test(body) && !body.includes(`&quot;${XSS_CANARY}`)) {
    // Ensure at least one occurrence is not entity-encoded.
    const withoutEntities = body
      .replace(/&lt;/gi, '')
      .replace(/&gt;/gi, '')
      .replace(/&quot;/gi, '')
      .replace(/&#x27;/gi, '')
      .replace(/&#39;/gi, '');
    return withoutEntities.includes(XSS_CANARY);
  }
  // Entity-only reflections are not XSS.
  const entityOnly =
    body.includes(`&lt;${XSS_CANARY}`) ||
    body.includes(`&quot;${XSS_CANARY}`) ||
    body.includes(`&#39;${XSS_CANARY}`);
  if (entityOnly && !body.includes(`<${XSS_CANARY}`) && !body.includes(`"${XSS_CANARY}`)) {
    return false;
  }
  return false;
}

/**
 * SSTI confirmed when the product appears and the original expression does not
 * (engine evaluated it). Requires the probe URL to have carried the expression.
 */
export function hasSstiEvaluation(body: string, probeUrl: string): boolean {
  if (!urlCarriesSstiCanary(probeUrl)) return false;
  if (!body.includes(SSTI_RESULT)) return false;
  // If the raw expression is still present, it was echoed not evaluated.
  if (body.includes(SSTI_EXPR) || body.includes(SSTI_EXPR_ALT) || body.includes(SSTI_EXPR_ERB)) {
    return false;
  }
  return true;
}

/** Paths that often reflect query input into HTML. */
export const REFLECTION_PATHS: string[] = [
  '/search',
  '/q',
  '/query',
  '/find',
  '/lookup',
  '/redirect',
  '/return',
  '/callback',
  '/error',
  '/message',
  '/name',
  '/echo',
  '/debug',
  '/test',
];

/** Whether a probe is a good candidate for injection follow-up GETs. */
export function shouldProbeInjection(probe: {
  url: string;
  status: number;
  headers: Record<string, string>;
  body: string;
  error?: string;
}): boolean {
  if (probe.error) return false;
  if (probe.status < 200 || probe.status >= 400) return false;
  const ct = (probe.headers['content-type'] ?? '').toLowerCase();
  const path = safePath(probe.url);
  if (REFLECTION_PATHS.some((p) => path === p || path.endsWith(p))) return true;
  if (ct.includes('text/html')) return true;
  if (ct.includes('application/json') && /search|query|q=|message/i.test(probe.url)) return true;
  // Forms that accept input often reflect it.
  if (ct.includes('text/html') && /<form[\s>]/i.test(probe.body)) return true;
  return false;
}

function safePath(url: string): string {
  try {
    return new URL(url).pathname.toLowerCase();
  } catch {
    return url.toLowerCase();
  }
}
