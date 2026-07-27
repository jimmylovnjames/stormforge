// Insecure sub-resource loading. Passive: parses the HTML body only and never
// fetches the referenced resources. Emits three related classes of finding, all
// about *how* a page pulls in external code/content:
//
//   1. Mixed content — an HTTPS page that loads active sub-resources (scripts,
//      iframes, stylesheets, objects) over cleartext http:// (CWE-319). Browsers
//      block or downgrade these, but they remain a real MITM/injection vector
//      and a reportable hardening gap.
//   2. Insecure form action — a form that submits to an http:// endpoint, i.e.
//      credentials/data travel in cleartext (CWE-319). Higher signal when the
//      form looks like a login (password field present).
//   3. Missing Subresource Integrity — a cross-origin <script>/<link> pulled in
//      without an `integrity=` attribute (CWE-353). If the third party (or its
//      CDN) is compromised, arbitrary code runs in the page's origin.

import type { Check, Finding, ProbeResult } from '../../types.js';
import { makeFindingId } from '../../findings/id.js';

type ResourceKind = 'script' | 'iframe' | 'stylesheet' | 'object';

interface Resource {
  kind: ResourceKind;
  url: string;
  integrity: boolean;
  crossOrigin: boolean;
  insecure: boolean;
}

/** Active sub-resource kinds ranked for mixed-content severity. */
const MIXED_SEVERITY: Record<ResourceKind, Finding['severity']> = {
  script: 'medium',
  iframe: 'medium',
  object: 'medium',
  stylesheet: 'low',
};

export const insecureSubresourceCheck: Check = {
  id: 'insecure-subresource',
  title: 'Insecure sub-resource loading (mixed content & missing SRI)',
  cwe: 'CWE-319',
  run(probe: ProbeResult): Finding[] {
    if (probe.error || !probe.body) return [];
    if (probe.status < 200 || probe.status >= 300) return [];
    const ct = (probe.headers['content-type'] ?? '').toLowerCase();
    const looksHtml = ct.includes('text/html') || (ct === '' && /<(!doctype|html|script|link|iframe|form)\b/i.test(probe.body));
    if (!looksHtml) return [];

    const pageUrl = probe.finalUrl ?? probe.url;
    const pageOrigin = originOf(pageUrl);
    const pageIsHttps = pageOrigin?.protocol === 'https:';

    const resources = extractResources(probe.body, pageUrl, pageOrigin);
    const forms = extractFormActions(probe.body, pageUrl);
    const now = new Date().toISOString();
    const findings: Finding[] = [];

    // 1) Mixed active content on an HTTPS page.
    if (pageIsHttps) {
      const mixed = resources.filter((r) => r.insecure);
      if (mixed.length) {
        const worst = mixed.reduce<Finding['severity']>(
          (acc, r) => maxSeverity(acc, MIXED_SEVERITY[r.kind]),
          'low',
        );
        const sample = mixed.slice(0, 5).map((r) => `${r.kind}: ${r.url}`);
        findings.push({
          id: makeFindingId(this.id, pageUrl, `mixed:${mixed.map((r) => r.url).sort().join(',')}`),
          checkId: this.id,
          title: 'Mixed content: HTTPS page loads active resources over http://',
          severity: worst,
          target: probe.url,
          description:
            `An HTTPS page references ${mixed.length} active sub-resource(s) over cleartext http://. ` +
            'A network attacker can tamper with these responses to inject script or content into the secure origin.',
          evidence: `Page: ${pageUrl}\nInsecure sub-resources:\n${sample.join('\n')}`,
          reproduction: [
            `curl -s '${pageUrl}'`,
            'Grep the body for src="http://" / href="http://" on script/link/iframe/object tags',
            'Load the page in a browser and observe the mixed-content console warnings',
          ],
          remediation:
            'Serve every sub-resource over https:// (or protocol-relative // to inherit the page scheme); add a Content-Security-Policy with `upgrade-insecure-requests` / `block-all-mixed-content`.',
          cwe: 'CWE-319',
          references: [
            'https://cwe.mitre.org/data/definitions/319.html',
            'https://developer.mozilla.org/en-US/docs/Web/Security/Mixed_content',
          ],
          needsManualReview: false,
          evidenceGrade: 'fingerprint',
          confidence: 0.75,
          submitReady: false,
          source: 'worker',
          discoveredAt: now,
        });
      }
    }

    // 2) Forms that submit over cleartext http://.
    const insecureForms = forms.filter((f) => f.insecure);
    if (insecureForms.length) {
      const hasLogin = insecureForms.some((f) => f.password);
      const sample = insecureForms.slice(0, 5).map((f) => f.action);
      findings.push({
        id: makeFindingId(this.id, pageUrl, `form:${insecureForms.map((f) => f.action).sort().join(',')}`),
        checkId: this.id,
        title: hasLogin
          ? 'Login form submits credentials over cleartext http://'
          : 'Form submits data over cleartext http://',
        severity: hasLogin ? 'high' : 'medium',
        target: probe.url,
        description:
          `A <form> posts to an http:// action, so submitted ${hasLogin ? 'credentials' : 'data'} traverse the network in cleartext ` +
          'and can be intercepted or modified by any on-path attacker.',
        evidence: `Page: ${pageUrl}\nInsecure form action(s):\n${sample.join('\n')}\nPassword field present: ${hasLogin}`,
        reproduction: [
          `curl -s '${pageUrl}'`,
          'Locate the <form> tag and confirm its action attribute begins with http://',
        ],
        remediation:
          'Point the form action at an https:// URL and redirect any cleartext endpoint to HTTPS; never accept credential submissions over http.',
        cwe: 'CWE-319',
        references: ['https://cwe.mitre.org/data/definitions/319.html'],
        needsManualReview: !hasLogin,
        evidenceGrade: 'fingerprint',
        confidence: hasLogin ? 0.8 : 0.65,
        submitReady: hasLogin,
        source: 'worker',
        discoveredAt: now,
      });
    }

    // 3) Cross-origin scripts/stylesheets without Subresource Integrity.
    const noSri = resources.filter((r) => !r.insecure && r.crossOrigin && !r.integrity && r.kind !== 'iframe' && r.kind !== 'object');
    if (noSri.length) {
      const sample = noSri.slice(0, 5).map((r) => `${r.kind}: ${r.url}`);
      const thirdParties = Array.from(new Set(noSri.map((r) => originOf(r.url)?.host).filter(Boolean)));
      findings.push({
        id: makeFindingId(this.id, pageUrl, `sri:${noSri.map((r) => r.url).sort().join(',')}`),
        checkId: this.id,
        title: 'Cross-origin script/style loaded without Subresource Integrity',
        severity: 'low',
        target: probe.url,
        description:
          `The page loads ${noSri.length} cross-origin resource(s) from ${thirdParties.length} third-party host(s) without an integrity attribute. ` +
          'If that origin or its CDN is compromised, tampered code executes with the full privileges of this page.',
        evidence: `Page: ${pageUrl}\nThird-party hosts: ${thirdParties.join(', ')}\nResources without integrity:\n${sample.join('\n')}`,
        reproduction: [
          `curl -s '${pageUrl}'`,
          'Confirm the cross-origin <script>/<link> tags have no integrity= attribute',
        ],
        remediation:
          'Add `integrity="sha384-…"` and `crossorigin="anonymous"` to cross-origin script/style tags, or self-host the assets. Consider a CSP `require-sri-for script style`.',
        cwe: 'CWE-353',
        references: [
          'https://cwe.mitre.org/data/definitions/353.html',
          'https://developer.mozilla.org/en-US/docs/Web/Security/Subresource_Integrity',
        ],
        needsManualReview: true,
        evidenceGrade: 'fingerprint',
        confidence: 0.55,
        submitReady: false,
        source: 'worker',
        discoveredAt: now,
      });
    }

    return findings;
  },
};

interface FormAction {
  action: string;
  insecure: boolean;
  password: boolean;
}

function extractResources(
  body: string,
  pageUrl: string,
  pageOrigin: URL | null,
): Resource[] {
  const out: Resource[] = [];
  const seen = new Set<string>();

  const push = (kind: ResourceKind, rawUrl: string | undefined, integrity: boolean) => {
    if (!rawUrl) return;
    const raw = rawUrl.trim();
    if (!raw || raw.startsWith('data:') || raw.startsWith('#') || raw.startsWith('javascript:')) return;
    const resolved = resolveUrl(raw, pageUrl);
    if (!resolved) return;
    const key = `${kind}|${resolved.toString()}`;
    if (seen.has(key)) return;
    seen.add(key);
    out.push({
      kind,
      url: resolved.toString(),
      integrity,
      crossOrigin: pageOrigin ? resolved.origin !== pageOrigin.origin : false,
      insecure: resolved.protocol === 'http:',
    });
  };

  for (const tag of matchTags(body, 'script')) {
    const src = attr(tag, 'src');
    if (src) push('script', src, hasAttr(tag, 'integrity'));
  }
  for (const tag of matchTags(body, 'iframe')) {
    push('iframe', attr(tag, 'src'), false);
  }
  for (const tag of matchTags(body, 'object')) {
    push('object', attr(tag, 'data'), false);
  }
  for (const tag of matchTags(body, 'link')) {
    const rel = (attr(tag, 'rel') ?? '').toLowerCase();
    const isStyle = rel.split(/\s+/).some((r) => r === 'stylesheet' || r === 'preload' || r === 'modulepreload');
    if (!isStyle) continue;
    push('stylesheet', attr(tag, 'href'), hasAttr(tag, 'integrity'));
  }

  return out;
}

function extractFormActions(body: string, pageUrl: string): FormAction[] {
  const out: FormAction[] = [];
  const seen = new Set<string>();
  // Split on <form ...> openers so each segment holds one form's inner markup,
  // letting us tell whether a password input lives inside it.
  const formRe = /<form\b([^>]*)>/gi;
  let m: RegExpExecArray | null;
  const opens: Array<{ attrs: string; index: number }> = [];
  while ((m = formRe.exec(body)) !== null) {
    opens.push({ attrs: m[1] ?? '', index: m.index + m[0].length });
  }
  for (let i = 0; i < opens.length; i++) {
    const seg = body.slice(opens[i]!.index, opens[i + 1]?.index ?? body.length);
    const inner = seg.slice(0, seg.search(/<\/form>/i) === -1 ? seg.length : seg.search(/<\/form>/i));
    const action = attr(`<form ${opens[i]!.attrs}>`, 'action');
    if (!action) continue;
    const resolved = resolveUrl(action.trim(), pageUrl);
    if (!resolved) continue;
    if (seen.has(resolved.toString())) continue;
    seen.add(resolved.toString());
    out.push({
      action: resolved.toString(),
      insecure: resolved.protocol === 'http:',
      password: /<input\b[^>]*type\s*=\s*['"]?password['"]?/i.test(inner),
    });
  }
  return out;
}

function matchTags(body: string, tag: string): string[] {
  const re = new RegExp(`<${tag}\\b[^>]*>`, 'gi');
  return body.match(re) ?? [];
}

function attr(tag: string, name: string): string | undefined {
  const re = new RegExp(`\\b${name}\\s*=\\s*("([^"]*)"|'([^']*)'|([^\\s>]+))`, 'i');
  const m = re.exec(tag);
  if (!m) return undefined;
  return m[2] ?? m[3] ?? m[4];
}

function hasAttr(tag: string, name: string): boolean {
  return new RegExp(`\\b${name}\\s*=`, 'i').test(tag);
}

function resolveUrl(raw: string, base: string): URL | null {
  try {
    return new URL(raw, base);
  } catch {
    return null;
  }
}

function originOf(url: string): URL | null {
  try {
    return new URL(url);
  } catch {
    return null;
  }
}

function maxSeverity(a: Finding['severity'], b: Finding['severity']): Finding['severity'] {
  const order: Finding['severity'][] = ['info', 'low', 'medium', 'high', 'critical'];
  return order.indexOf(a) >= order.indexOf(b) ? a : b;
}
