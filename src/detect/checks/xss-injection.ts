// XSS / template-injection / weak-CSP detection.
//
// Consumes safe GET canary probes issued by the scanner plus passive HTML/CSP
// inspection. Confirmed unescaped reflections and SSTI evaluations are high
// severity. Never executes attacker scripts or posts state-changing payloads.

import type { Check, Finding, ProbeResult } from '../../types.js';
import { makeFindingId } from '../../findings/id.js';
import {
  XSS_CANARY,
  XSS_PAYLOAD,
  SSTI_EXPR,
  SSTI_RESULT,
  hasUnescapedXssReflection,
  hasSstiEvaluation,
  urlCarriesXssCanary,
  urlCarriesSstiCanary,
} from '../../recon/injection-probes.js';

const DANGEROUS_SINKS =
  /(?:document\.write\s*\(|\.innerHTML\s*=|eval\s*\(|new\s+Function\s*\(|setTimeout\s*\(\s*['"]|javascript:)/i;

const TEMPLATE_ENGINE_ERROR =
  /(?:Twig_Error|Jinja2?\.exceptions|TemplateSyntaxError|FreeMarker template error|VelocityError|SmartyException|Unexpected token|Failed to compile template)/i;

export const xssInjectionCheck: Check = {
  id: 'xss-injection',
  title: 'XSS / template injection / weak CSP',
  cwe: 'CWE-79',
  run(probe: ProbeResult): Finding[] {
    if (probe.error || !probe.body) return [];
    if (probe.status < 200 || probe.status >= 300) return [];

    const findings: Finding[] = [];
    const url = probe.finalUrl ?? probe.url;
    const ct = (probe.headers['content-type'] ?? '').toLowerCase();
    const isHtml = ct.includes('text/html') || /^\s*</.test(probe.body);

    // ── Confirmed reflected XSS (canary probe) ────────────────────────────
    if (urlCarriesXssCanary(url) && hasUnescapedXssReflection(probe.body)) {
      findings.push({
        id: makeFindingId(this.id, probe.url, 'reflected-xss'),
        checkId: this.id,
        title: 'Reflected XSS — unescaped query parameter in response',
        severity: 'high',
        target: probe.url,
        description:
          'A unique XSS canary sent in a query parameter was reflected into the response without HTML encoding. This confirms reflected cross-site scripting: an attacker can inject script or break out of attributes in victims’ browsers.',
        evidence: `URL: ${probe.url}\nStatus: ${probe.status}\nCanary: ${XSS_CANARY}\nPayload: ${XSS_PAYLOAD}\nUnescaped reflection: confirmed\nBody preview: ${previewAround(probe.body, XSS_CANARY)}`,
        reproduction: [
          `curl -sG '${stripInjectionParams(url)}' --data-urlencode 'q=${XSS_PAYLOAD}'`,
          `Confirm the response contains the intact canary ${XSS_CANARY} without &lt; / &quot; encoding`,
          'Manually craft a benign alert payload only within authorized scope to demonstrate impact',
        ],
        remediation:
          'Context-encode all untrusted input for HTML/attr/JS contexts; prefer templating auto-escaping; deploy a strict Content-Security-Policy without unsafe-inline.',
        cwe: 'CWE-79',
        references: [
          'https://cwe.mitre.org/data/definitions/79.html',
          'https://owasp.org/www-community/attacks/xss/',
        ],
        needsManualReview: false,
        discoveredAt: new Date().toISOString(),
      });
    }

    // ── Confirmed SSTI (expression evaluated) ─────────────────────────────
    if (hasSstiEvaluation(probe.body, url)) {
      findings.push({
        id: makeFindingId(this.id, probe.url, 'ssti'),
        checkId: this.id,
        title: 'Server-side template injection (expression evaluated)',
        severity: 'high',
        target: probe.url,
        description:
          `A template expression (${SSTI_EXPR}) sent in a query parameter was evaluated server-side (result ${SSTI_RESULT} present, raw expression absent). SSTI often escalates to remote code execution depending on the engine and sandbox.`,
        evidence: `URL: ${probe.url}\nStatus: ${probe.status}\nExpression: ${SSTI_EXPR}\nEvaluated result: ${SSTI_RESULT}\nBody preview: ${previewAround(probe.body, SSTI_RESULT)}`,
        reproduction: [
          `curl -sG '${stripInjectionParams(url)}' --data-urlencode 'q=${SSTI_EXPR}'`,
          `Confirm the response contains ${SSTI_RESULT} and does not echo ${SSTI_EXPR} literally`,
          'Do not escalate to RCE payloads outside explicit program authorization',
        ],
        remediation:
          'Never render untrusted input as a template; pass user data as template variables only; disable preferential evaluation APIs; sandbox or remove template engines from request path.',
        cwe: 'CWE-94',
        references: [
          'https://cwe.mitre.org/data/definitions/94.html',
          'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/18-Testing_for_Server_Side_Template_Injection',
        ],
        needsManualReview: false,
        discoveredAt: new Date().toISOString(),
      });
    }

    // ── Template engine errors (passive hint) ─────────────────────────────
    if (TEMPLATE_ENGINE_ERROR.test(probe.body) && (urlCarriesSstiCanary(url) || /[{\\%$]/.test(url))) {
      findings.push({
        id: makeFindingId(this.id, probe.url, 'template-error'),
        checkId: this.id,
        title: 'Template engine error disclosed in response',
        severity: 'medium',
        target: probe.url,
        description:
          'The response discloses a server-side template engine error. This often indicates user input reaches a template compiler and warrants SSTI follow-up.',
        evidence: `URL: ${probe.url}\nStatus: ${probe.status}\nBody preview: ${preview(probe.body)}`,
        reproduction: [`Fetch ${probe.url}`, 'Observe template engine error text in the body'],
        remediation: 'Disable detailed template errors in production; treat user input as data, not template code.',
        cwe: 'CWE-209',
        references: ['https://cwe.mitre.org/data/definitions/209.html'],
        needsManualReview: true,
        discoveredAt: new Date().toISOString(),
      });
    }

    // ── Weak CSP / unsafe script signals (HTML only) ──────────────────────
    if (isHtml) {
      const csp = probe.headers['content-security-policy'] ?? '';
      const weak = analyzeCsp(csp);
      if (weak) {
        findings.push({
          id: makeFindingId(this.id, probe.url, `csp:${weak.kind}`),
          checkId: this.id,
          title: weak.title,
          severity: weak.severity,
          target: probe.url,
          description: weak.detail,
          evidence: `URL: ${probe.url}\nContent-Security-Policy: ${csp || '<absent>'}\nSinks present: ${DANGEROUS_SINKS.test(probe.body)}`,
          reproduction: [
            `curl -sI '${stripInjectionParams(url)}'`,
            'Inspect Content-Security-Policy for unsafe-inline, unsafe-eval, or wildcard script-src',
          ],
          remediation:
            'Deploy a strict CSP: remove unsafe-inline/unsafe-eval, avoid *, use nonces/hashes for trusted scripts, and pair with HTML encoding.',
          cwe: 'CWE-79',
          references: [
            'https://cwe.mitre.org/data/definitions/79.html',
            'https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP',
          ],
          needsManualReview: true,
          discoveredAt: new Date().toISOString(),
        });
      }

      // Dangerous sinks without any CSP — elevates XSS impact.
      if (!csp && DANGEROUS_SINKS.test(probe.body)) {
        findings.push({
          id: makeFindingId(this.id, probe.url, 'unsafe-sinks'),
          checkId: this.id,
          title: 'Unsafe client-side sinks without Content-Security-Policy',
          severity: 'medium',
          target: probe.url,
          description:
            'The HTML response contains dangerous JavaScript sinks (innerHTML/document.write/eval/javascript:) and no CSP. Combined with any reflection, this enables high-impact XSS.',
          evidence: `URL: ${probe.url}\nCSP: <absent>\nBody preview: ${preview(probe.body)}`,
          reproduction: [`Fetch ${probe.url}`, 'Search the HTML/JS for innerHTML, document.write, or eval'],
          remediation: 'Eliminate dangerous sinks, use textContent/safe DOM APIs, and enforce a strict CSP.',
          cwe: 'CWE-79',
          references: ['https://cwe.mitre.org/data/definitions/79.html'],
          needsManualReview: true,
          discoveredAt: new Date().toISOString(),
        });
      }
    }

    return findings;
  },
};

function analyzeCsp(
  csp: string,
): { kind: string; title: string; detail: string; severity: Finding['severity'] } | null {
  if (!csp) return null;
  const lower = csp.toLowerCase();
  if (/script-src[^;]*\*/.test(lower) || /default-src[^;]*\*/.test(lower)) {
    return {
      kind: 'wildcard',
      title: 'CSP allows wildcard script/default-src (*)',
      detail:
        'Content-Security-Policy permits script or default sources from `*`, which largely defeats XSS mitigation and enables CSP bypass via attacker-controlled hosts.',
      severity: 'high',
    };
  }
  if (lower.includes('unsafe-eval') && lower.includes('unsafe-inline')) {
    return {
      kind: 'unsafe-both',
      title: 'CSP allows unsafe-inline and unsafe-eval',
      detail:
        'CSP contains both `unsafe-inline` and `unsafe-eval`, permitting inline script injection and string-to-code evaluation — classic XSS bypass conditions.',
      severity: 'high',
    };
  }
  if (lower.includes("'unsafe-inline'") || lower.includes('unsafe-inline')) {
    return {
      kind: 'unsafe-inline',
      title: 'CSP allows unsafe-inline scripts',
      detail:
        'CSP includes `unsafe-inline`, so reflected or stored script content in HTML can still execute. This significantly weakens XSS defenses.',
      severity: 'medium',
    };
  }
  if (lower.includes("'unsafe-eval'") || lower.includes('unsafe-eval')) {
    return {
      kind: 'unsafe-eval',
      title: 'CSP allows unsafe-eval',
      detail:
        'CSP includes `unsafe-eval`, allowing `eval`/`new Function` style sinks that attackers abuse for XSS and CSP bypass gadgets.',
      severity: 'medium',
    };
  }
  return null;
}

function preview(body: string): string {
  return body.slice(0, 220).replace(/\s+/g, ' ');
}

function previewAround(body: string, marker: string): string {
  const idx = body.indexOf(marker);
  if (idx < 0) return preview(body);
  const start = Math.max(0, idx - 60);
  const end = Math.min(body.length, idx + marker.length + 60);
  return body.slice(start, end).replace(/\s+/g, ' ');
}

function stripInjectionParams(url: string): string {
  try {
    const u = new URL(url);
    // Keep path; drop query for cleaner repro base.
    u.search = '';
    return u.toString();
  } catch {
    return url.split('?')[0] ?? url;
  }
}
