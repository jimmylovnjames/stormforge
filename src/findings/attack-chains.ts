// Attack-chain correlation — "real hacker logic".
//
// Reasons across the WHOLE finding set (not per-finding) to connect co-occurring
// signals on the same registrable domain into escalated, narrated composite
// findings — the leaps a human hunter makes (exposed source → live secret,
// open redirect on an OAuth surface → token theft, SSRF + cloud → metadata
// pivot, …). Pure + deterministic; computed at read time, never mutates inputs.

import type { Finding, Scope, Severity } from '../types.js';
import { SEVERITY_ORDER } from '../types.js';
import { makeFindingId } from './id.js';
import type { PlannedTask } from '../planning/vuln-planner.js';
import { isBroadScopeCookieFinding } from '../detect/checks/cookies.js';

interface ChainMatch {
  ruleId: string;
  title: string;
  severity: Severity;
  cwe: string;
  steps: string[];
  remediation: string;
  references: string[];
  components: Finding[];
  /** Preferred follow-up when the swarm should act on the chain. */
  followUp?: { templates: string; rationale: string; tool?: 'nuclei' | 'katana' };
}

function hostOf(target: string): string {
  try {
    return new URL(target.includes('://') ? target : `https://${target}`).hostname.toLowerCase();
  } catch {
    return target.toLowerCase();
  }
}

function regDomainOf(target: string): string {
  const host = hostOf(target);
  const parts = host.split('.').filter(Boolean);
  return parts.length >= 2 ? parts.slice(-2).join('.') : host;
}

function originOf(target: string): string {
  try {
    return new URL(target.includes('://') ? target : `https://${target}`).origin;
  } catch {
    return target;
  }
}

const rank = (s: Severity): number => SEVERITY_ORDER[s] ?? 0;

/** All findings whose checkId (or title) matches the predicate. */
function match(fs: Finding[], re: RegExp): Finding[] {
  return fs.filter((f) => re.test(`${f.checkId} ${f.title}`.toLowerCase()));
}

function preferAppTarget(components: Finding[]): string {
  // Prefer a real HTTP target over a DNS/synthetic host.
  const http = components.find((c) => /^https?:\/\//i.test(c.target) && !/x-stormforge-dns/i.test(c.evidence));
  return (http ?? components[0]!).target;
}

// ─── Chain rules (each fires at most once per registrable domain) ────────────

type Rule = (fs: Finding[]) => ChainMatch | null;

const RULES: Rule[] = [
  // Exposed source/config/backup + a live secret → credential compromise.
  (fs) => {
    const src = match(fs, /exposed-files|sourcemap-exposure|directory-listing|debug-disclosure/);
    const secret = match(fs, /\bsecret-exposure\b/);
    if (!src.length || !secret.length) return null;
    const components = [...src.slice(0, 2), ...secret.slice(0, 2)];
    return {
      ruleId: 'source-to-secret',
      title: 'Exposed source/config leaking live credentials',
      severity: 'critical',
      cwe: 'CWE-538',
      steps: [
        `Retrieve the exposed asset(s): ${src.map((s) => s.target).slice(0, 2).join(', ')}`,
        `Extract the leaked credential(s) surfaced by ${secret[0]!.checkId} at ${secret[0]!.target}`,
        'Use the credential out-of-band to demonstrate access (within RoE), then report + rotate',
      ],
      remediation:
        'Remove source/config/backup artifacts from the web root, rotate every exposed secret immediately, and move secrets to server-side secret storage.',
      references: ['https://cwe.mitre.org/data/definitions/538.html'],
      components,
      followUp: { templates: 'exposures,tokens,misconfiguration', rationale: 'Confirm secret usage / adjacent exposures' },
    };
  },

  // Werkzeug/Django debug page → config/secret disclosure, potential RCE.
  (fs) => {
    const debug = match(fs, /\bdebug-disclosure\b/).filter((f) => rank(f.severity) >= rank('high'));
    if (!debug.length) return null;
    const werkzeug = debug.some((d) => /werkzeug/i.test(d.title));
    return {
      ruleId: 'debug-to-rce',
      title: werkzeug
        ? 'Werkzeug debugger exposed — config disclosure → potential RCE'
        : 'Debug interface exposed — full config/secret disclosure',
      severity: werkzeug ? 'critical' : 'high',
      cwe: 'CWE-489',
      steps: [
        `Load the debug page at ${debug[0]!.target}`,
        werkzeug
          ? 'Enumerate the traceback/console; if the Werkzeug PIN is weak/bypassable this is RCE'
          : 'Harvest settings, environment variables, and stack traces (often DB creds / API keys)',
        'Report the disclosure (and RCE path if applicable) without executing code on the target',
      ],
      remediation:
        'Disable debug mode in production (DEBUG=False / APP_DEBUG=false), return generic errors, and log details server-side.',
      references: ['https://cwe.mitre.org/data/definitions/489.html'],
      components: debug.slice(0, 2),
      followUp: { templates: 'exposures,misconfiguration,tokens', rationale: 'Sweep for adjacent debug/exposure leaks' },
    };
  },

  // Open redirect / OAuth redirect on an auth surface → token/code theft.
  (fs) => {
    const redir = match(fs, /open-redirect|oauth-misconfig/);
    const authSurface = match(fs, /oauth-misconfig|api-schema-exposure|graphql-introspection|auth-access-control/);
    const hasRedirect = redir.some((f) => /redirect/i.test(`${f.checkId} ${f.title}`));
    if (!hasRedirect || !authSurface.length) return null;
    const cred = match(fs, /cors-misconfig/).some((f) => rank(f.severity) >= rank('high'));
    return {
      ruleId: 'oauth-token-theft',
      title: 'Open redirect on OAuth/auth surface → access-token/code theft',
      severity: cred ? 'critical' : 'high',
      cwe: 'CWE-601',
      steps: [
        `Confirm the open redirect: ${redir[0]!.target}`,
        `Chain it into the OAuth/auth flow (${authSurface[0]!.target}) so the authorization code/token is delivered to an attacker-controlled callback`,
        cred ? 'Combine with the permissive CORS finding to read the token cross-origin' : 'Demonstrate token/code exfiltration via the redirect',
      ],
      remediation:
        'Allowlist exact redirect_uri values; never redirect to user-supplied absolute URLs; do not combine credentialed CORS with reflected origins.',
      references: ['https://datatracker.ietf.org/doc/html/rfc9700'],
      components: [...redir.slice(0, 1), ...authSurface.slice(0, 1)],
      followUp: { templates: 'redirect,exposures,misconfiguration', rationale: 'Probe OAuth redirect handling' },
    };
  },

  // Credentialed/reflected CORS + authenticated data surface → cross-origin theft.
  (fs) => {
    const cors = match(fs, /cors-misconfig/).filter((f) => rank(f.severity) >= rank('medium'));
    const authData = match(fs, /auth-access-control|api-schema-exposure|graphql-introspection/);
    if (!cors.length || !authData.length) return null;
    return {
      ruleId: 'cors-cred-theft',
      title: 'Permissive CORS enables cross-origin theft of authenticated data',
      severity: 'high',
      cwe: 'CWE-942',
      steps: [
        `Host a page that fetches ${authData[0]!.target} with credentials from an attacker origin`,
        `The permissive CORS policy (${cors[0]!.target}) reflects the origin and allows credentialed reads`,
        'Exfiltrate the authenticated/PII response cross-origin',
      ],
      remediation:
        'Reflect only allowlisted origins; never send Access-Control-Allow-Credentials with a reflected/wildcard origin.',
      references: ['https://cwe.mitre.org/data/definitions/942.html'],
      components: [...cors.slice(0, 1), ...authData.slice(0, 1)],
    };
  },

  // SSRF (candidate or confirmed) + cloud footprint → metadata / internal pivot.
  (fs) => {
    const ssrf = match(fs, /ssrf-candidate|ssrf-oast-confirmed/);
    const cloud = match(fs, /open-cloud-bucket/).concat(
      fs.filter((f) => /aws|s3|gcp|google cloud|azure|metadata/i.test(`${f.title} ${f.evidence}`)),
    );
    if (!ssrf.length || !cloud.length) return null;
    const confirmed = ssrf.some((f) => /oast-confirmed/.test(f.checkId));
    return {
      ruleId: 'ssrf-cloud-pivot',
      title: confirmed
        ? 'Confirmed SSRF + cloud footprint → metadata credential theft / internal pivot'
        : 'SSRF candidate + cloud footprint → likely metadata / internal pivot',
      severity: confirmed ? 'critical' : 'high',
      cwe: 'CWE-918',
      steps: [
        `Use the SSRF vector (${ssrf[0]!.target}) to request internal/link-local targets`,
        'Target the cloud metadata endpoint (e.g. 169.254.169.254) to retrieve instance credentials',
        'Pivot to internal services / storage using the recovered credentials (within RoE)',
      ],
      remediation:
        'Block internal/link-local ranges and the metadata IP from server-side fetchers; enforce a destination allowlist and IMDSv2.',
      references: ['https://cwe.mitre.org/data/definitions/918.html'],
      components: [...ssrf.slice(0, 1), ...cloud.slice(0, 1)],
      followUp: { templates: 'ssrf,exposures,misconfiguration', rationale: 'Drive SSRF toward cloud metadata' },
    };
  },

  // Subdomain takeover + broadly-scoped/cross-site cookies → session theft on parent.
  (fs) => {
    const takeover = match(fs, /subdomain-takeover/);
    const cookies = match(fs, /insecure-cookies/).filter((f) => isBroadScopeCookieFinding(f));
    if (!takeover.length || !cookies.length) return null;
    return {
      ruleId: 'takeover-cookie-theft',
      title: 'Subdomain takeover → cookie/session theft against the parent domain',
      severity: 'high',
      cwe: 'CWE-284',
      steps: [
        `Claim the dangling subdomain (${takeover[0]!.target})`,
        `Serve attacker content there; broadly-scoped/cross-site cookies (${cookies[0]!.target}) are sent to it`,
        'Capture session cookies / run same-site attacks against the parent application',
      ],
      remediation:
        'Remove dangling DNS records; scope cookies to the exact host (avoid parent Domain); use SameSite=Lax/Strict and __Host- prefix.',
      references: ['https://github.com/EdOverflow/can-i-take-over-xyz'],
      components: [...takeover.slice(0, 1), ...cookies.slice(0, 1)],
      followUp: { tool: 'nuclei', templates: 'takeovers,dns,misconfiguration', rationale: 'Confirm takeover + adjacent dangles' },
    };
  },

  // Exposed API schema/introspection + IDOR → precise mass object access.
  (fs) => {
    const schema = match(fs, /api-schema-exposure|graphql-introspection/);
    const idor = match(fs, /auth-access-control/);
    if (!schema.length || !idor.length) return null;
    return {
      ruleId: 'schema-idor',
      title: 'Exposed API schema maps the exact IDOR-able authenticated endpoints',
      severity: 'high',
      cwe: 'CWE-639',
      steps: [
        `Enumerate the full endpoint/param set from the exposed schema (${schema[0]!.target})`,
        `Replay the object-access endpoint (${idor[0]!.target}) across neighbouring IDs`,
        'Demonstrate cross-object reads/writes without authorization (read-only within RoE)',
      ],
      remediation:
        'Restrict schema/introspection in production and enforce object-level authorization on every request; use opaque IDs.',
      references: ['https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/'],
      components: [...schema.slice(0, 1), ...idor.slice(0, 1)],
      followUp: { tool: 'katana', templates: 'exposures,misconfiguration', rationale: 'Crawl schema-derived endpoints' },
    };
  },

  // Cache deception / host-header injection + authenticated surface → cache poisoning.
  (fs) => {
    const cache = match(fs, /cache-deception|host-header-injection/);
    const authSurface = match(fs, /auth-access-control|insecure-cookies/);
    if (!cache.length || !authSurface.length) return null;
    return {
      ruleId: 'cache-poison-auth',
      title: 'Cache poisoning / deception of authenticated responses',
      severity: 'high',
      cwe: 'CWE-444',
      steps: [
        `Reflect attacker input via ${cache[0]!.checkId} at ${cache[0]!.target}`,
        'Cause a victim’s authenticated/personalised response (or a poisoned link) to be cached',
        'Serve the cached sensitive response to other users / hijack the reset flow',
      ],
      remediation:
        'Normalize cache keys, never cache authenticated responses, and derive absolute URLs from a fixed canonical host (ignore X-Forwarded-Host).',
      references: ['https://portswigger.net/web-security/web-cache-poisoning'],
      components: [...cache.slice(0, 1), ...authSurface.slice(0, 1)],
    };
  },

  // Weak CSP + confirmed/candidate XSS reflection → executable XSS.
  (fs) => {
    const csp = match(fs, /\bweak-csp\b/);
    const xss = match(fs, /\bxss-reflection\b/);
    if (!csp.length || !xss.length) return null;
    return {
      ruleId: 'xss-csp',
      title: 'Weak CSP fails to block reflected XSS',
      severity: 'high',
      cwe: 'CWE-79',
      steps: [
        `Confirm unescaped reflection at ${xss[0]!.target}`,
        `Note the weak CSP (${csp[0]!.target}) permits inline/unsafe script execution`,
        'Deliver a context-appropriate payload that executes in the victim browser (within RoE)',
      ],
      remediation:
        'Encode all reflected input for its context and ship a strict CSP (no unsafe-inline / wildcards; prefer nonces/hashes).',
      references: ['https://owasp.org/www-community/attacks/xss/'],
      components: [...xss.slice(0, 1), ...csp.slice(0, 1)],
      followUp: { templates: 'xss,misconfiguration,cves', rationale: 'Probe XSS payloads behind weak CSP' },
    };
  },

  // JWT in browser-readable response + permissive CORS → cross-origin token theft.
  (fs) => {
    const jwt = match(fs, /\bjwt-exposure\b/).filter((f) => rank(f.severity) >= rank('medium'));
    const cors = match(fs, /cors-misconfig/).filter((f) => rank(f.severity) >= rank('medium'));
    if (!jwt.length || !cors.length) return null;
    return {
      ruleId: 'jwt-cors-theft',
      title: 'Browser-readable JWT + permissive CORS → cross-origin session theft',
      severity: 'critical',
      cwe: 'CWE-942',
      steps: [
        `Locate the JWT at ${jwt[0]!.target}`,
        `From an attacker origin, fetch it under the permissive CORS policy (${cors[0]!.target})`,
        'Replay the stolen JWT against authenticated APIs (within RoE) to demonstrate account takeover',
      ],
      remediation:
        'Do not expose JWTs to JavaScript when avoidable (HttpOnly cookies); never combine credentialed CORS with reflected origins; rotate any exposed tokens.',
      references: ['https://portswigger.net/web-security/jwt'],
      components: [...jwt.slice(0, 1), ...cors.slice(0, 1)],
      followUp: { templates: 'token,exposures,misconfiguration', rationale: 'Confirm JWT exfil / adjacent token leaks' },
    };
  },
];

/** Derive escalated composite findings by correlating co-occurring signals. */
export function deriveAttackChains(findings: Finding[]): Finding[] {
  const groups = new Map<string, Finding[]>();
  for (const f of findings) {
    if (!f?.checkId || !f.target) continue;
    if (f.checkId.startsWith('chain-')) continue; // never chain on chains
    const key = regDomainOf(f.target);
    (groups.get(key) ?? groups.set(key, []).get(key)!).push(f);
  }

  const out: Finding[] = [];
  for (const [domain, fs] of [...groups.entries()].sort(([a], [b]) => a.localeCompare(b))) {
    for (const rule of RULES) {
      const m = rule(fs);
      if (!m) continue;
      out.push(toFinding(m, domain));
    }
  }
  return out;
}

function toFinding(m: ChainMatch, domain: string): Finding {
  const target = preferAppTarget(m.components) || `https://${domain}/`;
  const confidences = m.components.map((c) => c.confidence ?? 0.6);
  const avgConf = confidences.reduce((a, b) => a + b, 0) / Math.max(1, confidences.length);
  const submitReady = rank(m.severity) >= rank('high') && m.components.some((c) => c.submitReady === true);
  const componentList = m.components
    .map((c) => `- [${c.severity}] ${c.checkId} @ ${c.target} (id ${c.id})`)
    .join('\n');

  return {
    id: makeFindingId(`chain-${m.ruleId}`, target, m.components.map((c) => c.id).sort().join('|')),
    checkId: `chain-${m.ruleId}`,
    title: `Attack chain: ${m.title}`,
    severity: m.severity,
    target,
    description: `Correlated attack chain on \`${domain}\`. ${m.title}. This composite is derived from ${m.components.length} co-occurring finding(s); the combined impact is higher than any single component.`,
    evidence: `Chain: ${m.ruleId}\nDomain: ${domain}\nAttack path:\n${m.steps.map((s, i) => `  ${i + 1}. ${s}`).join('\n')}\nComponents:\n${componentList}`,
    reproduction: m.steps,
    remediation: m.remediation,
    cwe: m.cwe,
    references: m.references,
    needsManualReview: true,
    evidenceGrade: 'fingerprint',
    confidence: Number(Math.min(0.95, Math.max(0.5, avgConf)).toFixed(2)),
    submitReady,
    source: 'worker',
    discoveredAt: new Date().toISOString(),
  };
}

/**
 * Chain-aware follow-up tasks: one high-value task per chain that has a defined
 * follow-up. Returned unsanitized; the caller (planFromFindings) scope-gates and
 * dedupes them. Bounded to keep task volume in check.
 */
export function chainFollowUpTasks(findings: Finding[], _scope?: Scope): PlannedTask[] {
  const tasks: PlannedTask[] = [];
  const groups = new Map<string, Finding[]>();
  for (const f of findings) {
    if (!f?.checkId || !f.target || f.checkId.startsWith('chain-')) continue;
    const key = regDomainOf(f.target);
    (groups.get(key) ?? groups.set(key, []).get(key)!).push(f);
  }
  for (const fs of groups.values()) {
    for (const rule of RULES) {
      if (tasks.length >= 4) break;
      const m = rule(fs);
      if (!m?.followUp) continue;
      const target = originOf(preferAppTarget(m.components));
      tasks.push({
        tool: m.followUp.tool ?? 'nuclei',
        target,
        args: {
          ...(m.followUp.tool === 'katana'
            ? { flags: '-silent -d 2 -jc' }
            : { flags: '-severity critical,high,medium -silent -c 20', templates: m.followUp.templates }),
          srcChain: m.ruleId,
        },
        timeoutSec: 300,
        rationale: `Chain follow-up (${m.ruleId}): ${m.followUp.rationale}`,
      });
    }
  }
  return tasks;
}
