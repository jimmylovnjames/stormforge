// Black Swan Engine - rarity-weighted exploit scenario synthesis.
//
// Unlike per-check findings, this module builds "campaign-grade" narratives from
// co-occurring signals on the same registrable domain and scores them by a
// custom momentum model (severity x confidence x novelty x diversity).

import type { Finding, Severity } from '../types.js';
import { SEVERITY_ORDER } from '../types.js';
import { makeFindingId } from './id.js';

interface ScenarioRule {
  id: string;
  title: string;
  severity: Severity;
  cwe: string;
  required: RegExp[];
  optional?: RegExp[];
  playbook: string[];
  prerequisites: string[];
  remediation: string;
  references: string[];
}

export interface BlackSwanScenario {
  id: string;
  scenarioId: string;
  domain: string;
  title: string;
  severity: Severity;
  cwe: string;
  score: number;
  novelty: number;
  confidence: number;
  submitReady: boolean;
  entryPoint: Finding;
  pivotPoints: Finding[];
  components: Finding[];
  playbook: string[];
  prerequisites: string[];
  remediation: string;
  references: string[];
}

const RULES: ScenarioRule[] = [
  {
    id: 'ghost-cookie-lateral',
    title: 'Ghost Cookie Lateral Hijack',
    severity: 'critical',
    cwe: 'CWE-565',
    required: [/subdomain-takeover/, /insecure-cookies/, /auth-access-control|auth-differential/],
    optional: [/xss-reflection|cors-misconfig/],
    prerequisites: [
      'Program allows proof of account impact without destructive actions',
      'At least one domain-scoped or cross-site session cookie',
    ],
    playbook: [
      'Claim the dangling subdomain and host attacker-controlled content',
      'Collect broadly scoped session cookies sent to the compromised host',
      'Replay against authenticated endpoints to demonstrate cross-account data access',
    ],
    remediation:
      'Remove dangling DNS, move session cookies to host-only scope (__Host-), require object-level authorization on all account routes.',
    references: ['https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/'],
  },
  {
    id: 'schema-shadow-exfil',
    title: 'Schema Shadow Exfiltration',
    severity: 'high',
    cwe: 'CWE-639',
    required: [/api-schema-exposure|graphql-introspection/, /auth-access-control|auth-differential/],
    optional: [/cors-misconfig|xss-reflection|chain-schema-idor/],
    prerequisites: [
      'Exposed schema/introspection reachable without privileged access',
      'ID-like object operations present in schema surface',
    ],
    playbook: [
      'Mine schema/introspection to enumerate object endpoints and ID parameters',
      'Replay neighboring IDs on authenticated surfaces to confirm cross-object reads',
      'Use permissive cross-origin behavior (if present) to scale exfiltration',
    ],
    remediation:
      'Restrict schema exposure and enforce object-level authorization checks independent of authenticated session state.',
    references: ['https://cwe.mitre.org/data/definitions/639.html'],
  },
  {
    id: 'token-eclipse-pivot',
    title: 'Token Eclipse Pivot',
    severity: 'critical',
    cwe: 'CWE-522',
    required: [/jwt-exposure|secret-exposure|oauth-misconfig/, /auth-differential|auth-access-control/],
    optional: [/open-redirect|cors-misconfig|chain-jwt-cors-theft|chain-oauth-token-theft/],
    prerequisites: [
      'Leaked token/credential material visible in client-served traffic',
      'A session-gated endpoint that returns privileged account data',
    ],
    playbook: [
      'Harvest leaked token/credential from exposed response or OAuth redirect surface',
      'Validate privilege delta by comparing anonymous vs token/session-backed response',
      'Chain redirect/CORS misconfig to automate token replay and account takeover evidence',
    ],
    remediation:
      'Eliminate token leakage from client surfaces, rotate exposed credentials, enforce strict redirect URI + CORS policy, and require fine-grained authorization.',
    references: ['https://portswigger.net/web-security/jwt'],
  },
  {
    id: 'cloud-wormhole',
    title: 'Cloud Wormhole Expansion',
    severity: 'critical',
    cwe: 'CWE-918',
    required: [/ssrf-oast-confirmed|ssrf-candidate/, /open-cloud-bucket|secret-exposure/],
    optional: [/api-schema-exposure|graphql-introspection|auth-differential|chain-ssrf-cloud-pivot/],
    prerequisites: [
      'Server-side fetch primitive available',
      'Cloud/storage signal indicating meaningful post-SSRF pivot target',
    ],
    playbook: [
      'Drive SSRF primitive toward internal metadata/link-local targets',
      'Leverage cloud storage/secret artifacts to expand blast radius',
      'Prove scoped impact by accessing internal or higher-trust assets read-only',
    ],
    remediation:
      'Block internal/link-local fetch destinations, enforce destination allowlists, and isolate cloud credentials from app runtime paths.',
    references: ['https://cwe.mitre.org/data/definitions/918.html'],
  },
];

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

function confidenceOf(f: Finding): number {
  return typeof f.confidence === 'number' ? f.confidence : 0.6;
}

function rankOf(s: Severity): number {
  return SEVERITY_ORDER[s] ?? 0;
}

function pickBest(fs: Finding[], re: RegExp): Finding | null {
  const hits = fs.filter((f) => re.test(`${f.checkId} ${f.title}`.toLowerCase()));
  if (!hits.length) return null;
  return [...hits].sort((a, b) => {
    const sev = rankOf(b.severity) - rankOf(a.severity);
    if (sev !== 0) return sev;
    const conf = confidenceOf(b) - confidenceOf(a);
    if (conf !== 0) return conf > 0 ? 1 : -1;
    return (b.evidence?.length ?? 0) - (a.evidence?.length ?? 0);
  })[0]!;
}

function uniqById(fs: Finding[]): Finding[] {
  const seen = new Set<string>();
  const out: Finding[] = [];
  for (const f of fs) {
    if (seen.has(f.id)) continue;
    seen.add(f.id);
    out.push(f);
  }
  return out;
}

function scoreScenario(
  severity: Severity,
  components: Finding[],
  freqByCheckId: Map<string, number>,
): { score: number; novelty: number; confidence: number; submitReady: boolean } {
  const conf = components.reduce((a, f) => a + confidenceOf(f), 0) / Math.max(1, components.length);
  const submitReadyCount = components.filter((f) => f.submitReady === true).length;
  const evidenceGrades = new Set(components.map((f) => f.evidenceGrade ?? 'fingerprint')).size;
  const sources = new Set(components.map((f) => f.source ?? 'worker')).size;
  const diversity = Math.min(1, (evidenceGrades + sources + Math.min(components.length, 4)) / 8);
  const rarity = components.reduce((a, f) => a + 1 / Math.max(1, freqByCheckId.get(f.checkId) ?? 1), 0) / Math.max(1, components.length);
  const rarityNorm = Math.min(1, rarity * 2);
  const severityNorm = rankOf(severity) / 4;
  const depthNorm = Math.min(1, components.length / 5);
  const readyNorm = Math.min(1, submitReadyCount / 3);
  const raw =
    0.28 * severityNorm +
    0.2 * conf +
    0.22 * rarityNorm +
    0.15 * depthNorm +
    0.1 * diversity +
    0.05 * readyNorm;
  const score = Math.round(Math.min(100, Math.max(0, raw * 100)));
  const submitReady = score >= 78 && submitReadyCount >= 1;
  return {
    score,
    novelty: Number(rarityNorm.toFixed(2)),
    confidence: Number(conf.toFixed(2)),
    submitReady,
  };
}

function toScenario(
  rule: ScenarioRule,
  domain: string,
  requiredHits: Finding[],
  optionalHits: Finding[],
  freqByCheckId: Map<string, number>,
): BlackSwanScenario {
  const components = uniqById([...requiredHits, ...optionalHits]);
  const sorted = [...components].sort(
    (a, b) => rankOf(b.severity) - rankOf(a.severity) || confidenceOf(b) - confidenceOf(a),
  );
  const entryPoint = sorted[0]!;
  const pivots = sorted.slice(1);
  const score = scoreScenario(rule.severity, components, freqByCheckId);
  return {
    id: makeFindingId(`black-swan-${rule.id}`, entryPoint.target, components.map((c) => c.id).sort().join('|')),
    scenarioId: rule.id,
    domain,
    title: rule.title,
    severity: rule.severity,
    cwe: rule.cwe,
    score: score.score,
    novelty: score.novelty,
    confidence: score.confidence,
    submitReady: score.submitReady,
    entryPoint,
    pivotPoints: pivots,
    components,
    playbook: rule.playbook,
    prerequisites: rule.prerequisites,
    remediation: rule.remediation,
    references: rule.references,
  };
}

/** Build rarity-weighted Black Swan scenarios from existing findings. */
export function deriveBlackSwanScenarios(findings: Finding[]): BlackSwanScenario[] {
  const clean = findings.filter((f) => !f.checkId.startsWith('black-swan-'));
  const groups = new Map<string, Finding[]>();
  for (const f of clean) {
    if (!f?.checkId || !f.target) continue;
    const key = regDomainOf(f.target);
    (groups.get(key) ?? groups.set(key, []).get(key)!).push(f);
  }

  const freqByCheckId = new Map<string, number>();
  for (const f of clean) freqByCheckId.set(f.checkId, (freqByCheckId.get(f.checkId) ?? 0) + 1);

  const out: BlackSwanScenario[] = [];
  for (const [domain, fs] of [...groups.entries()].sort(([a], [b]) => a.localeCompare(b))) {
    for (const rule of RULES) {
      const requiredHits: Finding[] = [];
      let missing = false;
      for (const re of rule.required) {
        const hit = pickBest(fs, re);
        if (!hit) {
          missing = true;
          break;
        }
        requiredHits.push(hit);
      }
      if (missing) continue;
      const optionalHits = (rule.optional ?? [])
        .map((re) => pickBest(fs, re))
        .filter((f): f is Finding => Boolean(f));
      out.push(toScenario(rule, domain, requiredHits, optionalHits, freqByCheckId));
    }
  }

  return out.sort((a, b) => b.score - a.score || rankOf(b.severity) - rankOf(a.severity) || a.domain.localeCompare(b.domain));
}

/** Convert scenarios into synthetic findings so triage/report can rank them. */
export function scenariosToFindings(scenarios: BlackSwanScenario[]): Finding[] {
  return scenarios.map((s) => {
    const componentList = s.components
      .map((c) => `- [${c.severity}] ${c.checkId} @ ${c.target} (id ${c.id})`)
      .join('\n');
    const playbook = s.playbook.map((step, i) => `${i + 1}. ${step}`);
    return {
      id: s.id,
      checkId: `black-swan-${s.scenarioId}`,
      title: `Black Swan: ${s.title}`,
      severity: s.severity,
      target: s.entryPoint.target,
      description: `Rarity-weighted exploit campaign synthesized for ${s.domain}. This is a multi-signal scenario (score ${s.score}/100, novelty ${s.novelty}) that combines ${s.components.length} independent signal(s).`,
      evidence:
        `Scenario: ${s.scenarioId}\nDomain: ${s.domain}\nScore: ${s.score}/100\nNovelty: ${s.novelty}\nConfidence: ${s.confidence}\nEntry point: ${s.entryPoint.checkId} @ ${s.entryPoint.target}\n` +
        `Prerequisites:\n${s.prerequisites.map((p) => `  - ${p}`).join('\n')}\n` +
        `Playbook:\n${playbook.map((p) => `  ${p}`).join('\n')}\n` +
        `Components:\n${componentList}`,
      reproduction: playbook,
      remediation: s.remediation,
      cwe: s.cwe,
      references: s.references,
      needsManualReview: true,
      confidence: s.confidence,
      evidenceGrade: 'heuristic',
      submitReady: s.submitReady,
      source: 'worker',
      discoveredAt: new Date().toISOString(),
    };
  });
}

/** Markdown view for /api/black-swan/:program?format=md */
export function draftBlackSwanReport(program: string, scenarios: BlackSwanScenario[]): string {
  if (!scenarios.length) {
    return `# Black Swan scenarios - ${program}\n\nNo high-momentum Black Swan scenarios derived yet.`;
  }
  const lines: string[] = [];
  lines.push(`# Black Swan scenarios - ${program}`);
  lines.push('');
  lines.push(`Scenarios: ${scenarios.length}`);
  lines.push('Model: severity x confidence x novelty x diversity.');
  lines.push('');
  for (const s of scenarios) {
    lines.push(`## [${s.severity}] ${s.title}`);
    lines.push('');
    lines.push(`- Domain: \`${s.domain}\``);
    lines.push(`- Scenario id: \`${s.scenarioId}\``);
    lines.push(`- Momentum score: **${s.score}/100**`);
    lines.push(`- Novelty: ${s.novelty}`);
    lines.push(`- Confidence: ${s.confidence}`);
    lines.push(`- Submit-ready: ${s.submitReady ? 'yes' : 'no'}`);
    lines.push(`- Entry point: \`${s.entryPoint.checkId}\` @ \`${s.entryPoint.target}\``);
    lines.push('');
    lines.push('**Prerequisites**');
    s.prerequisites.forEach((p) => lines.push(`- ${p}`));
    lines.push('');
    lines.push('**Playbook**');
    s.playbook.forEach((step, i) => lines.push(`${i + 1}. ${step}`));
    lines.push('');
    lines.push('**Components**');
    s.components.forEach((c) => lines.push(`- [${c.severity}] ${c.checkId} @ ${c.target}`));
    lines.push('');
    lines.push('**Remediation**');
    lines.push(s.remediation);
    lines.push('');
    lines.push('---');
    lines.push('');
  }
  return lines.join('\n');
}
