// Finding quality: confidence scoring, context-aware severity, noise filter.

import type { Finding, Severity } from '../types.js';
import { SEVERITY_ORDER } from '../types.js';
import { canonicalizeTarget } from './canonicalize.js';

export type EvidenceGrade = 'canary' | 'tool-confirmed' | 'fingerprint' | 'heuristic';

export interface QualityContext {
  /** True when responses look WAF-blocked (403/406/429 with WAF headers). */
  wafLikely?: boolean;
  /** True when CDN/edge headers observed (cf-ray, x-amz-cf-id, etc.). */
  cdnLikely?: boolean;
  /** True when scan/session had auth cookies / Authorization. */
  authenticated?: boolean;
}

const NOISE_CHECK_IDS = new Set([
  'nmap-open-port', // keep dangerous ports; filter plain info ports elsewhere
  'httpx-tech-detect',
  'security-headers',
]);

/** Pure confidence 0–1 from grade + severity + review flag. */
export function scoreConfidence(
  f: Pick<Finding, 'severity' | 'needsManualReview' | 'checkId'> & { evidenceGrade?: EvidenceGrade },
): number {
  const grade = f.evidenceGrade ?? inferGrade(f);
  let base =
    grade === 'canary'
      ? 0.9
      : grade === 'tool-confirmed'
        ? 0.82
        : grade === 'fingerprint'
          ? 0.65
          : 0.45;
  if (f.needsManualReview) base -= 0.12;
  if (f.severity === 'info') base -= 0.1;
  if (f.severity === 'critical' || f.severity === 'high') base += 0.05;
  return Math.max(0.05, Math.min(0.99, Number(base.toFixed(2))));
}

function inferGrade(
  f: Pick<Finding, 'checkId' | 'needsManualReview' | 'severity'> & { evidenceGrade?: EvidenceGrade },
): EvidenceGrade {
  if (f.evidenceGrade) return f.evidenceGrade;
  if (/nuclei|sqlmap-injection|command-injection|xss-injection|ssrf/i.test(f.checkId)) {
    return f.needsManualReview ? 'fingerprint' : 'tool-confirmed';
  }
  if (/httpx|nmap|subfinder|katana|ffuf|gobuster|fingerprint|tech/i.test(f.checkId)) {
    return 'heuristic';
  }
  return f.needsManualReview ? 'fingerprint' : 'tool-confirmed';
}

/**
 * Adjust severity using scan context. Never invents critical from info.
 * WAF/CDN → slightly dampen cache/header noise; auth → elevate IDOR/auth findings.
 */
export function adjustSeverity(
  f: Finding,
  ctx: QualityContext = {},
): Severity {
  let sev = f.severity;
  const id = f.checkId.toLowerCase();

  if (ctx.authenticated && /auth|idor|access-control|differential|jwt/i.test(id)) {
    sev = bump(sev, 1);
  }

  // Generic open ports stay info; dangerous services already elevated by parser.
  if (id === 'nmap-open-port' && sev === 'info') return 'info';

  // Tech detect is always informational recon.
  if (id === 'httpx-tech-detect') return 'info';

  // Behind WAF: dampen speculative low/info cache/header findings.
  if (ctx.wafLikely && (sev === 'low' || sev === 'info') && /header|cache|cors/i.test(id)) {
    return 'info';
  }

  // CDN: don't over-rank cache deception without confirmation.
  if (ctx.cdnLikely && id.includes('cache') && f.needsManualReview && sev === 'high') {
    sev = drop(sev, 1);
  }

  return sev;
}

function bump(s: Severity, n: number): Severity {
  const order: Severity[] = ['info', 'low', 'medium', 'high', 'critical'];
  const i = Math.min(order.length - 1, SEVERITY_ORDER[s] + n);
  return order[i]!;
}

function drop(s: Severity, n: number): Severity {
  const order: Severity[] = ['info', 'low', 'medium', 'high', 'critical'];
  const i = Math.max(0, SEVERITY_ORDER[s] - n);
  return order[i]!;
}

/** True if this finding is low-signal noise that should not pollute the store. */
export function isNoiseFinding(f: Finding): boolean {
  // Drop empty / invalid
  if (!f.id || !f.checkId || !f.target) return true;

  // Plain open ports that aren't elevated
  if (f.checkId === 'nmap-open-port' && f.severity === 'info') return true;

  // httpx tech lines without actionable severity stay out of primary store
  // (callers can keep them if they set keepRecon: true)
  if (f.checkId === 'httpx-tech-detect' && f.severity === 'info') return true;

  // Duplicate-looking security-headers info spam
  if (f.checkId === 'security-headers' && f.severity === 'info') return true;

  return false;
}

export interface EnrichOptions {
  ctx?: QualityContext;
  /** Keep recon noise (tech detect, open ports) — default false. */
  keepRecon?: boolean;
}

/** Enrich findings with confidence, adjusted severity, canonical target; drop noise. */
export function enrichAndFilterFindings(findings: Finding[], opts: EnrichOptions = {}): Finding[] {
  const out: Finding[] = [];
  const seen = new Set<string>();

  for (const raw of findings) {
    if (!opts.keepRecon && isNoiseFinding(raw)) continue;

    const severity = adjustSeverity(raw, opts.ctx);
    const evidenceGrade = raw.evidenceGrade ?? inferGrade(raw);
    const confidence = scoreConfidence({ ...raw, severity, evidenceGrade });
    const target = canonicalizeTarget(raw.target) || raw.target;

    const f: Finding = {
      ...raw,
      target: raw.target, // keep original display target
      severity,
      evidenceGrade,
      confidence,
      // Stable dedupe hint used by store when rewriting ids
      canonicalTarget: target,
    };

    // Prefer submitReady false for low confidence
    if (confidence < 0.55) {
      f.needsManualReview = true;
      f.submitReady = false;
    } else if (confidence >= 0.8 && !f.needsManualReview && (severity === 'high' || severity === 'critical')) {
      f.submitReady = f.submitReady ?? true;
    }

    if (seen.has(f.id)) continue;
    seen.add(f.id);
    out.push(f);
  }

  return out;
}

/** Detect WAF/CDN signals from header bag (for QualityContext). */
export function inferQualityContext(headersList: Array<Record<string, string>>): QualityContext {
  const blob = headersList
    .map((h) =>
      Object.entries(h)
        .map(([k, v]) => `${k}:${v}`)
        .join('\n'),
    )
    .join('\n')
    .toLowerCase();

  return {
    wafLikely: /cloudflare|akamai|sucuri|imperva|aws.?waf|x-sucuri|cf-ray.*block|attention required/i.test(blob),
    cdnLikely: /cf-ray|x-amz-cf-id|x-cache|x-cdn|fastly|cloudfront/i.test(blob),
  };
}

export { NOISE_CHECK_IDS };
