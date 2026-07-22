// Submit-triage: rank stored findings into a "what to file first" queue.
//
// Combines qualitative severity, detection confidence, and a computed CVSS base
// score into one triage score, collapses canonical duplicates, and flags the
// submit-ready subset. Pure + deterministic so it is unit-testable and stable
// across runs. Never mutates inputs.

import type { Finding, Severity } from '../types.js';
import { SEVERITY_ORDER } from '../types.js';
import { cvssFor } from '../report/cvss.js';
import { scoreConfidence } from './quality.js';
import { canonicalizeTarget } from './canonicalize.js';

export interface TriageEntry {
  finding: Finding;
  /** 1-based position in the prioritized queue. */
  rank: number;
  /** Composite 0–1 triage score (higher = file sooner). */
  triageScore: number;
  /** CVSS v3.1 base score (0–10) for the finding. */
  cvssScore: number;
  cvssVector: string;
  /** Whether this is ready for human-reviewed submission. */
  submitReady: boolean;
  /** How many duplicate findings were collapsed into this entry (0 = unique). */
  dupes: number;
}

export interface TriageResult {
  total: number;
  submitReady: number;
  entries: TriageEntry[];
}

function normSeverity(s: Severity): number {
  return SEVERITY_ORDER[s] / 4; // 0 (info) … 1 (critical)
}

function confidenceOf(f: Finding): number {
  return typeof f.confidence === 'number' ? f.confidence : scoreConfidence(f);
}

/** Consistent submit-ready rule (mirrors the report drafter's intent). */
export function isSubmitReady(f: Finding): boolean {
  if (f.submitReady === true) return true;
  if (f.submitReady === false) return false;
  return !f.needsManualReview && SEVERITY_ORDER[f.severity] >= SEVERITY_ORDER.high;
}

function clamp01(n: number): number {
  return Math.max(0, Math.min(1, n));
}

/** Composite triage score in [0,1]. */
export function triageScore(f: Finding): { score: number; cvssScore: number; cvssVector: string } {
  const cvss = cvssFor(f);
  const conf = confidenceOf(f);
  const raw =
    0.4 * normSeverity(f.severity) +
    0.3 * conf +
    0.3 * (cvss.score / 10) +
    (isSubmitReady(f) ? 0.08 : 0) -
    (f.needsManualReview ? 0.05 : 0);
  return { score: Number(clamp01(raw).toFixed(3)), cvssScore: cvss.score, cvssVector: cvss.vector };
}

function dedupeKey(f: Finding): string {
  const canon = f.canonicalTarget || canonicalizeTarget(f.target) || f.target;
  return `${f.checkId}|${canon}`;
}

/** Prefer the higher-severity, then higher-confidence, then richer-evidence finding. */
function better(a: Finding, b: Finding): Finding {
  const sev = SEVERITY_ORDER[b.severity] - SEVERITY_ORDER[a.severity];
  if (sev !== 0) return sev > 0 ? b : a;
  const conf = confidenceOf(b) - confidenceOf(a);
  if (conf !== 0) return conf > 0 ? b : a;
  return (b.evidence?.length ?? 0) > (a.evidence?.length ?? 0) ? b : a;
}

/**
 * Rank findings into a submit-first queue, collapsing canonical duplicates
 * (same checkId + canonical target). Deterministic ordering with stable
 * tie-breaks so repeated calls produce identical output.
 */
export function prioritizeFindings(findings: Finding[]): TriageResult {
  const groups = new Map<string, { keep: Finding; count: number }>();
  for (const f of findings) {
    if (!f || !f.checkId || !f.target) continue;
    const key = dedupeKey(f);
    const existing = groups.get(key);
    if (!existing) {
      groups.set(key, { keep: f, count: 1 });
    } else {
      existing.keep = better(existing.keep, f);
      existing.count += 1;
    }
  }

  const scored = [...groups.values()].map(({ keep, count }) => {
    const t = triageScore(keep);
    return {
      finding: keep,
      triageScore: t.score,
      cvssScore: t.cvssScore,
      cvssVector: t.cvssVector,
      submitReady: isSubmitReady(keep),
      dupes: count - 1,
    };
  });

  scored.sort((a, b) => {
    if (b.triageScore !== a.triageScore) return b.triageScore - a.triageScore;
    const sev = SEVERITY_ORDER[b.finding.severity] - SEVERITY_ORDER[a.finding.severity];
    if (sev !== 0) return sev;
    if (b.cvssScore !== a.cvssScore) return b.cvssScore - a.cvssScore;
    return a.finding.title.localeCompare(b.finding.title);
  });

  const entries: TriageEntry[] = scored.map((e, i) => ({ ...e, rank: i + 1 }));
  return {
    total: entries.length,
    submitReady: entries.filter((e) => e.submitReady).length,
    entries,
  };
}

/** Top-N submit-ready entries (for a focused disclosure batch). */
export function topSubmitReady(findings: Finding[], limit = 10): TriageEntry[] {
  return prioritizeFindings(findings)
    .entries.filter((e) => e.submitReady)
    .slice(0, limit);
}

/** Compact Markdown triage table (operator queue), highest priority first. */
export function draftTriageReport(result: TriageResult, program: string): string {
  const lines: string[] = [];
  lines.push(`# Triage queue — ${program}`);
  lines.push('');
  lines.push(`Findings: ${result.total} unique · submit-ready: ${result.submitReady}`);
  lines.push('');
  lines.push('| # | Score | Sev | CVSS | Ready | Check | Target | Title |');
  lines.push('|---|-------|-----|------|-------|-------|--------|-------|');
  for (const e of result.entries) {
    const dupe = e.dupes > 0 ? ` (+${e.dupes})` : '';
    lines.push(
      `| ${e.rank} | ${e.triageScore.toFixed(3)} | ${e.finding.severity} | ${e.cvssScore.toFixed(1)} | ${e.submitReady ? '✅' : '—'} | ${e.finding.checkId}${dupe} | ${truncate(e.finding.target, 48)} | ${truncate(sanitizeCell(e.finding.title), 60)} |`,
    );
  }
  lines.push('');
  return lines.join('\n');
}

function sanitizeCell(s: string): string {
  return s.replace(/\|/g, '\\|').replace(/\s+/g, ' ').trim();
}

function truncate(s: string, n: number): string {
  return s.length > n ? `${s.slice(0, n - 1)}…` : s;
}
