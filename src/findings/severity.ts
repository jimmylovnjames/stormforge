// Lightweight CVSS-style severity helpers.
//
// We don't compute a full CVSS v3.1 vector for every check (many passive
// findings don't warrant it), but we provide a mapping so report drafts can
// suggest a base score band the operator can refine.

import type { Severity } from '../types.js';
import { SEVERITY_ORDER } from '../types.js';

/** Representative CVSS base-score band per qualitative severity. */
export const CVSS_BAND: Record<Severity, string> = {
  info: '0.0',
  low: '0.1–3.9',
  medium: '4.0–6.9',
  high: '7.0–8.9',
  critical: '9.0–10.0',
};

export function maxSeverity(a: Severity, b: Severity): Severity {
  return SEVERITY_ORDER[a] >= SEVERITY_ORDER[b] ? a : b;
}

export function compareSeverityDesc(a: Severity, b: Severity): number {
  return SEVERITY_ORDER[b] - SEVERITY_ORDER[a];
}

/** Empty per-severity counter. */
export function emptySummary(): Record<Severity, number> {
  return { info: 0, low: 0, medium: 0, high: 0, critical: 0 };
}
