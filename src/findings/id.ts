// Stable finding IDs for deduplication.
//
// Two runs that discover the same issue on the same asset with the same
// evidence must produce the same id, so the store can dedupe across scans.
// Worker and executor both use this FNV-1a scheme + canonicalizeTarget.

import { canonicalizeEvidenceKey, canonicalizeTarget } from './canonicalize.js';

/** Deterministic short hash (FNV-1a 32-bit) rendered as hex. */
export function fnv1a(input: string): string {
  let hash = 0x811c9dc5;
  for (let i = 0; i < input.length; i++) {
    hash ^= input.charCodeAt(i);
    // hash *= 16777619 (mod 2^32), done with shifts to stay in 32-bit.
    hash = (hash + ((hash << 1) + (hash << 4) + (hash << 7) + (hash << 8) + (hash << 24))) >>> 0;
  }
  return hash.toString(16).padStart(8, '0');
}

export function makeFindingId(checkId: string, target: string, evidenceKey: string): string {
  const canonTarget = canonicalizeTarget(target) || target;
  const canonEvidence = canonicalizeEvidenceKey(evidenceKey);
  return `${checkId}-${fnv1a(`${checkId}|${canonTarget}|${canonEvidence}`)}`;
}
