// Operator-facing autonomy status — tactics, rescans, submit-ready counts.

import type { Finding } from '../types.js';

export interface RescanMeta {
  scanId: string;
  sourceTool?: string;
  targets: string[];
  createdAt: string;
  parentScanId?: string;
}

export interface AutonomyStatus {
  program: string;
  tacticsCount: number;
  topTactics: string[];
  findingCount: number;
  submitReadyCount: number;
  highImpactCount: number;
  bountyDraftCount: number;
  recentRescans: Array<{
    scanId: string;
    sourceTool?: string;
    targetCount: number;
    createdAt: string;
  }>;
  generatedAt: string;
}

export function summarizeTactics(tactics: string[], cap = 12): string[] {
  return [...new Set(tactics.filter((t) => typeof t === 'string' && t.startsWith('/')))].slice(0, cap);
}

export function buildAutonomyStatus(input: {
  program: string;
  tactics: string[];
  findings: Finding[];
  rescans: RescanMeta[];
  bountyDraftCount: number;
}): AutonomyStatus {
  const submitReadyCount = input.findings.filter((f) => f.submitReady === true).length;
  const highImpactCount = input.findings.filter(
    (f) =>
      (f.severity === 'critical' || f.severity === 'high') &&
      (f.submitReady === true || f.needsManualReview === false),
  ).length;

  return {
    program: input.program,
    tacticsCount: input.tactics.length,
    topTactics: summarizeTactics(input.tactics),
    findingCount: input.findings.length,
    submitReadyCount,
    highImpactCount,
    bountyDraftCount: input.bountyDraftCount,
    recentRescans: input.rescans.slice(0, 10).map((r) => ({
      scanId: r.scanId,
      sourceTool: r.sourceTool,
      targetCount: r.targets.length,
      createdAt: r.createdAt,
    })),
    generatedAt: new Date().toISOString(),
  };
}
