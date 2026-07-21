import { describe, it, expect } from 'vitest';
import {
  enrichFinding,
  findPromotionTarget,
  isSubmitReady,
  promoteWithToolConfirmation,
  submitReadyFindings,
} from '../src/findings/confidence.js';
import { buildBountyPackets } from '../src/report/templates.js';
import { shouldAutoDraft, highImpactFindings } from '../src/findings/prioritize.js';
import { oauthMisconfigCheck } from '../src/detect/checks/oauth.js';
import { listChecks } from '../src/detect/registry.js';
import type { CheckContext, Finding, Scope } from '../src/types.js';

const scope: Scope = {
  program: 'acme',
  platform: 'hackerone',
  inScope: ['*.acme.com'],
  outOfScope: [],
  authorized: true,
};

function f(over: Partial<Finding> & Pick<Finding, 'checkId' | 'severity' | 'title'>): Finding {
  return {
    id: over.id ?? 'f1',
    target: over.target ?? 'https://api.acme.com/v1?id=1',
    description: 'd',
    evidence: 'e',
    reproduction: ['r'],
    remediation: 'fix',
    references: [],
    needsManualReview: over.needsManualReview ?? false,
    discoveredAt: new Date().toISOString(),
    ...over,
  };
}

describe('confidence enrichment', () => {
  it('marks confirmed canary RCE as submitReady', () => {
    const e = enrichFinding(
      f({
        checkId: 'command-injection',
        severity: 'critical',
        title: 'RCE',
        needsManualReview: false,
      }),
    );
    expect(e.evidenceGrade).toBe('canary');
    expect(e.confidence).toBeGreaterThanOrEqual(0.85);
    expect(e.submitReady).toBe(true);
    expect(isSubmitReady(e)).toBe(true);
  });

  it('keeps manual-review candidates out of submitReady', () => {
    const e = enrichFinding(
      f({
        checkId: 'sql-injection-error',
        severity: 'critical',
        title: 'SQLi?',
        needsManualReview: true,
      }),
    );
    expect(e.submitReady).toBe(false);
  });

  it('treats recon noise as heuristic low confidence', () => {
    const e = enrichFinding(
      f({
        checkId: 'httpx-tech-detect',
        severity: 'info',
        title: 'tech',
        needsManualReview: false,
      }),
    );
    expect(e.evidenceGrade).toBe('heuristic');
    expect(e.confidence).toBeLessThan(0.5);
  });
});

describe('promotion', () => {
  it('promotes Worker SQLi candidate when sqlmap confirms', () => {
    const worker = f({
      id: 'w1',
      checkId: 'sql-injection-error',
      severity: 'critical',
      title: 'SQLi error',
      needsManualReview: true,
      target: 'https://api.acme.com/users?id=1',
    });
    const tool = f({
      id: 't1',
      checkId: 'sqlmap-injection',
      severity: 'critical',
      title: 'sqlmap confirmed',
      needsManualReview: false,
      target: 'https://api.acme.com/users?id=1',
      evidenceGrade: 'tool-confirmed',
      confidence: 0.95,
    });
    expect(findPromotionTarget([worker], tool)?.id).toBe('w1');
    const up = promoteWithToolConfirmation(worker, tool);
    expect(up.submitReady).toBe(true);
    expect(up.needsManualReview).toBe(false);
    expect(up.title).toMatch(/CONFIRMED/);
    expect(up.evidence).toContain('tool confirmation');
  });
});

describe('bounty gating', () => {
  it('excludes needsManualReview candidates from packs by default', () => {
    const packets = buildBountyPackets(
      [
        f({
          checkId: 'command-injection',
          severity: 'critical',
          title: 'RCE ready',
          needsManualReview: false,
          submitReady: true,
          confidence: 0.9,
          evidenceGrade: 'canary',
        }),
        f({
          id: 'c2',
          checkId: 'cors-misconfig',
          severity: 'high',
          title: 'CORS candidate',
          needsManualReview: true,
          submitReady: false,
        }),
      ],
      scope,
    );
    expect(packets).toHaveLength(1);
    expect(packets[0]!.title).toContain('RCE');
  });

  it('shouldAutoDraft / highImpactFindings prefer submitReady', () => {
    const findings = [
      f({
        checkId: 'cors-misconfig',
        severity: 'high',
        title: 'cors',
        needsManualReview: true,
        submitReady: false,
      }),
      f({
        id: 'r',
        checkId: 'command-injection',
        severity: 'critical',
        title: 'rce',
        needsManualReview: false,
        submitReady: true,
      }),
    ];
    expect(shouldAutoDraft(findings)).toBe(true);
    expect(highImpactFindings(findings)).toHaveLength(1);
    expect(submitReadyFindings(findings)).toHaveLength(1);
  });
});

describe('oauthMisconfigCheck', () => {
  const ctx: CheckContext = { scope };

  it('flags token-in-URL as high submitReady', () => {
    const findings = oauthMisconfigCheck.run(
      {
        url: 'https://app.acme.com/oauth/callback?access_token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.aaa.bbb',
        method: 'GET',
        status: 200,
        headers: {},
        body: 'ok',
        elapsedMs: 1,
      },
      ctx,
    );
    expect(findings).toHaveLength(1);
    expect(findings[0]!.severity).toBe('high');
    expect(findings[0]!.submitReady).toBe(true);
    expect(findings[0]!.evidence).toContain('REDACTED');
  });

  it('is registered', () => {
    expect(listChecks().some((c) => c.id === 'oauth-misconfig')).toBe(true);
  });
});
