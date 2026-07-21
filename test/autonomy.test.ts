import { describe, it, expect } from 'vitest';
import { planFollowUpTasks } from '../src/planning/vuln-planner.js';
import { planPathsFromFindings } from '../src/planning/llm-planner.js';
import type { Finding, Scope } from '../src/types.js';

const scope: Scope = {
  program: 'acme',
  platform: 'hackerone',
  inScope: ['*.acme.com', 'acme.com'],
  outOfScope: [],
  authorized: true,
};

function finding(over: Partial<Finding> & Pick<Finding, 'checkId' | 'severity' | 'target' | 'title'>): Finding {
  return {
    id: over.id ?? 'f1',
    description: 'd',
    evidence: over.evidence ?? '',
    reproduction: ['r'],
    remediation: 'fix',
    references: [],
    needsManualReview: false,
    discoveredAt: new Date().toISOString(),
    ...over,
  };
}

describe('planFollowUpTasks (autonomy loop)', () => {
  it('schedules sqlmap for parameterized injection targets', () => {
    const plan = planFollowUpTasks(
      [
        {
          checkId: 'xss-injection',
          severity: 'high',
          target: 'https://app.acme.com/search?q=test',
          title: 'Reflected XSS',
        },
      ],
      scope,
      { maxTasks: 10 },
    );
    expect(plan.tasks.some((t) => t.tool === 'sqlmap')).toBe(true);
    expect(plan.tasks.some((t) => t.tool === 'nuclei')).toBe(true);
    expect(plan.rationale).toMatch(/Autonomous follow-up/i);
  });

  it('schedules katana for GraphQL/schema findings', () => {
    const plan = planFollowUpTasks(
      [
        {
          checkId: 'graphql-introspection',
          severity: 'high',
          target: 'https://api.acme.com/graphql',
          title: 'Introspection open',
        },
      ],
      scope,
    );
    expect(plan.tasks.some((t) => t.tool === 'katana')).toBe(true);
  });

  it('schedules gobuster after secret exposure', () => {
    const plan = planFollowUpTasks(
      [
        {
          checkId: 'secret-exposure',
          severity: 'critical',
          target: 'https://app.acme.com/.env',
          title: 'AWS key in .env',
        },
      ],
      scope,
    );
    expect(plan.tasks.some((t) => t.tool === 'gobuster')).toBe(true);
    expect(plan.tasks.some((t) => t.tool === 'nuclei')).toBe(true);
  });

  it('schedules httpx for hosts in evidence and respects scope', () => {
    const plan = planFollowUpTasks(
      [
        {
          checkId: 'recon-subfinder',
          severity: 'info',
          target: 'https://www.acme.com',
          title: 'subfinder host',
          evidence: 'staging.acme.com\nevil.out-of-scope.net',
        },
      ],
      scope,
      { maxTasks: 10 },
    );
    expect(plan.tasks.some((t) => t.tool === 'httpx' && t.target.includes('staging.acme.com'))).toBe(true);
    expect(plan.tasks.every((t) => !t.target.includes('evil.out-of-scope.net'))).toBe(true);
  });

  it('caps task count', () => {
    const many = Array.from({ length: 20 }, (_, i) => ({
      checkId: 'command-injection',
      severity: 'critical' as const,
      target: `https://app.acme.com/ping?cmd=${i}`,
      title: `RCE ${i}`,
    }));
    const plan = planFollowUpTasks(many, scope, { maxTasks: 3 });
    expect(plan.tasks.length).toBeLessThanOrEqual(3);
  });
});

describe('planPathsFromFindings (scanner second pass)', () => {
  it('maps schema findings to GraphQL/OpenAPI paths', () => {
    const plan = planPathsFromFindings([
      finding({
        checkId: 'api-schema-exposure',
        severity: 'high',
        target: 'https://api.acme.com/swagger.json',
        title: 'OpenAPI exposed',
      }),
    ]);
    expect(plan.source).toBe('evolved');
    expect(plan.suggestedPaths).toContain('/graphql');
    expect(plan.suggestedPaths).toContain('/openapi.json');
  });

  it('maps auth and secret findings to IDOR and backup paths', () => {
    const plan = planPathsFromFindings([
      finding({
        checkId: 'auth-access-control',
        severity: 'high',
        target: 'https://api.acme.com/api/v1/users/1',
        title: 'IDOR',
      }),
      finding({
        checkId: 'secret-exposure',
        severity: 'critical',
        target: 'https://app.acme.com/.env',
        title: 'secret',
      }),
    ]);
    expect(plan.suggestedPaths).toContain('/api/v1/users/2');
    expect(plan.suggestedPaths).toContain('/.aws/credentials');
  });

  it('maps path-traversal and host-header to related surfaces', () => {
    const plan = planPathsFromFindings([
      finding({
        checkId: 'path-traversal',
        severity: 'critical',
        target: 'https://app.acme.com/file?file=../etc/passwd',
        title: 'LFI',
      }),
      finding({
        checkId: 'host-header-injection',
        severity: 'high',
        target: 'https://app.acme.com/',
        title: 'Host reflect',
      }),
    ]);
    expect(plan.suggestedPaths).toContain('/download');
    expect(plan.suggestedPaths).toContain('/reset-password');
  });
});
