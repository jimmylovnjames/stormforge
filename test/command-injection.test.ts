import { describe, it, expect } from 'vitest';
import {
  CMD_CANARY,
  CMD_EXEC_PATHS,
  CMD_SAFE_PAYLOADS,
  buildCommandInjectionProbeUrls,
  hasCommandExecutionCanary,
  hasOsCommandOutput,
  hasShellErrorSignal,
  shouldProbeCommandInjection,
  urlCarriesCmdPayload,
} from '../src/recon/command-probes.js';
import { commandInjectionCheck } from '../src/detect/checks/command-injection.js';
import { collectCommandInjectionFollowUps } from '../src/engine/scanner.js';
import { listChecks } from '../src/detect/registry.js';
import { draftFinding } from '../src/report/drafter.js';
import type { Finding, ProbeResult, Scope, CheckContext } from '../src/types.js';

const scope: Scope = {
  program: 'p',
  platform: 'hackerone',
  inScope: ['*.x.com'],
  outOfScope: [],
  authorized: true,
};
const ctx: CheckContext = { scope };

function probe(over: Partial<ProbeResult>): ProbeResult {
  return {
    url: 'https://a.x.com/ping',
    method: 'GET',
    status: 200,
    headers: { 'content-type': 'text/plain' },
    body: '',
    elapsedMs: 5,
    ...over,
  };
}

describe('command probe helpers', () => {
  it('builds ;|& echo canary URLs for exec params', () => {
    const urls = buildCommandInjectionProbeUrls('https://a.x.com/ping', 2);
    expect(urls.length).toBeGreaterThan(0);
    expect(urls.some((u) => urlCarriesCmdPayload(u))).toBe(true);
    expect(CMD_SAFE_PAYLOADS.some((p) => p.includes(';echo'))).toBe(true);
    expect(CMD_EXEC_PATHS).toContain('/ping');
    expect(CMD_EXEC_PATHS).toContain('/api/exec');
  });

  it('confirms execution only when canary appears without raw payload', () => {
    const url = `https://a.x.com/cmd?cmd=${encodeURIComponent(`;echo ${CMD_CANARY}`)}`;
    expect(hasCommandExecutionCanary(`ok ${CMD_CANARY} done`, url)).toBe(true);
    expect(hasCommandExecutionCanary(`literal ;echo ${CMD_CANARY}`, url)).toBe(false);
    expect(hasCommandExecutionCanary(CMD_CANARY, 'https://a.x.com/')).toBe(false);
  });

  it('detects shell errors and uid= output', () => {
    const url = `https://a.x.com/exec?cmd=${encodeURIComponent(';id')}`;
    expect(hasShellErrorSignal('sh: syntax error near unexpected token', url)).toBe(true);
    expect(hasOsCommandOutput('uid=33(www-data) gid=33(www-data) groups=33(www-data)', url)).toBe(true);
  });

  it('shouldProbeCommandInjection matches exec paths and forms', () => {
    expect(shouldProbeCommandInjection(probe({ url: 'https://a.x.com/traceroute', status: 200 }))).toBe(true);
    expect(
      shouldProbeCommandInjection(
        probe({
          url: 'https://a.x.com/tools',
          status: 200,
          headers: { 'content-type': 'text/html' },
          body: '<form><input name="cmd"></form>',
        }),
      ),
    ).toBe(true);
  });
});

describe('commandInjectionCheck', () => {
  it('flags echo canary execution as critical', () => {
    const url = `https://a.x.com/ping?cmd=${encodeURIComponent(`;echo ${CMD_CANARY}`)}`;
    const f = commandInjectionCheck.run(
      probe({ url, body: `PING ok\n${CMD_CANARY}\n` }),
      ctx,
    );
    expect(f.some((x) => x.severity === 'critical' && x.title.includes('echo canary'))).toBe(true);
    expect(f.find((x) => x.severity === 'critical')!.needsManualReview).toBe(false);
    expect(f.find((x) => x.severity === 'critical')!.cwe).toBe('CWE-78');
  });

  it('does not flag literal reflection of the echo payload', () => {
    const url = `https://a.x.com/ping?cmd=${encodeURIComponent(`;echo ${CMD_CANARY}`)}`;
    const f = commandInjectionCheck.run(
      probe({ url, body: `input was ;echo ${CMD_CANARY}` }),
      ctx,
    );
    expect(f.some((x) => x.title.includes('echo canary'))).toBe(false);
  });

  it('flags uid= OS output as critical', () => {
    const url = `https://a.x.com/exec?command=${encodeURIComponent(';id')}`;
    const f = commandInjectionCheck.run(
      probe({
        url,
        body: 'uid=0(root) gid=0(root) groups=0(root)',
      }),
      ctx,
    );
    expect(f.some((x) => x.severity === 'critical' && x.title.includes('OS command output'))).toBe(true);
  });

  it('flags shell errors as high', () => {
    const url = `https://a.x.com/cmd?cmd=${encodeURIComponent(`;echo ${CMD_CANARY}`)}`;
    const f = commandInjectionCheck.run(
      probe({
        url,
        status: 500,
        body: 'sh: command not found: blah',
      }),
      ctx,
    );
    expect(f.some((x) => x.severity === 'high' && x.title.includes('Shell interpreter'))).toBe(true);
    expect(f.find((x) => x.severity === 'high')!.needsManualReview).toBe(true);
  });

  it('is registered', () => {
    expect(listChecks().some((c) => c.id === 'command-injection')).toBe(true);
  });
});

describe('collectCommandInjectionFollowUps + report', () => {
  it('emits canary URLs for ping-like candidates', () => {
    const urls = collectCommandInjectionFollowUps([
      probe({ url: 'https://a.x.com/ping', status: 200, body: 'pong' }),
    ]);
    expect(urls.length).toBeGreaterThan(0);
    expect(urls.some((u) => decodeURIComponent(u).includes(CMD_CANARY) || u.includes('echo'))).toBe(true);
  });

  it('drafts CWE-78 impact text', () => {
    const finding: Finding = {
      id: '1',
      checkId: 'command-injection',
      title: 'RCE',
      severity: 'critical',
      target: 'https://a.x.com/exec',
      description: 'd',
      evidence: 'e',
      reproduction: ['r'],
      remediation: 'fix',
      cwe: 'CWE-78',
      references: [],
      needsManualReview: false,
      discoveredAt: new Date().toISOString(),
    };
    expect(draftFinding(finding, scope)).toContain('command injection');
  });
});
