// OS command injection / RCE signal detection.
//
// Consumes safe GET canaries (;|& echo/printf) on exec-like endpoints.
// Confirmed canary execution or uid=/Windows version output → critical.
// Shell error text after metachar probes → high. Never sends destructive payloads.

import type { Check, Finding, ProbeResult } from '../../types.js';
import { makeFindingId } from '../../findings/id.js';
import {
  CMD_CANARY,
  hasCommandExecutionCanary,
  hasOsCommandOutput,
  hasShellErrorSignal,
} from '../../recon/command-probes.js';

export const commandInjectionCheck: Check = {
  id: 'command-injection',
  title: 'OS command injection / RCE signals',
  cwe: 'CWE-78',
  run(probe: ProbeResult): Finding[] {
    if (probe.error || !probe.body) return [];
    const findings: Finding[] = [];
    const url = probe.url;

    // ── Confirmed echo/printf canary execution ────────────────────────────
    if (hasCommandExecutionCanary(probe.body, url)) {
      findings.push({
        id: makeFindingId(this.id, probe.url, 'echo-canary'),
        checkId: this.id,
        title: 'OS command injection — echo canary executed',
        severity: 'critical',
        target: probe.url,
        description:
          `A shell metacharacter payload caused the unique canary \`${CMD_CANARY}\` to appear in the response without reflecting the raw echo/printf expression. This confirms OS command injection (potential RCE).`,
        evidence: `URL: ${probe.url}\nStatus: ${probe.status}\nCanary: ${CMD_CANARY}\nExecution: confirmed (canary present, raw payload absent)\nBody preview: ${previewAround(probe.body, CMD_CANARY)}`,
        reproduction: [
          `curl -sG '${stripParams(url)}' --data-urlencode 'cmd=;echo ${CMD_CANARY}'`,
          `Confirm the body contains ${CMD_CANARY} and does not contain the literal ';echo ${CMD_CANARY}'`,
          'Do not escalate to reverse shells or destructive commands outside explicit authorization',
        ],
        remediation:
          'Never pass user input to a shell; use argv arrays / safe APIs (no /bin/sh -c); allowlist arguments; run helpers with least privilege.',
        cwe: 'CWE-78',
        references: [
          'https://cwe.mitre.org/data/definitions/78.html',
          'https://owasp.org/www-community/attacks/Command_Injection',
        ],
        needsManualReview: false,
        discoveredAt: new Date().toISOString(),
      });
    }

    // ── Classic OS command output (uid= / Windows Version) ────────────────
    if (hasOsCommandOutput(probe.body, url)) {
      findings.push({
        id: makeFindingId(this.id, probe.url, 'os-output'),
        checkId: this.id,
        title: 'OS command output reflected after shell metacharacters',
        severity: 'critical',
        target: probe.url,
        description:
          'The response contains OS command output (e.g. `uid=`/`gid=` or Windows version banners) after a request that included shell metacharacters. This is a strong command-injection / RCE signal.',
        evidence: `URL: ${probe.url}\nStatus: ${probe.status}\nBody preview: ${preview(probe.body)}`,
        reproduction: [
          `curl -sG '${stripParams(url)}' --data-urlencode 'cmd=;id'`,
          'Confirm uid=/gid= (or Windows version) appears — stop at proof; no further exploitation',
        ],
        remediation:
          'Remove shell invocation from request handlers; validate and allowlist host/IP inputs for ping-like tools without a shell.',
        cwe: 'CWE-78',
        references: ['https://cwe.mitre.org/data/definitions/78.html'],
        needsManualReview: false,
        discoveredAt: new Date().toISOString(),
      });
    }

    // ── Shell interpreter errors (high confidence sink) ───────────────────
    if (hasShellErrorSignal(probe.body, url)) {
      findings.push({
        id: makeFindingId(this.id, probe.url, 'shell-error'),
        checkId: this.id,
        title: 'Shell interpreter error after command metacharacters',
        severity: 'high',
        target: probe.url,
        description:
          'The response discloses a shell/cmd.exe error after shell metacharacters were supplied in a parameter. User input likely reaches `/bin/sh -c` or equivalent — treat as command-injection until proven otherwise.',
        evidence: `URL: ${probe.url}\nStatus: ${probe.status}\nBody preview: ${preview(probe.body)}`,
        reproduction: [
          `curl -sG '${stripParams(url)}' --data-urlencode 'cmd=;echo ${CMD_CANARY}'`,
          'Observe sh/bash/cmd.exe error text in the response',
        ],
        remediation:
          'Eliminate shell execution paths; return generic errors; never include stderr from OS commands in HTTP responses.',
        cwe: 'CWE-78',
        references: ['https://cwe.mitre.org/data/definitions/78.html'],
        needsManualReview: true,
        discoveredAt: new Date().toISOString(),
      });
    }

    return findings;
  },
};

function stripParams(url: string): string {
  try {
    const u = new URL(url);
    u.search = '';
    return u.toString();
  } catch {
    return url.split('?')[0] ?? url;
  }
}

function preview(body: string): string {
  return body.slice(0, 240).replace(/\s+/g, ' ');
}

function previewAround(body: string, marker: string): string {
  const idx = body.indexOf(marker);
  if (idx < 0) return preview(body);
  const start = Math.max(0, idx - 50);
  const end = Math.min(body.length, idx + marker.length + 50);
  return body.slice(start, end).replace(/\s+/g, ' ');
}
