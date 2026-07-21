// Verbose error / debug surface disclosure (stack traces, debug consoles).

import type { Check, Finding, ProbeResult } from '../../types.js';
import { makeFindingId } from '../../findings/id.js';

const STACK_TRACE =
  /(?:Traceback \(most recent call last\)|Exception in thread|at [\w.$]+\([\w.]+:\d+\)|System\.(?:NullReferenceException|ArgumentException)|org\.springframework\.|django\.|Rails\.root|PHP (?:Fatal|Warning|Notice):|Fatal error:|Stack overflow|java\.lang\.|Node\.js|ReferenceError:|TypeError: .* at )/i;

const DEBUG_MARKERS =
  /(?:phpinfo\(\)|PHP Version\s+\d|Django Debug Toolbar|Xdebug|Whoops!|Laravel.*Exception|Symfony Exception|Werkzeug Debugger|DEBUG\s*=\s*True|Application Error \(Rails\)|ASP\.NET.*Yellow Screen)/i;

const SENSITIVE_PATH_HINT =
  /(?:\/var\/www|\/home\/\w+|\/usr\/local|C:\\Users\\|site-packages|node_modules[/\\]|WEB-INF)/i;

export const debugDisclosureCheck: Check = {
  id: 'debug-error-disclosure',
  title: 'Debug / verbose error disclosure',
  cwe: 'CWE-209',
  run(probe: ProbeResult): Finding[] {
    if (probe.error || !probe.body) return [];
    if (probe.status === 0) return [];

    const findings: Finding[] = [];
    const body = probe.body.slice(0, 50_000);
    const path = safePath(probe.url);

    if (STACK_TRACE.test(body)) {
      const pathLeak = SENSITIVE_PATH_HINT.test(body);
      findings.push({
        id: makeFindingId(this.id, probe.url, 'stack'),
        checkId: this.id,
        title: pathLeak
          ? 'Verbose stack trace with filesystem path disclosure'
          : 'Verbose stack trace / exception disclosure',
        severity: pathLeak ? 'medium' : 'low',
        target: probe.url,
        description:
          'The response contains a framework stack trace or exception dump. This aids attackers in mapping the stack and locating injection points; path disclosure escalates impact.',
        evidence: `URL: ${probe.url}\nStatus: ${probe.status}\nPreview: ${body.slice(0, 280).replace(/\s+/g, ' ')}`,
        reproduction: [`curl -s '${probe.url}' | head -n 40`],
        remediation:
          'Disable debug mode in production; return generic error pages; log full traces server-side only.',
        cwe: 'CWE-209',
        references: ['https://cwe.mitre.org/data/definitions/209.html'],
        needsManualReview: false,
        discoveredAt: new Date().toISOString(),
      });
    }

    if (
      DEBUG_MARKERS.test(body) ||
      /\/(?:phpinfo\.php|_profiler|__debug__|rails\/info|actuator\/env)/i.test(path)
    ) {
      // Avoid double-reporting pure stack pages already covered.
      if (!findings.length || /phpinfo|Debug Toolbar|Werkzeug|_profiler|actuator\/env/i.test(body + path)) {
        findings.push({
          id: makeFindingId(this.id, probe.url, 'debug'),
          checkId: this.id,
          title: 'Debug console / diagnostic endpoint exposed',
          severity: /actuator\/env|phpinfo|Werkzeug/i.test(body + path) ? 'high' : 'medium',
          target: probe.url,
          description:
            'A diagnostic or debug surface (phpinfo, framework profiler, Werkzeug debugger, actuator env, etc.) is reachable. These often leak secrets, env vars, and enable RCE gadgets.',
          evidence: `URL: ${probe.url}\nStatus: ${probe.status}\nPreview: ${body.slice(0, 240).replace(/\s+/g, ' ')}`,
          reproduction: [`curl -sI '${probe.url}'`, `curl -s '${probe.url}' | head`],
          remediation:
            'Remove diagnostic endpoints from production; gate profilers behind auth and network policy; never expose actuator/env publicly.',
          cwe: 'CWE-215',
          references: [
            'https://cwe.mitre.org/data/definitions/215.html',
            'https://cwe.mitre.org/data/definitions/209.html',
          ],
          needsManualReview: false,
          discoveredAt: new Date().toISOString(),
        });
      }
    }

    return findings;
  },
};

function safePath(url: string): string {
  try {
    return new URL(url).pathname;
  } catch {
    return url;
  }
}
