// Framework debug pages / verbose stack-trace disclosure.
//
// Passive: matches high-precision framework fingerprints in the response body.
// Debug pages leak source paths, settings, env vars and secrets; some (Werkzeug
// interactive debugger, Django DEBUG) can escalate to RCE / full-config leak,
// so those are graded higher. Never interacts with any exposed console.

import type { Check, Finding, ProbeResult } from '../../types.js';
import { makeFindingId } from '../../findings/id.js';

interface DebugSignature {
  key: string;
  label: string;
  severity: Finding['severity'];
  /** ALL of these must match (AND) to confirm — keeps false positives low. */
  all: RegExp[];
  note: string;
}

// Ordered most-severe first; the first matching signature wins.
const SIGNATURES: DebugSignature[] = [
  {
    key: 'werkzeug-console',
    label: 'Werkzeug interactive debugger (Flask) exposed',
    severity: 'high',
    all: [/Werkzeug Debugger/i, /(?:Traceback|console)/i, /__debugger__|class="traceback"|Console Locked/i],
    note: 'The Werkzeug interactive debugger is reachable. If the PIN is weak/bypassable this yields remote code execution; regardless it leaks full stack traces and source.',
  },
  {
    key: 'django-debug',
    label: 'Django DEBUG=True error page',
    severity: 'high',
    all: [/Traceback \(most recent call last\)/, /(?:Django Version:|You&#39;re seeing this error because you have|<code>DEBUG = True|djangoproject\.com)/],
    note: 'A Django DEBUG=True page discloses settings, installed apps, environment variables, and often secrets/DB credentials.',
  },
  {
    key: 'rails-exception',
    label: 'Rails verbose exception page',
    severity: 'medium',
    all: [/Action Controller: Exception caught|ActionView::Template::Error|<title>.*\((?:RuntimeError|NoMethodError|ArgumentError)\)/, /app\/(?:controllers|models|views)\//],
    note: 'A Rails development/verbose exception page discloses source paths and application internals.',
  },
  {
    key: 'symfony-profiler',
    label: 'Symfony debug / profiler exposure',
    severity: 'medium',
    all: [/(?:Symfony\\Component|class="sf-dump"|Whoops\\|Twig\\Error)/, /(?:Stack Trace|in \/[^ ]+\.php|vendor\/symfony)/],
    note: 'Symfony debug output / Whoops handler discloses source paths, config, and stack traces.',
  },
  {
    key: 'laravel-whoops',
    label: 'Laravel Whoops debug page',
    severity: 'medium',
    all: [/Whoops(?:, looks like something went wrong)?/i, /Illuminate\\|\/vendor\/laravel\//],
    note: 'A Laravel Whoops error page discloses source, env, and often APP_KEY / DB credentials.',
  },
  {
    key: 'aspnet-yellow',
    label: 'ASP.NET detailed error / stack trace',
    severity: 'medium',
    all: [/Server Error in .* Application/i, /(?:Stack Trace:|\[[A-Za-z.]*Exception:)/],
    note: 'ASP.NET custom errors are off — the detailed error page discloses stack traces and source paths.',
  },
  {
    key: 'php-fatal',
    label: 'PHP fatal error with source path disclosure',
    severity: 'medium',
    all: [/(?:Fatal error|Warning|Parse error|Notice):/, / in \/(?:var|home|srv|app|usr)\/[^ ]+\.php on line \d+/],
    note: 'A PHP fatal/warning reveals absolute source paths and application structure.',
  },
  {
    key: 'node-express-stack',
    label: 'Node/Express stack trace disclosure',
    severity: 'medium',
    all: [/(?:^|\n)\s*at [A-Za-z0-9_$.<> ]+ \(?[^\n]*:\d+:\d+\)?/m, /(?:node_modules|\/express\/lib\/|Error: )/],
    note: 'An unhandled Node/Express error returned a stack trace, disclosing source paths and dependency layout.',
  },
  {
    key: 'spring-trace',
    label: 'Spring Boot error with stack trace',
    severity: 'low',
    all: [/"(?:trace|exception)"\s*:/, /\bat [a-z0-9_.]+\([A-Za-z0-9_]+\.java:\d+\)/],
    note: 'A Spring Boot error response includes a Java stack trace (server.error.include-stacktrace), disclosing internals.',
  },
];

export const debugDisclosureCheck: Check = {
  id: 'debug-disclosure',
  title: 'Debug / verbose error disclosure',
  cwe: 'CWE-489',
  run(probe: ProbeResult): Finding[] {
    if (probe.error || !probe.body) return [];
    if (probe.status < 200 || probe.status >= 600) return [];
    const body = probe.body;

    for (const sig of SIGNATURES) {
      if (!sig.all.every((re) => re.test(body))) continue;

      const escalates = sig.severity === 'high';
      return [
        {
          id: makeFindingId(this.id, probe.url, sig.key),
          checkId: this.id,
          title: sig.label,
          severity: sig.severity,
          target: probe.url,
          description: `${sig.note} Debug output must never be reachable in production.`,
          evidence: `URL: ${probe.url}\nStatus: ${probe.status}\nSignature: ${sig.key}\nBody preview: ${body.slice(0, 300).replace(/\s+/g, ' ')}`,
          reproduction: [
            `curl -s '${probe.url}'`,
            `Confirm the response is a ${sig.label} (matches signature "${sig.key}")`,
            'Do not interact with any exposed console — report the disclosure only',
          ],
          remediation:
            'Disable debug mode in production (DEBUG=False / APP_DEBUG=false / customErrors On / server.error.include-stacktrace=never); return generic error pages and log details server-side.',
          cwe: sig.severity === 'high' ? 'CWE-489' : 'CWE-200',
          references: [
            'https://cwe.mitre.org/data/definitions/489.html',
            'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/08-Testing_for_Error_Handling/',
          ],
          needsManualReview: true,
          evidenceGrade: 'fingerprint',
          confidence: escalates ? 0.9 : 0.78,
          submitReady: escalates,
          source: 'worker',
          discoveredAt: new Date().toISOString(),
        },
      ];
    }
    return [];
  },
};
